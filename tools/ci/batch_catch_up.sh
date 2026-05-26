#!/usr/bin/env bash
# Generate every missing Bootlin signature locally.
#
# Bulk catch-up of the Bootlin signature set is too big for the GitHub
# Actions budget (~10 min per signature on a 2-core runner). This
# script runs the same pipeline that the workflow runs (bootlin_index
# -> bootlin_diff -> build_bootlin_signature.sh), but on the local
# host where each build takes ~5 minutes on a 12-core box and the
# total catch-up finishes overnight instead of consuming the monthly
# CI minute pool.
#
# Requires ``uv`` (https://docs.astral.sh/uv/). The script creates a
# project-local ``.venv`` if one is not already present and runs
# ``uv pip install -e .`` to bring the stelftools package into it
# before any build kicks off. ``.venv/`` is gitignored.
#
# Idempotent: a signature whose .yara already lives in the on-disk
# tree is skipped, so re-runs (after Ctrl-C, OOM, or simple resume)
# only pay for the ones that have not landed yet.
#
# Output for each build streams to ``.cache/batch_logs/<sig_name>.log``
# while the parent prints one status line per toolchain. The summary
# at the end lists succeeded / skipped / failed counts and the paths
# of any failure logs.

set -euo pipefail

usage() {
    cat <<'EOF' >&2
usage: batch_catch_up.sh [options]

Options:
  --since YYYY.MM[-N]    Earliest release to consider (inclusive). Default: every release.
  --until YYYY.MM[-N]    Latest release to consider (inclusive). Default: newest.
  --libc LIST            Comma-separated libc allowlist. Default: glibc,musl,uclibc.
  --arch LIST            Comma-separated arch allowlist. Default: all (minus the
                         unsupported set baked into bootlin_index.py).
  --parallel N           Run up to N builds concurrently. Default: 2.
                         Each build internally uses cpu//2 workers (capped at 8),
                         so --parallel 2 saturates a 12-core box; bump only if
                         you have many spare cores.
  --dry-run              List what would be built and exit. No tarballs fetched.
  --skip-sync            Skip the up-front ``uv pip install -e .`` step. Useful
                         when re-running and the .venv is already current.
  -h, --help             This message.

Examples:
  # Build every missing signature with two toolchains in parallel.
  tools/ci/batch_catch_up.sh --parallel 2

  # Catch up only the newest two Bootlin releases.
  tools/ci/batch_catch_up.sh --since 2024.05 --parallel 2

  # See what would run without touching the network.
  tools/ci/batch_catch_up.sh --dry-run
EOF
    exit 2
}

since=""
until_=""
libc="glibc,musl,uclibc"
arch=""
parallel=2
dry_run=0
skip_sync=0

while [ $# -gt 0 ]; do
    case "$1" in
        --since) since="$2"; shift 2;;
        --until) until_="$2"; shift 2;;
        --libc) libc="$2"; shift 2;;
        --arch) arch="$2"; shift 2;;
        --parallel) parallel="$2"; shift 2;;
        --dry-run) dry_run=1; shift;;
        --skip-sync) skip_sync=1; shift;;
        -h|--help) usage;;
        *) printf 'unknown argument: %s\n' "$1" >&2; usage;;
    esac
done

case "$parallel" in
    ''|*[!0-9]*) printf 'invalid --parallel: %s\n' "$parallel" >&2; exit 2;;
esac
if [ "$parallel" -lt 1 ]; then
    printf 'invalid --parallel (must be >= 1): %s\n' "$parallel" >&2
    exit 2
fi

repo_root="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$repo_root"

if ! command -v uv >/dev/null 2>&1; then
    printf 'uv is required (https://docs.astral.sh/uv/); install and re-run.\n' >&2
    exit 2
fi

venv_dir="$repo_root/.venv"
if [ "$skip_sync" -eq 0 ]; then
    if [ ! -d "$venv_dir" ]; then
        printf '[batch] creating %s with uv ...\n' "$venv_dir" >&2
        uv venv "$venv_dir"
    fi
    printf '[batch] uv pip install -e . into %s ...\n' "$venv_dir" >&2
    VIRTUAL_ENV="$venv_dir" uv pip install --quiet -e .
fi

python_bin="$venv_dir/bin/python"
if [ ! -x "$python_bin" ]; then
    printf 'expected uv-managed python at %s but did not find one. ' "$python_bin" >&2
    printf 'Re-run without --skip-sync to bootstrap the environment.\n' >&2
    exit 2
fi

log_dir="$repo_root/.cache/batch_logs"
mkdir -p "$log_dir"

work_root="$repo_root/_bootlin_work"
mkdir -p "$work_root"

idx_json="$(mktemp -t bl_index.XXXXXX.json)"
missing_json="$(mktemp -t bl_missing.XXXXXX.json)"
todo_tsv="$(mktemp -t bl_todo.XXXXXX.tsv)"
trap 'rm -f "$idx_json" "$missing_json" "$todo_tsv"' EXIT

printf '[batch] fetching Bootlin index ...\n' >&2
"$python_bin" tools/ci/bootlin_index.py \
    --stability stable \
    --libc "$libc" \
    ${since:+--since "$since"} \
    ${until_:+--until "$until_"} \
    ${arch:+--arch "$arch"} \
    --out "$idx_json"

printf '[batch] computing missing entries ...\n' >&2
"$python_bin" tools/ci/bootlin_diff.py "$idx_json" \
    --yara-dir signatures/yara \
    --out "$missing_json"

# Filter again at the on-disk level: bootlin_diff already drops anything
# whose .yara is present, but a parallel sibling might land one between
# the discovery time and the start of a given build. We re-check inside
# the loop too.
"$python_bin" - "$missing_json" <<'PY' > "$todo_tsv"
import json
import os
import sys

with open(sys.argv[1]) as f:
    rows = json.load(f)

for r in rows:
    yara_path = os.path.join(
        "signatures", "yara", r["family"], f"{r['signature_name']}.yara"
    )
    if os.path.exists(yara_path):
        continue
    print("\t".join((
        r["release"], r["libc"], r["arch"],
        r["ext"], r["stability"], r["family"], r["signature_name"],
    )))
PY

total=$(wc -l < "$todo_tsv" | tr -d ' ')
printf '[batch] %d signatures to build (parallel=%d, python=%s)\n' \
       "$total" "$parallel" "$python_bin" >&2
if [ "$total" -eq 0 ]; then
    printf '[batch] nothing to do; signature tree is already up to date\n' >&2
    exit 0
fi

if [ "$dry_run" -eq 1 ]; then
    cut -f7 < "$todo_tsv" | sed 's/^/  /'
    exit 0
fi

# A FIFO acts as a counting semaphore: write one token before launching
# a child, the child removes its token in a trap. `read -n1` blocks
# until a slot is free. This keeps live workers <= --parallel without
# any heavyweight dependency on GNU parallel.
sem_fifo="$(mktemp -u -t bl_sem.XXXXXX)"
mkfifo "$sem_fifo"
exec 7<>"$sem_fifo"
rm -f "$sem_fifo"
for _ in $(seq 1 "$parallel"); do
    printf '.' >&7
done

# Failure tracking shared across children via append-only file. Each
# build writes its name + return code into either succeeded.log,
# failed.log, or skipped.log under the per-run log directory.
run_id="$(date -u +%Y%m%dT%H%M%SZ)"
run_log_dir="$log_dir/run-$run_id"
mkdir -p "$run_log_dir"
succeeded_log="$run_log_dir/succeeded.log"
failed_log="$run_log_dir/failed.log"
skipped_log="$run_log_dir/skipped.log"
: > "$succeeded_log"
: > "$failed_log"
: > "$skipped_log"
printf '[batch] per-run logs: %s\n' "$run_log_dir" >&2

# Per-toolchain build wrapper, run in background.
build_one() {
    local release="$1" libc="$2" arch="$3" ext="$4" stability="$5"
    local family="$6" sig_name="$7"
    local idx="$8" total="$9"
    local log_file="$run_log_dir/$sig_name.log"

    # Late check: a parallel sibling may have generated the yara since
    # the TSV was built. Cheap to re-test; saves a full tarball fetch.
    if [ -f "signatures/yara/$family/$sig_name.yara" ]; then
        printf '[%4d/%4d skip ] %s (already present)\n' \
               "$idx" "$total" "$sig_name" >&2
        printf '%s\n' "$sig_name" >> "$skipped_log"
        # Release the semaphore slot and exit.
        printf '.' >&7
        return 0
    fi

    printf '[%4d/%4d start] %s\n' "$idx" "$total" "$sig_name" >&2

    local rc=0
    bash tools/ci/build_bootlin_signature.sh \
        --release "$release" \
        --libc "$libc" \
        --arch "$arch" \
        --ext "$ext" \
        --stability "$stability" \
        --python "$python_bin" \
        --work-dir "$work_root/$sig_name" \
        >"$log_file" 2>&1 || rc=$?

    # Per-build scratch directory cleanup. build_bootlin_signature.sh's
    # internal trap handles the extracted toolchain; we additionally
    # remove the wrapping --work-dir so a leftover-after-crash on the
    # download itself does not linger.
    rm -rf "$work_root/$sig_name"

    if [ "$rc" -eq 0 ]; then
        printf '[%4d/%4d ok   ] %s\n' "$idx" "$total" "$sig_name" >&2
        printf '%s\n' "$sig_name" >> "$succeeded_log"
    else
        printf '[%4d/%4d FAIL ] %s (rc=%d log=%s)\n' \
               "$idx" "$total" "$sig_name" "$rc" "$log_file" >&2
        printf '%s\trc=%d\tlog=%s\n' "$sig_name" "$rc" "$log_file" >> "$failed_log"
    fi

    # Release the semaphore slot.
    printf '.' >&7
}

idx=0
while IFS=$'\t' read -r release libc_e arch_e ext stability family sig_name; do
    idx=$((idx + 1))
    # Acquire a slot. Blocks when --parallel children are in flight.
    read -n1 -u7 _slot
    build_one "$release" "$libc_e" "$arch_e" "$ext" "$stability" \
              "$family" "$sig_name" "$idx" "$total" &
done < "$todo_tsv"

wait
exec 7<&-

succeeded=$(wc -l < "$succeeded_log" | tr -d ' ')
failed=$(wc -l < "$failed_log" | tr -d ' ')
skipped=$(wc -l < "$skipped_log" | tr -d ' ')

printf '\n[batch] done: succeeded=%d  skipped=%d  failed=%d  total=%d\n' \
       "$succeeded" "$skipped" "$failed" "$total" >&2

if [ "$failed" -gt 0 ]; then
    printf '[batch] failures listed in %s\n' "$failed_log" >&2
    exit 1
fi
