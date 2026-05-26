# Bootlin signature refresh

This workflow keeps `signatures/yara/bootlin-stable/bl-*.yara` (plus matching toolchain
config, dependency list, and alias list files) in sync with the prebuilt
toolchains published at https://toolchains.bootlin.com . Upstream
stelftools shipped Bootlin coverage through release 2021.11-1; everything
newer is generated here.

## Pieces

| Path | Purpose |
|---|---|
| `tools/ci/bootlin_index.py` | Scrape the per-arch `tarballs/` directory listings into a JSON array of `(arch, libc, stability, release, tarball_url, sha256_url, signature_name)` rows |
| `tools/ci/bootlin_diff.py` | Drop rows whose `signature_name.yara` already lives in `signatures/yara/` |
| `tools/ci/build_bootlin_signature.sh` | Download + verify + extract + run `stelftools.info_create` + validate, for one row |
| `tools/ci/validate_signature.py` | Confirm the generated YARA compiles under `yara-x` and the rule count clears a permissive floor |
| `.github/workflows/refresh-bootlin.yml` | `discover -> build (matrix) -> commit` runner |

## Cron and dispatch

The workflow fires on the first day of each month at 04:17 UTC and is
also reachable from the Actions UI via `workflow_dispatch`. Inputs:

  - `since` / `until`: clamp the release range (e.g. `since=2024.01`)
  - `arch`: comma-separated arch allowlist
  - `libc`: comma-separated subset of `glibc,musl,uclibc`
  - `max_jobs`: matrix size cap (default 12). Excess work is picked up
    on the following run instead of overflowing the runner budget.

Each matrix job downloads one tarball, generates one signature, and
uploads the four-file artifact. A final `commit` job collects every
artifact, opens a new branch named `ci/bootlin-refresh-<UTC-timestamp>`,
commits the additions, and pushes. **The workflow never merges to
`main`.** Open a PR off the pushed branch after manual review.

## Why `stelftools.info_create` needs an absolute toolchain path

`get_static_lib_file_list()` excludes any archive whose stored path
differs from its `os.path.realpath()` result. With a relative `-tp`
argument the comparison flips every file (relative ≠ absolute), so
every `.a` and `.o` is silently dropped and the generated YARA file
holds zero rules. `build_bootlin_signature.sh` always resolves the
extracted tree to its absolute path before invoking
`stelftools.info_create`.

## Storage policy

Each new Bootlin release adds roughly forty signature files at
10–20 MB apiece, so a single full release lands around 500–600 MB
in the repository. `signatures/yara/` already weighs 3.5 GB.

The current policy is to commit signatures directly to keep parity
with the historical `bl-stable-*` set. Revisit this once total
`signatures/yara/` size exceeds 6 GB (close to GitHub's soft-limit
warning band at 5 GB), at which point switching to Git LFS or
GitHub Release attachments becomes the better option.

## Running it locally

```
# Discover what is currently missing for the libc/arch you care about
python tools/ci/bootlin_index.py --since 2024.01 --arch aarch64 --libc glibc --out /tmp/idx.json
python tools/ci/bootlin_diff.py /tmp/idx.json

# Generate one signature triple
bash tools/ci/build_bootlin_signature.sh \
    --release 2024.05-1 --libc glibc --arch aarch64 \
    --python .venv/bin/python
```

`build_bootlin_signature.sh` cleans up the extracted toolchain on
exit (pass `--keep` if you want to inspect it).

## Bulk catch-up off-CI

The monthly cron only chips at 12 signatures per run; closing the
backlog of several hundred missing entries through CI would burn the
whole monthly Actions budget for very little incremental value. The
batch driver runs the same pipeline on a developer workstation
instead:

```bash
# What would the next pass do?
tools/ci/batch_catch_up.sh --dry-run

# Run it. Default --parallel 2 saturates a 12-core box (each build
# uses ~6 internal workers).
tools/ci/batch_catch_up.sh --parallel 2

# Catch up only the newest two Bootlin releases.
tools/ci/batch_catch_up.sh --since 2024.05 --parallel 2
```

Per-toolchain logs land in `.cache/batch_logs/run-<UTC-timestamp>/`
along with `succeeded.log`, `skipped.log`, and `failed.log` indexes.
Re-running the script is safe: every entry whose `.yara` is already
on disk is skipped, so a Ctrl-C or OOM only loses the in-flight builds.

The resulting `signatures/` tree can grow by several gigabytes during
a full catch-up. GitHub's HTTPS push tops out at 2 GB per push, so
when pushing the bulk to origin use SSH and split the commit into
release-sized chunks (commit per Bootlin release, push each one).

## Failure modes worth knowing

  - Bootlin reshuffles its HTML and the index parser misses tarballs.
    Mitigation: `bootlin_index.py` matches strictly on the documented
    filename grammar; a future site rewrite would fail loudly rather
    than silently miss entries.
  - The runner runs out of disk on a heavy toolchain. Mitigation: the
    builder unpacks one toolchain at a time and removes the extracted
    tree as part of its exit trap.
  - `stelftools.info_create` aborts on an architecture the rule
    generator does not yet understand (most current Bootlin archs are
    covered, but exotic targets such as `xtensa-lx60` are not).
    Mitigation: matrix `fail-fast` is off so one unsupported arch does
    not poison the rest, and the failing job's logs surface the
    unsupported architecture for follow-up.
