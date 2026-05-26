#!/usr/bin/env bash
# Build a stelftools YARA signature triple from one Bootlin prebuilt toolchain.
#
# Pipeline: download tarball + .sha256 -> verify -> extract -> run
# stelftools.info_create -> validate. The Python entry point writes
# directly into signatures/<family>/<arch>/, so this wrapper only
# handles I/O and cleanup; the runner never holds more than one
# extracted toolchain at a time.
#
# Requires stelftools.info_create to receive an *absolute* toolchain path:
# its symlink-exclusion logic compares each .a's path against
# os.path.realpath(), which always differs for relative inputs and silently
# drops every archive.
set -euo pipefail

usage() {
    cat <<'EOF' >&2
usage: build_bootlin_signature.sh --release <ver> --libc <libc> --arch <arch>
                                  [--ext xz|bz2]
                                  [--stability stable|bleeding-edge]
                                  [--work-dir <dir>] [--keep]
                                  [--python <interpreter>]

  --release      Bootlin release token, e.g. 2024.05-1
  --libc         glibc | musl | uclibc
  --arch         Bootlin arch token, e.g. aarch64, mips32el
  --ext          Tarball extension (default: xz; releases <= 2023.11 use bz2)
  --stability    Default: stable
  --work-dir     Scratch directory (default: <repo>/_bootlin_work)
  --keep         Do not delete the extracted toolchain after success
  --python       Python interpreter (default: python3)
EOF
    exit 2
}

release=""
libc=""
arch=""
ext="xz"
stability="stable"
work_dir=""
keep=0
python_bin="${PYTHON:-python3}"

while [ $# -gt 0 ]; do
    case "$1" in
        --release) release="$2"; shift 2;;
        --libc) libc="$2"; shift 2;;
        --arch) arch="$2"; shift 2;;
        --ext) ext="$2"; shift 2;;
        --stability) stability="$2"; shift 2;;
        --work-dir) work_dir="$2"; shift 2;;
        --keep) keep=1; shift;;
        --python) python_bin="$2"; shift 2;;
        -h|--help) usage;;
        *) printf 'unknown argument: %s\n' "$1" >&2; usage;;
    esac
done

[ -n "$release" ] || { printf 'missing --release\n' >&2; usage; }
[ -n "$libc"    ] || { printf 'missing --libc\n'    >&2; usage; }
[ -n "$arch"    ] || { printf 'missing --arch\n'    >&2; usage; }

case "$libc" in glibc|musl|uclibc) ;; *) printf 'invalid --libc %s\n' "$libc" >&2; exit 2;; esac
case "$ext"  in xz|bz2) ;;            *) printf 'invalid --ext %s\n'  "$ext"  >&2; exit 2;; esac

repo_root="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
work_dir="${work_dir:-$repo_root/_bootlin_work}"
mkdir -p "$work_dir"

stem="${arch}--${libc}--${stability}-${release}"
tar_name="${stem}.tar.${ext}"
sha_name="${stem}.sha256"
base_url="https://toolchains.bootlin.com/downloads/releases/toolchains/${arch}/tarballs"
sig_name="bl-${stability}-${release}_${libc}_${arch}"

extract_dir="$work_dir/$stem"

cleanup() {
    if [ "$keep" -eq 0 ] && [ -d "$extract_dir" ]; then
        rm -rf "$extract_dir"
    fi
    rm -f "$work_dir/$tar_name" "$work_dir/$sha_name"
}
trap cleanup EXIT

cd "$work_dir"

printf '[bootlin] fetching %s\n' "$tar_name" >&2
curl --fail --location --silent --show-error -o "$sha_name" "$base_url/$sha_name"
curl --fail --location --silent --show-error -o "$tar_name" "$base_url/$tar_name"

printf '[bootlin] verifying sha256\n' >&2
sha256sum --check --status "$sha_name"

printf '[bootlin] extracting\n' >&2
rm -rf "$extract_dir"
case "$ext" in
    xz)  tar -xJf "$tar_name";;
    bz2) tar -xjf "$tar_name";;
esac

# stelftools.info_create needs the toolchain path resolved (see header).
tc_abs="$(cd "$extract_dir" && pwd -P)"

printf '[bootlin] generating signature %s\n' "$sig_name" >&2
cd "$repo_root"
"$python_bin" -m stelftools.info_create \
    -name "$sig_name" \
    -tp "$tc_abs" \
    -cp "" \
    -arch "$arch"

printf '[bootlin] validating signature %s\n' "$sig_name" >&2
"$python_bin" tools/ci/validate_signature.py \
    --name "$sig_name" \
    --repo-root "$repo_root"

printf '[bootlin] %s done\n' "$sig_name" >&2
