#!/usr/bin/env bash
# Build the netbsd family from the historical release sets: one signature per
# release, from pmax (the one little-endian MIPS port every release from 1.4
# to 1.6.2 ships). The libraries are in comp.tgz, not base.tgz.
#
#   tools/ci/build_netbsd_signatures.sh WORKDIR [RELEASE...]
#
# Output lands in the resolved signature root; set STELFTOOLS_SIGNATURES_DIR to
# build anywhere else. Each set is checked against the release's own MD5 file.
set -euo pipefail

workdir=${1:?usage: $0 WORKDIR [RELEASE...]}
shift
releases=("$@")
[ ${#releases[@]} -gt 0 ] || releases=(1.4 1.4.1 1.4.2 1.4.3 1.5 1.5.1 1.5.2 1.5.3 1.6 1.6.1 1.6.2)
archive=https://archive.netbsd.org/pub/NetBSD-archive
port=pmax
members=(./usr/lib/crt0.o ./usr/lib/libc.a ./usr/lib/libcrypt.a ./usr/lib/libkvm.a ./usr/lib/libutil.a)

for release in "${releases[@]}"; do
  dir=$workdir/$release-$port
  mkdir -p "$dir/toolchain"
  sets=$archive/NetBSD-$release/$port/binary/sets
  curl -fsSL -o "$dir/comp.tgz" "$sets/comp.tgz"
  curl -fsSL -o "$dir/MD5" "$sets/MD5"
  want=$(awk '$2 == "(comp.tgz)" {print $4}' "$dir/MD5")
  got=$(md5sum "$dir/comp.tgz" | cut -d' ' -f1)
  if [ -z "$want" ] || [ "$want" != "$got" ]; then
    echo "$release: comp.tgz MD5 $got does not match the release's ${want:-(none)}" >&2
    exit 1
  fi
  tar -xzf "$dir/comp.tgz" -C "$dir/toolchain" "${members[@]}"
  stelftools mkrule "$dir/toolchain" --name "netbsd-$release-${port}_mipsel" --arch mipsel \
    --compiler '' --unique-site-only
done
