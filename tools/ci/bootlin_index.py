#!/usr/bin/env python3
"""Enumerate Bootlin prebuilt toolchain tarballs.

Walks https://toolchains.bootlin.com/downloads/releases/toolchains/<arch>/tarballs/
and emits one JSON object per (arch, libc, stability, release, tarball_url,
sha256_url) tuple. Output is JSON Lines on stdout, or a JSON array when
``--out`` is given.

The index page hosts an Apache directory listing whose ``<a href="...">``
entries name the tarballs directly; no API or release manifest exists.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from collections.abc import Iterable

BOOTLIN_ROOT = "https://toolchains.bootlin.com/downloads/releases/toolchains/"

# release tokens look like 2024.05-1 or 2017.05 or 2025.08
RELEASE_RE = re.compile(r"^\d{4}\.\d{2}(?:-\d+)?$")

# tarball name convention: <arch>--<libc>--<stability>-<release>.tar.{xz,bz2}
TARBALL_RE = re.compile(
    r"^(?P<arch>[A-Za-z0-9._+-]+)"
    r"--(?P<libc>glibc|musl|uclibc)"
    r"--(?P<stability>stable|bleeding-edge)"
    r"-(?P<release>\d{4}\.\d{2}(?:-\d+)?)"
    r"\.tar\.(?P<ext>xz|bz2)$"
)

# Architectures Bootlin ships that ``stelftools.generate.fetch_opecodes``'s per-arch
# dispatch does not handle yet. A CI build against any of these would
# fail at ``exit(-1)`` after downloading and extracting the toolchain,
# so the workflow drops them at index time. Keep this set in sync with
# the dispatch table in ``stelftools/mkrule.py``; remove an entry once
# the matcher grows a corresponding branch.
DEFAULT_UNSUPPORTED_ARCHES = frozenset({
    "bfin",
    "microblazebe",
    "microblazeel",
    "nios2",
    "openrisc",
    "xtensa-lx60",
    "s390x-z13",
    # RISC-V 64-bit is gated behind a commented-out branch in
    # mkrule.py; mark unsupported until that branch is restored.
    "riscv64",
    "riscv64-lp64d",
    # MIPS R6 introduces relocation types (R_MIPS_PC21_S2,
    # R_MIPS_PC26_S2, R_MIPS_PCHI16, ...) that mkrule's 32-bit MIPS
    # dispatch does not enumerate, so the build aborts at exit(-1)
    # after downloading the toolchain. Re-include once mkrule grows
    # the R6 reloc list.
    "mips32r6el",
    "mips64r6el-n32",
    # The MIPS64 n32 ABI carries ELFCLASS32 with EF_MIPS_ABI2, so
    # mkrule routes it through the 32-bit MIPS branch — which lacks
    # the R_MIPS_GOT_DISP / R_MIPS_GPREL16 / etc. that n32 emits.
    # Confirmed failing on bl-stable-2025.08-1_glibc_mips64-n32 with
    # 'unknown relocation type (0x7|0x13)' warnings before exit.
    "mips64-n32",
    "mips64el-n32",
})


@dataclass(frozen=True)
class Entry:
    arch: str
    libc: str
    stability: str
    release: str
    ext: str
    tarball_url: str
    sha256_url: str

    @property
    def signature_name(self) -> str:
        """Stelftools yara filename stem: bl-<stability>-<release>_<libc>_<arch>."""
        return f"bl-{self.stability}-{self.release}_{self.libc}_{self.arch}"

    @property
    def family(self) -> str:
        """Family subdirectory under signatures/<kind>/ for placement.

        Today every Bootlin entry routes into ``bootlin-<stability>``
        (only ``bootlin-stable`` exists in the index by default). Computed
        from the stability token rather than the signature name so the
        index file is self-describing for the workflow matrix.
        """
        return f"bootlin-{self.stability}"


class _AnchorCollector(HTMLParser):
    """Collect href targets that look like leaf filenames or subdirectories."""

    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        for key, value in attrs:
            if key == "href" and value:
                self.hrefs.append(value)
                return


def _fetch_text(url: str, timeout: float = 30.0) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "stelftools-ci/1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _list_anchors(url: str) -> list[str]:
    parser = _AnchorCollector()
    parser.feed(_fetch_text(url))
    return parser.hrefs


def list_architectures() -> list[str]:
    """Subdirectory names under the Bootlin toolchains root.

    The Apache listing emits a "Parent Directory" anchor whose href is an
    absolute path back up the tree (e.g. ``/downloads/releases/``); we
    reject anything that is not a single relative directory token to
    avoid sending requests to non-arch URLs.
    """
    archs: list[str] = []
    for href in _list_anchors(BOOTLIN_ROOT):
        if href in ("../", "./") or href.startswith("?") or not href.endswith("/"):
            continue
        name = href.rstrip("/")
        if "/" in name or name.startswith("."):
            continue
        archs.append(name)
    return sorted(archs)


def list_tarballs(arch: str) -> list[Entry]:
    """All tarball entries for a single arch directory."""
    base = f"{BOOTLIN_ROOT}{arch}/tarballs/"
    entries: list[Entry] = []
    seen_sha: set[str] = set()
    sha_bases: set[str] = set()
    for href in _list_anchors(base):
        if href.endswith(".sha256"):
            sha_bases.add(href[: -len(".sha256")])
            seen_sha.add(href)
    for href in _list_anchors(base):
        m = TARBALL_RE.match(href)
        if not m:
            continue
        base_name = href[: -(len(m.group("ext")) + 5)]  # strip ".tar.<ext>"
        if base_name not in sha_bases:
            # No sha256 companion published — skip, we will not consume unsigned tarballs.
            continue
        entries.append(
            Entry(
                arch=m.group("arch"),
                libc=m.group("libc"),
                stability=m.group("stability"),
                release=m.group("release"),
                ext=m.group("ext"),
                tarball_url=f"{base}{href}",
                sha256_url=f"{base}{base_name}.sha256",
            )
        )
    return entries


def _release_sort_key(release: str) -> tuple[int, int, int]:
    """``2024.05-1`` -> ``(2024, 5, 1)``; missing revision counts as 0."""
    head, _, rev = release.partition("-")
    year, _, month = head.partition(".")
    return (int(year), int(month), int(rev) if rev else 0)


def filter_entries(
    entries: Iterable[Entry],
    *,
    stability: set[str],
    libcs: set[str],
    archs: set[str] | None,
    since: str | None,
    until: str | None,
    exclude_archs: set[str] | None = None,
    newest_first: bool = True,
) -> list[Entry]:
    """Filter and order index entries.

    The default ordering is **release descending** (newest first) so the
    workflow's ``max_jobs`` slice picks the most recently published
    toolchains. The earlier ascending order kept the monthly cron
    forever stuck on 2018-era releases.
    """
    result: list[Entry] = []
    since_key = _release_sort_key(since) if since else None
    until_key = _release_sort_key(until) if until else None
    exclude_archs = exclude_archs or set()
    for entry in entries:
        if entry.stability not in stability:
            continue
        if entry.libc not in libcs:
            continue
        if archs is not None and entry.arch not in archs:
            continue
        if entry.arch in exclude_archs:
            continue
        key = _release_sort_key(entry.release)
        if since_key is not None and key < since_key:
            continue
        if until_key is not None and key > until_key:
            continue
        result.append(entry)
    if newest_first:
        # Negate the release tuple so ``sort`` keeps libc / arch
        # ascending while putting the newest release first; this keeps
        # the per-release group order stable across runs.
        result.sort(key=lambda e: (
            tuple(-x for x in _release_sort_key(e.release)),
            e.libc,
            e.arch,
        ))
    else:
        result.sort(key=lambda e: (_release_sort_key(e.release), e.libc, e.arch))
    return result


def collect(archs: Iterable[str], *, workers: int = 8) -> list[Entry]:
    archs = list(archs)
    out: list[Entry] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for arch, result in zip(archs, pool.map(list_tarballs, archs)):
            try:
                out.extend(result)
            except urllib.error.HTTPError as exc:
                print(f"warning: {arch}: {exc}", file=sys.stderr)
    return out


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument(
        "--out",
        help="Write JSON array to this file instead of JSON Lines on stdout",
    )
    p.add_argument(
        "--stability",
        default="stable",
        help="Comma-separated subset of {stable,bleeding-edge} (default: stable)",
    )
    p.add_argument(
        "--libc",
        default="glibc,musl,uclibc",
        help="Comma-separated subset of {glibc,musl,uclibc} (default: all)",
    )
    p.add_argument(
        "--arch",
        help="Comma-separated arch allowlist; default is every arch the index lists",
    )
    p.add_argument(
        "--since",
        help="Earliest release in YYYY.MM[-N] form (inclusive)",
    )
    p.add_argument(
        "--until",
        help="Latest release in YYYY.MM[-N] form (inclusive)",
    )
    p.add_argument(
        "--exclude-arch",
        default=",".join(sorted(DEFAULT_UNSUPPORTED_ARCHES)),
        help="Comma-separated arches to drop from the output. Default "
             "excludes the arches that stelftools.generate.fetch_opecodes cannot yet "
             "handle. Pass an empty string to disable the filter.",
    )
    p.add_argument(
        "--oldest-first",
        action="store_true",
        help="Sort by release ascending (default is newest-first so "
             "max_jobs picks the most recent toolchains).",
    )
    p.add_argument("--workers", type=int, default=8)
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    archs = list_architectures()
    if args.arch:
        wanted = {x.strip() for x in args.arch.split(",") if x.strip()}
        unknown = wanted - set(archs)
        if unknown:
            print(f"warning: unknown arch(es): {sorted(unknown)}", file=sys.stderr)
        archs = [a for a in archs if a in wanted]
    entries = collect(archs, workers=args.workers)
    entries = filter_entries(
        entries,
        stability={x.strip() for x in args.stability.split(",") if x.strip()},
        libcs={x.strip() for x in args.libc.split(",") if x.strip()},
        archs=None,
        since=args.since,
        until=args.until,
        exclude_archs={x.strip() for x in args.exclude_arch.split(",") if x.strip()},
        newest_first=not args.oldest_first,
    )
    payload = [
        asdict(e) | {"signature_name": e.signature_name, "family": e.family}
        for e in entries
    ]
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
            f.write("\n")
    else:
        for row in payload:
            print(json.dumps(row, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
