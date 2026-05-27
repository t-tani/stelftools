#!/usr/bin/env python3
"""Fetch Bootlin toolchains and extract minimal test object sets.

Reads ``tests/test_objects_spec.json``, downloads each tarball into
``.cache/_bootlin_work/``, verifies SHA256, and extracts the leaf
filenames named in the spec to
``.cache/_bootlin_work/test_objects/<arch>--<libc>--<release>/``.

Tarballs are deleted after extraction unless ``--keep-tarballs``. An
already-populated extract directory is treated as cached and skipped.

``--resolve-sha`` fetches ``<stem>.sha256`` from Bootlin for every entry
and writes the value back into the spec; the tarballs themselves are
not downloaded in that mode. Pinning SHAs in the spec is required for
the regression-test workflow so a Bootlin republish cannot silently
change the golden inputs.
"""

import argparse
import hashlib
import json
import shutil
import sys
import tarfile
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CACHE = REPO_ROOT / ".cache" / "_bootlin_work"
OBJECTS = CACHE / "test_objects"
SPEC_PATH = REPO_ROOT / "tests" / "test_objects_spec.json"

BOOTLIN_BASE = "https://toolchains.bootlin.com/downloads/releases/toolchains"


def _stem(entry):
    return f"{entry['arch']}--{entry['libc']}--{entry['stability']}-{entry['release']}"


def _tarball_url(entry):
    return f"{BOOTLIN_BASE}/{entry['arch']}/tarballs/{_stem(entry)}.tar.{entry['ext']}"


def _sha256_url(entry):
    return f"{BOOTLIN_BASE}/{entry['arch']}/tarballs/{_stem(entry)}.sha256"


def _http_get(url, dest):
    req = urllib.request.Request(url, headers={"User-Agent": "stelftools-tests/1"})
    with urllib.request.urlopen(req, timeout=120) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f, length=1 << 16)


def _http_text(url):
    req = urllib.request.Request(url, headers={"User-Agent": "stelftools-tests/1"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8")


def _file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _resolve_sha(entry):
    text = _http_text(_sha256_url(entry))
    return text.split()[0]


def _fetch_tarball(entry):
    stem = _stem(entry)
    tar = CACHE / f"{stem}.tar.{entry['ext']}"
    expected = entry.get("tarball_sha256")
    if tar.exists():
        observed = _file_sha256(tar)
        if expected and observed == expected:
            print(f"[{stem}] cached tarball, sha ok", flush=True)
            return tar
        print(f"[{stem}] cached tarball sha mismatch, re-fetching", flush=True)
        tar.unlink()
    print(f"[{stem}] downloading {_tarball_url(entry)}", flush=True)
    tmp = tar.with_suffix(tar.suffix + ".part")
    _http_get(_tarball_url(entry), tmp)
    observed = _file_sha256(tmp)
    if expected is None:
        print(f"[{stem}] WARN sha256 not pinned, observed {observed}", flush=True)
    elif observed != expected:
        tmp.unlink()
        raise RuntimeError(
            f"{stem}: sha256 mismatch (expected {expected}, got {observed})"
        )
    tmp.rename(tar)
    return tar


def _extract(entry, tar):
    stem = _stem(entry)
    out_dir = OBJECTS / f"{entry['arch']}--{entry['libc']}--{entry['release']}"
    if out_dir.exists() and any(out_dir.iterdir()):
        print(f"[{stem}] cached extract, skip", flush=True)
        return out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    leaves_wanted = set(entry["leaves"])
    members_by_leaf = {}
    with tarfile.open(tar, mode=f"r:{entry['ext']}") as tf:
        for m in tf.getmembers():
            if not m.isfile():
                continue
            leaf = Path(m.name).name
            if leaf in leaves_wanted and leaf not in members_by_leaf:
                members_by_leaf[leaf] = m
        for leaf, m in members_by_leaf.items():
            src = tf.extractfile(m)
            if src is None:
                continue
            with src, open(out_dir / leaf, "wb") as dst:
                shutil.copyfileobj(src, dst, length=1 << 16)
    missing = sorted(leaves_wanted - members_by_leaf.keys())
    if missing:
        print(f"[{stem}] leaves absent from tarball: {missing}", flush=True)
    return out_dir


def _run_one(entry, keep_tarballs):
    stem = _stem(entry)
    try:
        tar = _fetch_tarball(entry)
        out = _extract(entry, tar)
    except Exception as exc:
        print(f"[{stem}] FAILED: {exc}", flush=True)
        return entry, None, exc
    if not keep_tarballs:
        tar.unlink(missing_ok=True)
    return entry, out, None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", default=SPEC_PATH, type=Path)
    parser.add_argument("--workers", type=int, default=2,
                        help="concurrent tarball downloads (default: 2)")
    parser.add_argument("--keep-tarballs", action="store_true",
                        help="do not delete tarballs after extraction")
    parser.add_argument("--resolve-sha", action="store_true",
                        help="fetch .sha256 for every spec entry and write it back; skip tarballs")
    parser.add_argument("--arch", nargs="*",
                        help="restrict to these arch tokens (otherwise all entries)")
    args = parser.parse_args(argv)

    spec = json.loads(args.spec.read_text())
    entries = spec["entries"]
    if args.arch:
        wanted = set(args.arch)
        entries = [e for e in entries if e["arch"] in wanted]
        unknown = wanted - {e["arch"] for e in entries}
        if unknown:
            print(f"unknown arches: {sorted(unknown)}", file=sys.stderr)
            return 2

    CACHE.mkdir(parents=True, exist_ok=True)
    OBJECTS.mkdir(parents=True, exist_ok=True)

    if args.resolve_sha:
        for e in entries:
            try:
                sha = _resolve_sha(e)
                e["tarball_sha256"] = sha
                print(f"[{_stem(e)}] sha256 = {sha}", flush=True)
            except Exception as exc:
                print(f"[{_stem(e)}] resolve FAILED: {exc}", flush=True)
        args.spec.write_text(json.dumps(spec, indent=2) + "\n")
        print(f"wrote {args.spec}")
        return 0

    failures = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(_run_one, e, args.keep_tarballs): e for e in entries}
        for fut in as_completed(futures):
            _, _, err = fut.result()
            if err is not None:
                failures.append(futures[fut])
    if failures:
        print(f"\nfailed: {[_stem(e) for e in failures]}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
