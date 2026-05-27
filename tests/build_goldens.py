#!/usr/bin/env python3
"""Generate golden JSON dumps of stelftools.mkrule.fetch_opecodes output.

Reads ``tests/test_objects_spec.json``, runs
:func:`stelftools.mkrule.fetch_opecodes` / ``fetch_opecodes_from_arfile``
on the extracted test objects under
``.cache/_bootlin_work/test_objects/<arch>--<libc>--<release>/``, and
writes a gzip-compressed canonicalised ``{"tab": ..., "crt": ...}``
payload to ``tests/golden/<arch>--<libc>--<release>.json.gz``.

Canonicalisation sorts the ``tab[key]`` list by ``(name, objname)`` and
sorts each entry's ``exports``/``imports`` lists so the comparison in
:mod:`tests.test_fetch_opecodes_golden` is independent of any insertion
order that ``elftools`` symbol iteration or archive walk may produce.
"""

import argparse
import gzip
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from stelftools import mkrule  # noqa: E402

CACHE = REPO_ROOT / ".cache" / "_bootlin_work"
OBJECTS = CACHE / "test_objects"
SPEC_PATH = REPO_ROOT / "tests" / "test_objects_spec.json"
GOLDEN_DIR = REPO_ROOT / "tests" / "golden"


def _entry_id(e):
    return f"{e['arch']}--{e['libc']}--{e['release']}"


def _entry_dir(e):
    return OBJECTS / _entry_id(e)


def _golden_path(e):
    return GOLDEN_DIR / f"{_entry_id(e)}.json.gz"


def canonicalize(tab):
    out = {}
    for key, entries in tab.items():
        canon = []
        for e in entries:
            ce = dict(e)
            if "exports" in ce:
                ce["exports"] = sorted(ce["exports"])
            if "imports" in ce:
                ce["imports"] = sorted(ce["imports"])
            canon.append(ce)
        canon.sort(key=lambda x: (x.get("name", ""), x.get("objname", "")))
        out[key] = canon
    return out


_AR_MAGIC = b"!<arch>\n"


def _looks_like_ar(path):
    """Glibc ships libm.a / libpthread.a as ld linker scripts or empty AR
    stubs; arpy chokes on the former and yields nothing useful on the
    latter. Detect by magic and skip in both cases — the regression
    fixtures only exercise files that fetch_opecodes actually processes.
    """
    try:
        with open(path, "rb") as f:
            head = f.read(8)
    except OSError:
        return False
    return head == _AR_MAGIC


def run_fetch_on_dir(obj_dir):
    """Drive fetch_opecodes / fetch_opecodes_from_arfile over a fixture dir.

    Inputs are processed in sorted leaf order so the merge sequence is
    reproducible. ``.a`` files that are linker scripts or empty archives
    are skipped (see :func:`_looks_like_ar`); non-archive / non-object
    files are also ignored.
    """
    tab = {}
    crt = {}
    for fp in sorted(obj_dir.iterdir()):
        if fp.name.endswith(".a"):
            if not _looks_like_ar(fp):
                continue
            newtab, new_crt = mkrule.fetch_opecodes_from_arfile(str(fp))
        elif fp.name.endswith(".o"):
            with open(fp, "rb") as f:
                newtab, new_crt = mkrule.fetch_opecodes(f)
        else:
            continue
        tab = mkrule.merge_dicts(tab, newtab)
        crt = mkrule.merge_dicts(crt, new_crt)
    return tab, crt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", default=SPEC_PATH, type=Path)
    parser.add_argument("--arch", nargs="*")
    parser.add_argument("--force", action="store_true",
                        help="overwrite existing goldens")
    args = parser.parse_args(argv)

    spec = json.loads(args.spec.read_text())
    entries = spec["entries"]
    if args.arch:
        wanted = set(args.arch)
        entries = [e for e in entries if e["arch"] in wanted]

    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    for e in entries:
        gp = _golden_path(e)
        if gp.exists() and not args.force:
            print(f"[{e['arch']}] cached, skip ({gp.name})", flush=True)
            continue
        d = _entry_dir(e)
        if not d.exists() or not any(d.iterdir()):
            print(f"[{e['arch']}] no extract at {d}, skip", flush=True)
            continue
        print(f"[{e['arch']}] running fetch_opecodes ...", flush=True)
        tab, crt = run_fetch_on_dir(d)
        payload = {"tab": canonicalize(tab), "crt": canonicalize(crt)}
        text = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        with gzip.open(gp, "wb", compresslevel=9) as f:
            f.write(text.encode("utf-8"))
        print(
            f"[{e['arch']}] {len(tab):>6} tab / {len(crt):>3} crt  "
            f"-> {gp.name} ({gp.stat().st_size:,} B)",
            flush=True,
        )


if __name__ == "__main__":
    sys.exit(main() or 0)
