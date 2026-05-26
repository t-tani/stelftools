#!/usr/bin/env python3
"""Merge an externally generated old-layout signature tree into the repo.

The legacy stelftools generator writes
``configs/<family>/<sig>.json`` + ``yara/<family>/<sig>.yara`` +
``deps/{dlists,aliases}/<family>/<sig>.{dlist,alist}``. Sources that have
not yet been pivoted to the new layout (developer workstations,
upstream-tracking forks) keep producing trees in that shape.

This helper walks such a tree and lands its content into the repo's
``signatures/<family>/<arch>/`` layout:

* New (family, arch, sig) combinations land their four files in place.
* Overlapping signatures keep the repo's existing yara / dlist / alist
  (which the caller has already verified are byte-identical with the
  external source) — the cfg JSON is always re-emitted in the new
  schema so a stale schema cannot survive the merge.

The merge does not move or modify anything under ``<src>/``; the
caller can delete it freely afterwards.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path


def _new_schema_cfg(body: dict) -> dict:
    return {
        "name": body["name"],
        "arch": body["arch"],
        "compiler_path": body.get("compiler_path", ""),
    }


def merge(src_root: Path, dst_root: Path, *, dry_run: bool) -> int:
    src_configs = src_root / "configs"
    if not src_configs.is_dir():
        print(f"no {src_configs}; nothing to merge", file=sys.stderr)
        return 0

    added_sigs = 0
    overlap_sigs = 0
    rewrote_cfgs = 0
    copied_blobs = 0
    skipped_blobs = 0
    errors: list[str] = []

    for cfg_src in sorted(src_configs.rglob("*.json")):
        family = cfg_src.parent.name
        sig = cfg_src.stem
        try:
            body = json.loads(cfg_src.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"{cfg_src}: {exc}")
            continue
        arch = body.get("arch")
        if not arch:
            errors.append(f"{cfg_src}: missing 'arch'")
            continue

        dest_dir = dst_root / family / arch
        cfg_dst = dest_dir / f"{sig}.json"
        is_new = not cfg_dst.exists()

        if is_new:
            added_sigs += 1
        else:
            overlap_sigs += 1

        if not dry_run:
            dest_dir.mkdir(parents=True, exist_ok=True)
            cfg_dst.write_text(
                json.dumps(_new_schema_cfg(body), indent=2) + "\n",
                encoding="utf-8",
            )
            rewrote_cfgs += 1

        for ext, src_subdir in (
            ("yara",  "yara"),
            ("dlist", "deps/dlists"),
            ("alist", "deps/aliases"),
        ):
            src_blob = src_root / src_subdir / family / f"{sig}.{ext}"
            dst_blob = dest_dir / f"{sig}.{ext}"
            if not src_blob.is_file():
                # dlist / alist are sometimes legitimately absent for
                # very old toolchains; let the rest of the merge proceed.
                continue
            if dst_blob.is_file():
                skipped_blobs += 1
                continue
            if dry_run:
                copied_blobs += 1
                continue
            shutil.copy2(src_blob, dst_blob)
            copied_blobs += 1

    print(
        f"new sigs: {added_sigs}  overlap sigs: {overlap_sigs}  "
        f"cfgs rewritten: {rewrote_cfgs}  blobs copied: {copied_blobs}  "
        f"blobs skipped (already present): {skipped_blobs}  "
        f"errors: {len(errors)}",
        file=sys.stderr,
    )
    for err in errors:
        print(f"  error: {err}", file=sys.stderr)
    return 1 if errors else 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("src", help="External signature tree root (with configs/, yara/, deps/).")
    p.add_argument(
        "--dst",
        default=str(Path(__file__).resolve().parents[2] / "signatures"),
        help="Destination root (default: repo signatures/).",
    )
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args(argv)
    return merge(Path(args.src), Path(args.dst), dry_run=args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
