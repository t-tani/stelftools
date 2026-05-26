#!/usr/bin/env python3
"""Migrate the on-disk signature tree to the family/arch layout.

Before:
    signatures/configs/<family>/<sig>.json
    signatures/yara/<family>/<sig>.yara
    signatures/deps/dlists/<family>/<sig>.dlist
    signatures/deps/aliases/<family>/<sig>.alist

After:
    signatures/<family>/<arch>/<sig>.json
    signatures/<family>/<arch>/<sig>.yara
    signatures/<family>/<arch>/<sig>.dlist
    signatures/<family>/<arch>/<sig>.alist

The cfg JSON also loses ``yara_path`` / ``alias_list_path`` /
``dependency_list_path`` since paths are now derived from the cfg's own
location. Idempotent: a signature already present under the new layout
is skipped, so re-runs (after Ctrl-C or partial migration) only finish
the entries that have not moved yet.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SIG_ROOT = REPO_ROOT / "signatures"

OLD_CONFIGS = SIG_ROOT / "configs"
OLD_YARA = SIG_ROOT / "yara"
OLD_DLISTS = SIG_ROOT / "deps" / "dlists"
OLD_ALISTS = SIG_ROOT / "deps" / "aliases"

PATH_FIELDS = ("yara_path", "alias_list_path", "dependency_list_path")


def _move(src: Path, dst: Path, dry_run: bool) -> str:
    if dst.exists():
        if src.exists():
            return f"conflict: both {src} and {dst} exist; leaving src in place"
        return "already-moved"
    if not src.exists():
        return "missing-src"
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dry_run:
        return f"would move {src} -> {dst}"
    shutil.move(str(src), str(dst))
    return "moved"


def _rewrite_cfg(cfg_path: Path, dry_run: bool) -> bool:
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    changed = any(field in cfg for field in PATH_FIELDS)
    if not changed:
        return False
    for field in PATH_FIELDS:
        cfg.pop(field, None)
    if dry_run:
        return True
    # Match the original writer's two-space indent so diffs stay readable.
    cfg_path.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    return True


def migrate(dry_run: bool) -> int:
    if not OLD_CONFIGS.is_dir():
        print(f"no {OLD_CONFIGS}; nothing to migrate", file=sys.stderr)
        return 0

    moved = 0
    skipped = 0
    conflicts: list[str] = []

    for cfg_src in sorted(OLD_CONFIGS.rglob("*.json")):
        family = cfg_src.parent.name
        sig = cfg_src.stem
        cfg_body = json.loads(cfg_src.read_text(encoding="utf-8"))
        arch = cfg_body.get("arch")
        if not arch:
            conflicts.append(f"{cfg_src}: missing 'arch' field")
            continue

        dest_dir = SIG_ROOT / family / arch
        for src, dst_name in (
            (cfg_src, f"{sig}.json"),
            (OLD_YARA / family / f"{sig}.yara", f"{sig}.yara"),
            (OLD_DLISTS / family / f"{sig}.dlist", f"{sig}.dlist"),
            (OLD_ALISTS / family / f"{sig}.alist", f"{sig}.alist"),
        ):
            result = _move(src, dest_dir / dst_name, dry_run)
            if result == "moved" or result.startswith("would move"):
                moved += 1
            elif result == "already-moved":
                skipped += 1
            elif result == "missing-src":
                # dlist / alist are optional historically; tolerate.
                pass
            else:
                conflicts.append(f"{src}: {result}")

        new_cfg = dest_dir / f"{sig}.json"
        if new_cfg.exists() and not dry_run:
            _rewrite_cfg(new_cfg, dry_run=False)
        elif dry_run and (cfg_src.exists() or new_cfg.exists()):
            _rewrite_cfg(cfg_src if cfg_src.exists() else new_cfg, dry_run=True)

    # Sweep empty per-family dirs under the old layout, then the old
    # parent dirs themselves once empty.
    if not dry_run:
        for old_dir in (OLD_CONFIGS, OLD_YARA, OLD_DLISTS, OLD_ALISTS):
            if not old_dir.is_dir():
                continue
            for family_dir in old_dir.iterdir():
                if family_dir.is_dir() and not any(family_dir.iterdir()):
                    family_dir.rmdir()
            if not any(old_dir.iterdir()):
                old_dir.rmdir()
        deps = SIG_ROOT / "deps"
        if deps.is_dir() and not any(deps.iterdir()):
            deps.rmdir()

    print(f"moved={moved} skipped={skipped} conflicts={len(conflicts)}", file=sys.stderr)
    for c in conflicts:
        print(f"  conflict: {c}", file=sys.stderr)
    return 1 if conflicts else 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would change without touching the filesystem.",
    )
    args = p.parse_args(argv)
    return migrate(args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
