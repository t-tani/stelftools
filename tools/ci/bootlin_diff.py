#!/usr/bin/env python3
"""Diff a Bootlin index against the on-disk ``yara-patterns/`` directory.

Reads the JSON array produced by ``bootlin_index.py`` and emits entries that
do not yet have a matching ``yara-patterns/<signature_name>.yara`` file.

The output is JSON suitable for use as a GitHub Actions matrix ``include``
list: each row carries the ``signature_name`` plus the source URLs and the
arch/libc/release tokens consumed by ``build_bootlin_signature.sh``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_index(path: str) -> list[dict]:
    text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
    text = text.strip()
    if not text:
        return []
    if text.startswith("["):
        return json.loads(text)
    # JSON Lines fallback
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _existing_signatures(yara_dir: Path) -> set[str]:
    return {p.stem for p in yara_dir.glob("*.yara")}


def diff(entries: list[dict], yara_dir: Path) -> list[dict]:
    existing = _existing_signatures(yara_dir)
    return [e for e in entries if e["signature_name"] not in existing]


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument(
        "index",
        nargs="?",
        default="-",
        help="Path to JSON index produced by bootlin_index.py (default: stdin)",
    )
    p.add_argument(
        "--yara-dir",
        default=str(REPO_ROOT / "yara-patterns"),
        help="Directory whose *.yara stems are treated as already-generated",
    )
    p.add_argument(
        "--out",
        help="Write JSON array to this file instead of stdout",
    )
    p.add_argument(
        "--github-matrix",
        action="store_true",
        help="Emit a ``matrix=<json>`` line suitable for $GITHUB_OUTPUT",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    entries = _load_index(args.index)
    missing = diff(entries, Path(args.yara_dir))
    payload = json.dumps(missing, sort_keys=True)
    if args.github_matrix:
        line = f"matrix={payload}"
        if args.out:
            Path(args.out).write_text(line + "\n", encoding="utf-8")
        else:
            print(line)
    elif args.out:
        Path(args.out).write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    print(
        f"diff: {len(missing)} missing of {len(entries)} indexed",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
