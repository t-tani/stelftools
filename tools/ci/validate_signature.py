#!/usr/bin/env python3
"""Sanity-check a freshly generated stelftools signature triple.

The four files live under ``<repo>/signatures/`` partitioned by family
(``signatures/yara/<family>/<name>.yara`` plus the matching
``signatures/configs/`` / ``signatures/deps/{dlists,aliases}/`` paths).
The family for a given signature name is derived by ``families.family_for``
so the validator stays a single-arg entry point.

This confirms that for the four files keyed by ``name``:

  - the YARA file compiles under yara-x
  - the rule count is above a minimum threshold (catches the
    relative-path / symlink-exclusion failure mode that yields a
    zero-rule file)
  - the toolchain config JSON parses and carries the expected keys
  - the dlist and alist files exist and are non-empty

The thresholds are deliberately permissive (a few hundred rules) so the
validator stays useful across libcs and architectures of very different
sizes. Reference sizes for Bootlin glibc/musl/uclibc on aarch64/mips/x86
sit in the low thousands of rules, so the floor is set well below that.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Bootlin's smallest libc/arch combination publishes around 1k rules; we
# floor well below that to keep the check architecture-agnostic.
DEFAULT_MIN_RULES = 200


def _yara_rule_count(path: Path) -> int:
    count = 0
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("rule "):
                count += 1
    return count


def _check_yara_x_compiles(path: Path) -> None:
    try:
        import yara_x  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - environment guard
        raise SystemExit(f"yara_x not importable: {exc}") from exc
    compiler = yara_x.Compiler()
    compiler.add_source(path.read_text(encoding="utf-8", errors="replace"))
    compiler.build()


def validate(repo_root: Path, name: str, min_rules: int) -> list[str]:
    errors: list[str] = []
    # The stelftools package lives at repo root; seed sys.path so this
    # script can run before a pip install -e . has happened.
    import sys
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    from stelftools.families import family_for  # type: ignore[import-not-found]
    family = family_for(name)
    sig_root = repo_root / "signatures"
    yara_path  = sig_root / "yara"    / family / f"{name}.yara"
    cfg_path   = sig_root / "configs" / family / f"{name}.json"
    dlist_path = sig_root / "deps" / "dlists"  / family / f"{name}.dlist"
    alist_path = sig_root / "deps" / "aliases" / family / f"{name}.alist"

    if not yara_path.is_file():
        errors.append(f"missing yara file: {yara_path}")
        return errors
    if yara_path.stat().st_size == 0:
        errors.append(f"empty yara file: {yara_path}")
        return errors

    rule_count = _yara_rule_count(yara_path)
    if rule_count < min_rules:
        errors.append(
            f"only {rule_count} rules in {yara_path.name} (expected >= {min_rules})"
        )

    try:
        _check_yara_x_compiles(yara_path)
    except Exception as exc:  # pragma: no cover - yara_x bubble-up
        errors.append(f"yara-x compile failed: {exc}")

    if not cfg_path.is_file():
        errors.append(f"missing config file: {cfg_path}")
    else:
        try:
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"config not valid JSON: {exc}")
            cfg = None
        if cfg is not None:
            required = {"name", "arch", "yara_path", "alias_list_path", "dependency_list_path"}
            missing = required - set(cfg)
            if missing:
                errors.append(f"config missing keys: {sorted(missing)}")
            elif cfg.get("name") != name:
                errors.append(f"config name mismatch: {cfg.get('name')!r} != {name!r}")

    for label, path in (("dlist", dlist_path), ("alist", alist_path)):
        if not path.is_file():
            errors.append(f"missing {label}: {path}")
        elif path.stat().st_size == 0:
            errors.append(f"empty {label}: {path}")

    return errors


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--name", required=True, help="Signature basename (no extension)")
    p.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parents[2]),
        help="stelftools checkout root (default: derived from script path)",
    )
    p.add_argument(
        "--min-rules",
        type=int,
        default=DEFAULT_MIN_RULES,
        help=f"Minimum rule count (default: {DEFAULT_MIN_RULES})",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    errors = validate(Path(args.repo_root), args.name, args.min_rules)
    if errors:
        for err in errors:
            print(f"FAIL: {err}", file=sys.stderr)
        return 1
    print(f"OK: {args.name}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
