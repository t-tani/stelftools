"""Deprecation shims for the pre-1.0 hyphen-separated console scripts.

Each entry point here:

1. Prints a one-line deprecation warning to stderr pointing the caller
   at the new ``stelftools <verb>`` form.
2. Translates the old argv shape into the new verb's argv (when the
   flag names changed) and forwards.

New scripts should call ``stelftools <verb>`` directly. The forwarding
keeps every old call site working unchanged.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence


def _warn(old: str, new: str) -> None:
    sys.stderr.write(
        f"warning: '{old}' is deprecated; use '{new}'.\n"
    )


def ident(argv: Sequence[str] | None = None) -> int:
    """``stelftools-ident`` -> ``stelftools identify``.

    The old entry preserved its own argparse in :mod:`stelftools.match.cli`,
    so the shim simply forwards. The new ``stelftools identify`` verb is
    the recommended replacement.
    """
    _warn("stelftools-ident", "stelftools identify <target> --cfg <cfg>")
    from ..match.cli import main as _main
    return _main() or 0


def mkrule(argv: Sequence[str] | None = None) -> int:
    """``stelftools-mkrule`` -> ``stelftools mkrule``.

    The old flag names (``-name``, ``-tp``, ``-cp``, ``-arch``,
    ``--workers``) are preserved by delegating to the original
    :func:`stelftools.generate.main`; new callers should use the verb
    form with ``--name``, ``--arch``, ``--compiler``.
    """
    _warn(
        "stelftools-mkrule",
        "stelftools mkrule <toolchain-path> --name N --arch A --compiler C",
    )
    from ..generate import main as _main
    _main()
    return 0


def bruteforce(argv: Sequence[str] | None = None) -> int:
    """``stelftools-bruteforce`` -> ``stelftools identify`` (no cfg).

    Translates the old ``-target`` / ``-arch`` / ``-libc`` / ``-j`` /
    ``-verbose`` flags into the new positional + long-flag shape so the
    consolidated identify verb runs unchanged.
    """
    _warn("stelftools-bruteforce", "stelftools identify <target> [--arch A] [--libc L]")
    parser = argparse.ArgumentParser(prog="stelftools-bruteforce")
    parser.add_argument("-target", required=True)
    parser.add_argument("-arch", default=None)
    parser.add_argument("-libc", default=None)
    parser.add_argument("-j", "--jobs", type=int, default=None)
    parser.add_argument("-verbose", "-v", action="store_true")
    args = parser.parse_args(argv)

    new_argv = [args.target, "--verdict-only"]
    if args.arch is not None:
        new_argv += ["--arch", args.arch]
    if args.libc is not None:
        new_argv += ["--libc", args.libc]
    if args.jobs is not None:
        new_argv += ["-j", str(args.jobs)]
    if args.verbose:
        new_argv += ["--verbose"]

    from .identify import main as _main
    return _main(new_argv)


def symbolize(argv: Sequence[str] | None = None) -> int:
    """``stelftools-symbolize`` -> ``stelftools symbolize``.

    The old ``--out`` flag (summary JSON path) was renamed to
    ``--summary`` so a future shared ``-o`` shortcut can mean
    "output ELF" across all verbs. The shim performs the rename
    transparently.
    """
    _warn("stelftools-symbolize", "stelftools symbolize <binary> --out-elf O")
    raw = list(argv) if argv is not None else sys.argv[1:]
    translated: list[str] = []
    i = 0
    while i < len(raw):
        tok = raw[i]
        if tok == "--out":
            translated += ["--summary"]
            i += 1
            continue
        if tok.startswith("--out="):
            translated.append("--summary=" + tok.split("=", 1)[1])
            i += 1
            continue
        translated.append(tok)
        i += 1
    from .symbolize import main as _main
    return _main(translated)


def fetch(argv: Sequence[str] | None = None) -> int:
    """``stelftools-fetch-signatures`` -> ``stelftools fetch``.

    Argument shape is identical; only the entry-point name changes.
    """
    _warn("stelftools-fetch-signatures", "stelftools fetch")
    from .fetch import main as _main
    return _main(argv)
