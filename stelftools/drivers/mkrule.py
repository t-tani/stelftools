"""``stelftools mkrule`` -- generate YARA signatures from a toolchain.

The verb accepts a toolchain root as its positional argument and emits
the four artifacts under ``signatures/<family>/<arch>/``:

* ``<name>.yara``  -- the YARA rule body (one rule per static-library function).
* ``<name>.dlist`` -- dependency list: per-function caller / callee
  table used by the dependency heuristic to disambiguate multi-aliased
  rule hits.
* ``<name>.alist`` -- alias list: groups of symbol names that share
  one opcode body (so a single rule fires for several names at once).
* ``<name>.json``  -- the toolchain config JSON the matcher reads at
  run time (carries ``name``, ``arch``, ``compiler_path``).

Family routing happens automatically: ``<name>`` carries the family
prefix (``fl-``, ``al-``, ``bl-stable-``, ``br-``, ``ct-ng``,
``ucli-pub-``, ``synopsys_arc_gnu``) and :mod:`stelftools.families`
resolves the destination directory.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from ..generate import create_toolchain_cfg_file, mkrule_and_other


def _announce_output(label, path, verb='created'):
    """Print one ``[successfully <verb>] <label> : <path>`` line, gated on
    the file actually existing on disk (a silent ``mkrule_and_other``
    failure would otherwise return a path with no contents)."""
    if os.path.exists(path):
        print('[successfully %s] %s : %s' % (verb, label, path))


def _add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        'toolchain_path', nargs='?',
        help='Toolchain root directory containing the .a / .o archives. '
             'When omitted, the path is inferred as two directory levels '
             'above --compiler (Bootlin layout: <root>/bin/<triplet>-gcc).',
    )
    parser.add_argument(
        '--name', required=True,
        help='Signature name. Must start with a family prefix '
             '(fl-, al-, bl-stable-, br-, ct-ng, ucli-pub-, '
             'synopsys_arc_gnu) so the output lands in the right '
             'signatures/<family>/<arch>/ directory.',
    )
    parser.add_argument(
        '--arch', required=True,
        help='Target architecture label (aarch64, mips32, mipsel, '
             'i386, x86_64, …). Matches the directory name under '
             'signatures/<family>/.',
    )
    parser.add_argument(
        '--compiler', required=True, dest='compiler_path',
        help='Path to the cross-gcc binary in the toolchain. Used at '
             'identify-time by the link-order heuristic to compile a '
             'dummy binary and observe linker ordering.',
    )
    parser.add_argument(
        '-j', '--workers', type=int, default=0,
        help='Worker processes for archive-level parallelism. '
             '0 (default) auto-picks ~half the available CPUs, capped '
             'at 8; 1 forces the serial path; values >1 dispatch to a '
             'process pool.',
    )


def register_parser(subparsers) -> argparse.ArgumentParser:
    parser = subparsers.add_parser(
        'mkrule',
        help='Generate YARA signatures from a toolchain.',
        description=__doc__.splitlines()[0],
    )
    _add_arguments(parser)
    parser.set_defaults(_run=run)
    return parser


def run(args: argparse.Namespace) -> int:
    tc_path = args.toolchain_path or str(Path(args.compiler_path).parent.parent)
    workers = None if args.workers <= 0 else args.workers

    yara_path, dlist_path, alist_path = mkrule_and_other(
        tc_path, args.name, args.arch, workers=workers,
    )
    _announce_output('yara rule', yara_path)
    _announce_output('toolchain compiler path', args.compiler_path, verb='checked')
    _announce_output('dependency list', dlist_path)
    _announce_output('alias list', alist_path)
    create_toolchain_cfg_file(args.name, args.arch, args.compiler_path)
    return 0


def main(argv: list[str] | None = None) -> int:
    """Legacy entry point for the ``stelftools-mkrule`` shim."""
    parser = argparse.ArgumentParser(prog='stelftools-mkrule')
    _add_arguments(parser)
    return run(parser.parse_args(argv))


if __name__ == '__main__':
    raise SystemExit(main())
