"""``stelftools`` entry point with subcommand dispatch.

Verbs:

* ``identify``  -- match an ELF against toolchain signatures.
* ``symbolize`` -- write matched names into a fresh .symtab.
* ``mkrule``    -- generate YARA signatures from a toolchain.
* ``fetch``     -- download published signatures.

Each verb lives in its own module (``stelftools.drivers.<verb>``) and
registers itself by calling :func:`register_parser` on the shared
subparsers. The registered parser stores its own ``run`` callable on
``args._run`` so this dispatcher stays verb-agnostic; adding a new verb
is one new module plus a single line in :data:`_VERB_MODULES` below.
"""

from __future__ import annotations

import argparse

from . import fetch, identify, mkrule, symbolize

# Order chosen for ``stelftools --help`` discoverability:
# identify and symbolize are the analyst's daily verbs, mkrule and
# fetch are the maintenance verbs.
_VERB_MODULES = (identify, symbolize, mkrule, fetch)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stelftools",
        description="Static-library function identification for stripped ELFs.",
    )
    subparsers = parser.add_subparsers(dest="verb", required=True,
                                        metavar="<verb>")
    for module in _VERB_MODULES:
        module.register_parser(subparsers)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args._run(args)


if __name__ == "__main__":
    raise SystemExit(main())
