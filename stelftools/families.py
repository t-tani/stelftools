"""Map a toolchain signature name to its source-vendor family directory.

The signature tree under ``signatures/`` is partitioned by the upstream
toolchain family that produced the rule set (Bootlin, Buildroot,
Aboriginal Linux, etc.) so new releases land next to their siblings and
filesystem listings stay legible at one glance. Filenames continue to
carry the family abbreviation as a prefix, so the routing is a pure
prefix match.

Used by :mod:`stelftools.generate` when writing fresh artifacts, by the
CI helpers in ``tools/ci/`` when looking up existing or in-progress
files, and by anything else that needs the four-tree placement (yara
rule, toolchain config json, dependency list, alias list) for one
toolchain name.
"""

from __future__ import annotations

# Order matters: ``ct-ng`` is a prefix of ``ct`` so the longer entry has
# to come first; the same shape will hold if we ever ship multiple
# Crosstool-NG flavours under one umbrella.
_FAMILY_PREFIXES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ('aboriginal-linux',  ('al-',)),
    ('bootlin-stable',    ('bl-stable-',)),
    ('buildroot',         ('br-',)),
    ('crosstool-ng',      ('ct-ng',)),
    ('firmware-linux',    ('fl-',)),
    ('synopsys-arc-gnu',  ('synopsys_arc_gnu',)),
    ('uclibc-pub',        ('ucli-pub-',)),
)


def family_for(tc_name: str) -> str:
    """Return the family directory name for ``tc_name``.

    Raises ``ValueError`` if no family prefix matches, so the caller
    has a chance to either register a new family or reject the input
    rather than silently scattering files into the tree root.
    """
    for family, prefixes in _FAMILY_PREFIXES:
        for prefix in prefixes:
            if tc_name.startswith(prefix):
                return family
    raise ValueError(f"unknown toolchain family for {tc_name!r}")


def known_families() -> tuple[str, ...]:
    """All family directory names, in declaration order."""
    return tuple(family for family, _ in _FAMILY_PREFIXES)
