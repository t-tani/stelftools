"""stelftools: cross-architecture static-library function identification.

This package houses the rule generator, the matcher, the dependency
parser, and a few helpers around them. The most common entry points are
exposed as console scripts (``stelftools-ident``, ``stelftools-mkrule``,
``stelftools-bruteforce``) declared in ``pyproject.toml`` and as
``python -m stelftools.<module>`` for environments that have not run a
``pip install``.

Public API surface today is intentionally narrow: ``family_for`` resolves
a toolchain signature name to its family directory and is re-exported
here so callers (CI helpers, plugins) can ``from stelftools import
family_for`` without poking at the leaf module path.
"""

from .families import family_for, known_families

__all__ = ["family_for", "known_families"]
