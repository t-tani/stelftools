"""Resolve where the on-disk signature tree lives.

Resolution order (highest priority first):

1. ``$STELFTOOLS_SIGNATURES_DIR`` — explicit user override. Returned
   verbatim whether or not the directory currently exists; the user
   asked us to look there, so we look there.
2. ``<package_root>/signatures/`` — the in-repo location, used
   automatically when a checkout includes the tree.
3. ``${XDG_DATA_HOME:-~/.local/share}/stelftools/signatures/`` —
   the user cache where a future ``stelftools-fetch-signatures``
   command will land downloads.

``signatures_root()`` always returns a ``Path``; callers (bruteforce,
ident, info_create, the radare2 plugin) decide how to react to an
empty or missing tree. For reads that means an empty candidate list
falls through naturally; for writes (mkrule) the parent is created at
file-creation time.

The lookup runs on every call rather than being cached at import so an
``os.environ`` change during a session takes effect immediately.
"""

from __future__ import annotations

import os
from pathlib import Path


_PACKAGE_ROOT = Path(__file__).resolve().parent.parent


def package_root() -> Path:
    """Repository root, one level above the ``stelftools/`` package."""
    return _PACKAGE_ROOT


def _xdg_cache_root() -> Path:
    base = os.environ.get("XDG_DATA_HOME")
    if base:
        return Path(base).expanduser() / "stelftools" / "signatures"
    return Path.home() / ".local" / "share" / "stelftools" / "signatures"


def _in_repo_root() -> Path:
    return _PACKAGE_ROOT / "signatures"


def signatures_root() -> Path:
    """Return the resolved signature tree root.

    See module docstring for the resolution order.
    """
    env = os.environ.get("STELFTOOLS_SIGNATURES_DIR")
    if env:
        return Path(env).expanduser()
    in_repo = _in_repo_root()
    # Honor the in-repo location whenever the directory exists, even
    # when it is empty: a clone right after ``git pull`` is the normal
    # pre-fetch state, and falling through to XDG would route a later
    # ``stelftools-fetch-signatures`` run away from the repo path the
    # developer was using before. The XDG fallback fires only for
    # non-clone installs (``pip install stelftools`` with no checkout
    # alongside), where the repo path simply doesn't exist.
    if in_repo.is_dir():
        return in_repo
    return _xdg_cache_root()
