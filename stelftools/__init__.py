"""stelftools: cross-architecture static-library function identification.

The package shape mirrors the three-part design the README pitches:

* :mod:`stelftools.match` -- the YARA-driven matcher and the three
  named heuristics that lift detection accuracy to 97.18% on the
  IoT-malware reference set (link-order, dependency, consecutive-
  candidate, each its own file under
  :mod:`stelftools.match.heuristics`).
* :mod:`stelftools.generate` -- the rule generator that turns a
  toolchain's ``.a`` / ``.o`` archives into the per-arch YARA rule
  set, relocation / optimisation / linker-relaxation aware
  (:mod:`stelftools.generate.fetch_opecodes` does the opcode
  extraction, :mod:`stelftools.generate.arch` carries the per-arch
  relocation handlers).
* :mod:`stelftools.elf` -- read primitives and the write-side symtab
  synthesiser shared across both stacks.

Operational glue stays at this top level: console scripts in
:mod:`stelftools.drivers` (``stelftools-ident``, ``stelftools-mkrule``,
``stelftools-bruteforce``, ``stelftools-symbolize``,
``stelftools-fetch-signatures``) tie the library to the shell;
:mod:`stelftools.sigstore` and :mod:`stelftools.families` are the
public helpers external tools and plugins reach for.
"""

from .families import family_for, known_families

__all__ = ["family_for", "known_families"]
