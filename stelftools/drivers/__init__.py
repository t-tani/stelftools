"""Console-script entry points for stelftools.

Each module here ties one user-facing CLI verb to the library
packages. The :mod:`.cli` module is the entry point (``stelftools
<verb>``) and dispatches to:

* :mod:`.identify`  -- match an ELF against toolchain signatures and
  report which toolchain produced it.
* :mod:`.symbolize` -- write the matched library-function names into
  a fresh ``.symtab`` on a copy of the ELF, so downstream
  disassemblers (IDA, Ghidra) show named functions.
* :mod:`.mkrule`    -- generate new toolchain signatures from a
  cross-toolchain tree.
* :mod:`.fetch`     -- download published signature tarballs from
  GitHub Release attachments.
* :mod:`.legacy_shims` -- one-line deprecation receivers for the
  pre-1.0 hyphen-separated console scripts (forward to the verbs
  above).
"""
