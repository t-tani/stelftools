"""ELF binary read primitives shared across stelftools.

Helpers in this sub-package extract structured information from an ELF
without mutating it: architecture identification, executable-region
bounds, disassembly, symbol-table reconstruction, and the MIPS GOT
resolver. The write-side counterpart that synthesises a ``.symtab``
back into a stripped binary lives in :mod:`stelftools.elf_symtab`.
"""

from .arch_info import get_bin_arch
from .disasm import get_func_addr
from .symtab import get_symtab_info_by_capstone, get_symtab_info_by_reaelf

__all__ = [
    "get_bin_arch",
    "get_func_addr",
    "get_symtab_info_by_capstone",
    "get_symtab_info_by_reaelf",
]
