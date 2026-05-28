"""Per-architecture relocation handlers for stelftools.generate.fetch_opecodes.

Each module under this package exports one function:

    apply_relocation(textsec, name, offset, rtype,
                     reloc_info, checked_offsets, ei_data, fname) -> None

It wildcards the bytes in ``textsec[name]`` that the relocation entry
patches. ``reloc_info`` and ``checked_offsets`` are state RISC-V uses to
coalesce R_RISCV_RELAX windows across the per-relocation loop; other
handlers ignore them.

``HANDLERS[(e_machine, EI_CLASS)]`` resolves an ELF header to the right
module. :func:`dispatch` raises :class:`UnsupportedArch` when no entry
matches.
"""

from . import (
    aarch64,
    arc,
    arm,
    i386,
    m68k,
    mips32,
    mips64,
    ppc,
    ppc64,
    riscv,
    sh,
    sparc,
    sparcv9,
    x86_64,
)


class UnsupportedArch(Exception):
    """Raised when fetch_opecodes meets an unhandled (e_machine, EI_CLASS)."""


HANDLERS = {
    ('EM_386',          'ELFCLASS32'): i386,
    ('EM_X86_64',       'ELFCLASS64'): x86_64,
    ('EM_ARM',          'ELFCLASS32'): arm,
    ('EM_AARCH64',      'ELFCLASS64'): aarch64,
    ('EM_MIPS',         'ELFCLASS32'): mips32,
    ('EM_MIPS',         'ELFCLASS64'): mips64,
    ('EM_PPC',          'ELFCLASS32'): ppc,
    ('EM_PPC64',        'ELFCLASS64'): ppc64,
    ('EM_SPARC',        'ELFCLASS32'): sparc,
    ('EM_SPARCV9',      'ELFCLASS64'): sparcv9,
    ('EM_68K',          'ELFCLASS32'): m68k,
    ('EM_SH',           'ELFCLASS32'): sh,
    ('EM_ARC_COMPACT',  'ELFCLASS32'): arc,
    ('EM_ARC_COMPACT2', 'ELFCLASS32'): arc,
    # The pre-split implementation matched EM_RISCV without filtering on
    # EI_CLASS, so 64-bit RISC-V silently fell through the 32-bit branch.
    # Both keys map to the same handler here to keep that behaviour.
    ('EM_RISCV',        'ELFCLASS32'): riscv,
    ('EM_RISCV',        'ELFCLASS64'): riscv,
}


def dispatch(e):
    """Return the per-arch handler module for an ELF header, or raise."""
    key = (e['e_machine'], e['e_ident']['EI_CLASS'])
    handler = HANDLERS.get(key)
    if handler is None:
        raise UnsupportedArch(f"{key[0]} {key[1]}")
    return handler
