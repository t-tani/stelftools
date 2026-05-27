"""Read the ELF header to identify architecture, bit width, and endianness."""

from elftools.elf.elffile import ELFFile
from elftools.common import exceptions


def get_bin_arch(target):
    try:
        e = ELFFile(target)
        arch = e['e_machine']
        if e['e_ident']['EI_CLASS'] == 'ELFCLASS32':
            bit = 32
        elif e['e_ident']['EI_CLASS'] == 'ELFCLASS64':
            bit = 64
        if e['e_ident']['EI_DATA'] == 'ELFDATA2LSB':
            endian = 'little'
        elif e['e_ident']['EI_DATA'] == 'ELFDATA2MSB':
            endian = 'big'
    except exceptions.ELFParseError:
        # pyelftools refuses unusual/packed headers. LIEF tolerates more
        # ELF dialects, so retry there before giving up. LIEF 0.16+
        # uppercased some enum labels (i386 -> I386, ARCH_68K -> M68K)
        # and uses CLASS.ELF32 in place of the older ELF_CLASS.CLASS32,
        # so the comparisons below normalise both forms.
        import lief
        b = lief.parse(target.name)
        if b is None:
            raise
        machine_raw = str(b.header.machine_type).rsplit('.', 1)[-1].upper()
        # capstone-side names live in EM_* form (matching pyelftools).
        # LIEF's ARCH_68K / M68K both map to EM_68K, X86_64 to EM_X86_64.
        arch = 'EM_' + {'ARCH_68K': '68K', 'M68K': '68K'}.get(machine_raw, machine_raw)
        cls = str(b.header.identity_class).rsplit('.', 1)[-1].upper()
        bit = 32 if cls in ('CLASS32', 'ELF32') else 64
        endian = 'little' \
            if str(b.header.identity_data).rsplit('.', 1)[-1].upper() == 'LSB' \
            else 'big'
    return arch, bit, endian
