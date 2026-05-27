"""Build a (file_offset, end_offset, vaddr_minus_offset) table over the
executable, readable PT_LOAD segments. ident uses this to translate
between file offsets and virtual addresses when scanning matches.

Two implementations: pyelftools first (fast, strict), LIEF fallback for
ELFs with corrupted or packed section headers that pyelftools refuses.
"""

from elftools.elf.elffile import ELFFile


def get_symtab_info_by_capstone(target):
    symtab_info = []
    PH_EXEC = 0x1
    PH_WRITE = 0x2
    PH_READ = 0x4
    with open(target, 'rb') as f:
        e = ELFFile(f)
        for s in e.iter_segments():
            if s.header['p_type'] != 'PT_LOAD':
                continue
            # exclude other section
            if s.header['p_flags'] & PH_EXEC == 0 or s.header['p_flags'] & PH_READ == 0:
                continue
            offset = s.header['p_offset']
            size   = s.header['p_filesz']
            vaddr  = s.header['p_vaddr']
            symtab_info.append((offset, offset + size, vaddr - offset))
    return symtab_info


def get_symtab_info_by_reaelf(target):
    # LIEF fallback for ELFs that pyelftools cannot parse (corrupted /
    # packed section headers). Iterates PT_LOAD with R+X just like
    # get_symtab_info_by_capstone().
    import lief
    symtab_info = []
    b = lief.parse(target)
    if b is None:
        return symtab_info
    for seg in b.segments:
        # LIEF spells the LOAD type as either SEGMENT_TYPES.LOAD (older)
        # or TYPE.LOAD (newer); compare on the trailing token only.
        if str(seg.type).rsplit('.', 1)[-1].upper() != 'LOAD':
            continue
        flags = int(seg.flags)
        # PF_R = 4, PF_X = 1
        if (flags & 0x4) == 0 or (flags & 0x1) == 0:
            continue
        offset = seg.file_offset
        size = seg.physical_size
        vaddr = seg.virtual_address
        symtab_info.append((offset, offset + size, vaddr - offset))
    return symtab_info
