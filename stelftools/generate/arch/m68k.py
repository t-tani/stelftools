"""EM_68K (Motorola 68000) relocation wildcarding.

Reloc type values cross-checked against mold's elf.h (commit b7102d2).
Reference: https://github.com/rui314/mold/blob/b7102d26ca42c7d72838f64c82835cb6d7ccdd7b/src/elf.h
"""

R_68K_NONE          = 0x00
R_68K_32            = 0x01
R_68K_PC32          = 0x04
R_68K_GOTPCREL32    = 0x07
R_68K_GOTOFF32      = 0x0a
R_68K_GOTOFF16      = 0x0b
R_68K_PLT32         = 0x0d


def apply_relocation(textsec, name, offset, rtype,
                    reloc_info, checked_offsets, ei_data, fname):
    if rtype in [R_68K_NONE]:
        return
    elif rtype in [R_68K_32, R_68K_PC32, R_68K_GOTPCREL32, R_68K_GOTOFF32, R_68K_PLT32]:
        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    elif rtype in [R_68K_GOTOFF16]:
        textsec[name][offset:offset + 2] = ['??', '??']
    else:
        # logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, offset, fname)
        return
        exit(-1)
