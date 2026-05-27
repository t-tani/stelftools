"""EM_SH (Renesas SuperH) relocation wildcarding.

Reloc type values cross-checked against mold's elf.h (commit b7102d2).
Reference: https://github.com/rui314/mold/blob/b7102d26ca42c7d72838f64c82835cb6d7ccdd7b/src/elf.h
"""

import logging

R_SH_NONE       = 0x00
R_SH_DIR32      = 0x01
R_SH_REL32      = 0x02
R_SH_TLS_IE_32  = 0x93
R_SH_GOT32      = 0xa0
R_SH_PLT32      = 0xa1
R_SH_GOTOFF     = 0xa6
R_SH_GOTPC      = 0xa7


def apply_relocation(textsec, name, offset, rtype,
                    reloc_info, checked_offsets, ei_data, fname):
    if rtype in [R_SH_NONE]:
        return
    elif rtype in [R_SH_DIR32, R_SH_REL32, R_SH_TLS_IE_32,
                   R_SH_GOT32, R_SH_PLT32, R_SH_GOTOFF, R_SH_GOTPC]:
        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    else:
        logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, offset, fname)
        # continue
        exit(-1)
