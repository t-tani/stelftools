"""EM_SH (Renesas SuperH) relocation wildcarding."""

import logging

# 0x00 R_SH_NONE, 0x01 R_SH_DIR32, 0x02 R_SH_REL32, 0xa0 R_SH_GOT32,
# 0xa1 R_SH_PLT32, 0xa6 R_SH_GOTOFF, 0xa7 R_SH_GOTPC


def apply_relocation(textsec, name, offset, rtype,
                    reloc_info, checked_offsets, ei_data, fname):
    if rtype in [0x00]:
        return
    elif rtype in [0x01, 0x02, 0x93, 0xa0, 0xa1, 0xa6, 0xa7]:
        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    else:
        logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, offset, fname)
        # continue
        exit(-1)
