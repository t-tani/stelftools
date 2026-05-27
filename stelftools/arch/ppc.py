"""EM_PPC (PowerPC 32-bit) relocation wildcarding."""

import logging

# 0x00 R_PPC_NONE, 0x04 R_PPC_ADDR16_LO, 0x06 R_PPC_ADDR_16_HA, 0x0a R_PPC_REL24, 0x0e R_PPC_GOT16
# 0x12 R_PPC_PLTREL24, 0x17 R_PPC_LOCAL24PC, 0x1a R_PPC_REL32,
# 0x43 R_PPC_TLS, 0x57 R_PPC_GOT_TPREL16
# 0xfa R_PPC_REL16_HI 0xfc R_PPC_REL16_HA
R_PPC_TPREL16_LO = 0x46
R_PPC_TPREL16_HA = 0x48
R_PPC_GOT_TLSGD16 = 0x4f
R_PPC_GOT_TPREL16 = 0x57
R_PPC_TLSGD = 0x5f

R_PPC_DTPREL16_LO = 0x4b
R_PPC_DTPREL16_HA = 0x4d
R_PPC_GOT_TLSLD16 = 0x53
R_PPC_TLSLD = 0x60


def apply_relocation(textsec, name, offset, rtype,
                    reloc_info, checked_offsets, ei_data, fname):
    if rtype in [0x00]:
        return
    elif rtype in [0x04, 0x06, 0x0e, 0xfa, 0xfc]:  # , R_PPC_TPREL16_HA]:
        textsec[name][offset:offset + 2] = ['??', '??']
    elif rtype in [R_PPC_GOT_TPREL16, R_PPC_GOT_TLSGD16, R_PPC_TPREL16_LO, R_PPC_TPREL16_HA]:  # optimize?
        textsec[name][offset-2:offset+2] = ['??', '??', '??', '??']
    elif rtype in [0x1a, 0x43, R_PPC_TLSGD]:
        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    elif rtype in [0x0a, 0x12, 0x17]:
        half_wild_hex = textsec[name][offset:offset + 4]
        textsec[name][offset:offset + 4] = ['( '+half_wild_hex[0][0]+'? | 3? )', '??', '??', '??']
    elif rtype in [R_PPC_GOT_TLSLD16, R_PPC_DTPREL16_LO, R_PPC_DTPREL16_HA]:
        textsec[name][offset:offset + 2] = ['??', '??']
    elif rtype in [R_PPC_TLSLD]:
        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    else:
        logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, offset, fname)
        exit(-1)
