"""EM_AARCH64 (ARMv8 64-bit) relocation wildcarding."""

import logging

# 0x101 R_AARCH64_ABS64
# 0x113 R_AARCH64_ADR_PREL_PG_HI21, 0x115 R_AARCH64_ADD_ABS_LO12_NC,
# 0x116 R_AARCH64_LDST8_ABS_LO12_NC, 0x11A R_AARCH64_JUMP26, 0x11B R_AARCH64_CALL26,
# 0x11C R_AARCH64_LDST16_ABS_LO12_NC, 0x11D R_AARCH64_LDST32_ABS_LO12_NC,
# 0x11E R_AARCH64_LDST64_ABS_LO12_NC, 0x137 R_AARCH64_ADR_GOT_PAGE,
# 0x138 R_AARCH64_LD64_GOT_LO12_NC, 0x139 R_AARCH64_LD64_GOTPAGE_LO15
# 0x21D R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21,
# 0x21E R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC, 0x225 R_AARCH64_TLSLE_ADD_TPREL_HI12
# 0x227 R_AARCH64_TLSLE_ADD_TPREL_LO12_NC, 0x232 R_AARCH64_TLSDESC_ADR_PAGE21
# 0x233 R_AARCH64_TLSDESC_LD64_LO12, 0x234 R_AARCH64_TLSDESC_ADD_LO12
# 0x239 R_AARCH64_TLSDESC_CALL


def apply_relocation(textsec, name, offset, rtype,
                    reloc_info, checked_offsets, ei_data, fname):
    if rtype in [0x00]:
        return
    elif rtype in [0x101, 0x102, 0x103, 0x104, 0x105, 0x106, 0x107, 0x108, 0x109,
            0x10a, 0x10b, 0x10c, 0x10d, 0x10e, 0x10f, 0x113, 0x115, 0x116, 0x118, 0x11a, 0x11b, 0x11c, 0x11d, 0x11e,
            0x137, 0x138, 0x139, 0x12b, 0x21d, 0x21e, 0x225, 0x227, 0x232, 0x233, 0x234, 0x239]:
        textsec[name][offset:offset+4] = ['??', '??', '??', '??']
    else:
        logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, offset, fname)
        # continue
        exit(-1)
