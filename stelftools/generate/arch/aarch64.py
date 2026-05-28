"""EM_AARCH64 (ARMv8 64-bit) relocation wildcarding.

Reloc type values cross-checked against mold's elf.h (commit b7102d2).
Reference: https://github.com/rui314/mold/blob/b7102d26ca42c7d72838f64c82835cb6d7ccdd7b/src/elf.h
"""

import logging

R_AARCH64_NONE                          = 0x00

R_AARCH64_ABS64                         = 0x101
R_AARCH64_ABS32                         = 0x102
R_AARCH64_ABS16                         = 0x103
R_AARCH64_PREL64                        = 0x104
R_AARCH64_PREL32                        = 0x105
R_AARCH64_PREL16                        = 0x106
R_AARCH64_MOVW_UABS_G0                  = 0x107
R_AARCH64_MOVW_UABS_G0_NC               = 0x108
R_AARCH64_MOVW_UABS_G1                  = 0x109
R_AARCH64_MOVW_UABS_G1_NC               = 0x10a
R_AARCH64_MOVW_UABS_G2                  = 0x10b
R_AARCH64_MOVW_UABS_G2_NC               = 0x10c
R_AARCH64_MOVW_UABS_G3                  = 0x10d
R_AARCH64_MOVW_SABS_G0                  = 0x10e
R_AARCH64_MOVW_SABS_G1                  = 0x10f

R_AARCH64_ADR_PREL_PG_HI21              = 0x113
R_AARCH64_ADD_ABS_LO12_NC               = 0x115
R_AARCH64_LDST8_ABS_LO12_NC             = 0x116
R_AARCH64_CONDBR19                      = 0x118
R_AARCH64_JUMP26                        = 0x11a
R_AARCH64_CALL26                        = 0x11b
R_AARCH64_LDST16_ABS_LO12_NC            = 0x11c
R_AARCH64_LDST32_ABS_LO12_NC            = 0x11d
R_AARCH64_LDST64_ABS_LO12_NC            = 0x11e

R_AARCH64_LDST128_ABS_LO12_NC           = 0x12b

R_AARCH64_ADR_GOT_PAGE                  = 0x137
R_AARCH64_LD64_GOT_LO12_NC              = 0x138
R_AARCH64_LD64_GOTPAGE_LO15             = 0x139

R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21     = 0x21d
R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC   = 0x21e

R_AARCH64_TLSLE_ADD_TPREL_HI12          = 0x225
R_AARCH64_TLSLE_ADD_TPREL_LO12_NC       = 0x227

R_AARCH64_TLSDESC_ADR_PAGE21            = 0x232
R_AARCH64_TLSDESC_LD64_LO12             = 0x233
R_AARCH64_TLSDESC_ADD_LO12              = 0x234
R_AARCH64_TLSDESC_CALL                  = 0x239

_WILDCARD_4_BYTES = [
    R_AARCH64_ABS64, R_AARCH64_ABS32, R_AARCH64_ABS16,
    R_AARCH64_PREL64, R_AARCH64_PREL32, R_AARCH64_PREL16,
    R_AARCH64_MOVW_UABS_G0, R_AARCH64_MOVW_UABS_G0_NC,
    R_AARCH64_MOVW_UABS_G1, R_AARCH64_MOVW_UABS_G1_NC,
    R_AARCH64_MOVW_UABS_G2, R_AARCH64_MOVW_UABS_G2_NC,
    R_AARCH64_MOVW_UABS_G3,
    R_AARCH64_MOVW_SABS_G0, R_AARCH64_MOVW_SABS_G1,
    R_AARCH64_ADR_PREL_PG_HI21, R_AARCH64_ADD_ABS_LO12_NC,
    R_AARCH64_LDST8_ABS_LO12_NC, R_AARCH64_CONDBR19,
    R_AARCH64_JUMP26, R_AARCH64_CALL26,
    R_AARCH64_LDST16_ABS_LO12_NC, R_AARCH64_LDST32_ABS_LO12_NC,
    R_AARCH64_LDST64_ABS_LO12_NC,
    R_AARCH64_LDST128_ABS_LO12_NC,
    R_AARCH64_ADR_GOT_PAGE, R_AARCH64_LD64_GOT_LO12_NC,
    R_AARCH64_LD64_GOTPAGE_LO15,
    R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21,
    R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC,
    R_AARCH64_TLSLE_ADD_TPREL_HI12,
    R_AARCH64_TLSLE_ADD_TPREL_LO12_NC,
    R_AARCH64_TLSDESC_ADR_PAGE21,
    R_AARCH64_TLSDESC_LD64_LO12,
    R_AARCH64_TLSDESC_ADD_LO12,
    R_AARCH64_TLSDESC_CALL,
]


def apply_relocation(textsec, name, offset, rtype,
                    reloc_info, checked_offsets, ei_data, fname):
    if rtype in [R_AARCH64_NONE]:
        return
    elif rtype in _WILDCARD_4_BYTES:
        textsec[name][offset:offset+4] = ['??', '??', '??', '??']
    else:
        logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, offset, fname)
        # continue
        exit(-1)
