"""EM_ARM (32-bit ARM) relocation wildcarding.

Reloc type values cross-checked against mold's elf.h (commit b7102d2).
Reference: https://github.com/rui314/mold/blob/b7102d26ca42c7d72838f64c82835cb6d7ccdd7b/src/elf.h
"""

import logging

R_ARM_NONE              = 0x00
R_ARM_PC24              = 0x01
R_ARM_ABS32             = 0x02
R_ARM_REL32             = 0x03
R_ARM_LDR_PC_G0         = 0x04
R_ARM_ABS16             = 0x05
R_ARM_ABS12             = 0x06
R_ARM_THM_ABS5          = 0x07
R_ARM_ABS8              = 0x08
R_ARM_SBREL32           = 0x09
R_ARM_THM_CALL          = 0x0a
R_ARM_GOTOFF32          = 0x18
R_ARM_BASE_PREL         = 0x19
R_ARM_GOT_BREL          = 0x1a
R_ARM_PLT32             = 0x1b
R_ARM_CALL              = 0x1c
R_ARM_JUMP24            = 0x1d
R_ARM_THM_JUMP24        = 0x1e
R_ARM_MOVW_ABS_NC       = 0x2b
R_ARM_MOVT_ABS          = 0x2c
R_ARM_MOVW_PREL_NC      = 0x2d
R_ARM_MOVT_PREL         = 0x2e
R_ARM_THM_JUMP11        = 0x66
R_ARM_TLS_GD32          = 0x68
R_ARM_TLS_LDM32         = 0x69
R_ARM_TLS_LDO32         = 0x6a
R_ARM_TLS_IE32          = 0x6b
R_ARM_TLS_LE32          = 0x6c

# Out-of-spec value carried over from the pre-split implementation;
# value 0x12b (decimal 299) is past the highest standard R_ARM_* entry.
# Treated as a 4-byte wildcard until the corpus identifies it.
R_ARM_UNKNOWN_0X12B     = 0x12b


def apply_relocation(textsec, name, offset, rtype,
                    reloc_info, checked_offsets, ei_data, fname):
    if rtype in [R_ARM_NONE]:
        return
    elif rtype in [R_ARM_ABS8]:
        textsec[name][offset:offset + 1] = ['??']
    elif rtype in [R_ARM_ABS16]:
        textsec[name][offset:offset + 2] = ['??', '??']
    elif rtype in [R_ARM_PC24]:
        textsec[name][offset:offset + 3] = ['??', '??', '??']
    elif rtype in [R_ARM_ABS32, R_ARM_REL32, R_ARM_LDR_PC_G0, R_ARM_SBREL32,
                   R_ARM_GOTOFF32, R_ARM_BASE_PREL, R_ARM_GOT_BREL, R_ARM_PLT32,
                   R_ARM_CALL, R_ARM_JUMP24,
                   R_ARM_TLS_GD32, R_ARM_TLS_IE32, R_ARM_TLS_LE32]:
        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    elif rtype in [R_ARM_THM_CALL, R_ARM_THM_JUMP24,
                   R_ARM_MOVW_ABS_NC, R_ARM_MOVT_ABS,
                   R_ARM_THM_JUMP11, R_ARM_TLS_LDM32, R_ARM_TLS_LDO32]:
        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    elif rtype in [R_ARM_UNKNOWN_0X12B, R_ARM_MOVW_PREL_NC, R_ARM_MOVT_PREL]:
        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    else:
        logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, offset, fname)
        exit(-1)
