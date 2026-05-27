"""EM_ARM (32-bit ARM) relocation wildcarding."""

import logging

# 0x00 R_ARM_NONE, 0x01 R_ARM_PC24, 0x02 R_ARM_ABS32, 0x03 R_ARM_REL32, 0x04 R_ARM_LDR_PC_G0
# 0x05 R_ARM_ABS16, 0x06 R_ARM_ABS12, 0x07 R_ARM_THM_ABS5, 0x08 R_ARM_ABS8, 0x09 R_ARM_SBREL32
# 0x10 R_ARM_THM_CALL
# 0x18 R_ARM_GOTOFF32, 0x19 R_ARM_GOTPC, 0x1a R_ARM_GOT32, 0x1b R_ARM_PLT32, 0x1c R_ARM_CALL
# 0x1d R_ARM_JUMP24, 0x1c, 0x68 R_ARM_TLS_GD32, 0x6b R_ARM_TLS_IE32, 0x6c R_ARM_TLS_LE32


def apply_relocation(textsec, name, offset, rtype,
                    reloc_info, checked_offsets, ei_data, fname):
    if rtype in [0x00]:
        return
    elif rtype in [0x08]:
        textsec[name][offset:offset + 1] = ['??']
    elif rtype in [0x05]:
        textsec[name][offset:offset + 2] = ['??', '??']
    # elif rtype in [0x06]:
    #     half_wild_hex = textsec[name][offset:offset + 2]
    #     textsec[name][offset:offset + 2] = ['??', half_wild_hex[1][0]+'?']
    # elif rtype in [0x07]:
    #     half_wild_hex = textsec[name][offset:offset + 2]
    #     textsec[name][offset:offset + 2] = ['?'+half_wild_hex[0][1], half_wild_hex[1][0]+'?']
    elif rtype in [0x01]:
        textsec[name][offset:offset + 3] = ['??', '??', '??']
    elif rtype in [0x02, 0x03, 0x04, 0x09, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x68, 0x6b, 0x6c]:
        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    elif rtype in [0xa, 0x1e, 0x2b, 0x2c, 0x66, 0x69, 0x6a]:  # additional
        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    elif rtype in [0x12b, 0x2d, 0x2e, 0x12b]:  # additional
        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    # elif rtype in [0x10]:
    #     half_wild_hex = textsec[name][offset:offset + 4]
    else:
        logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, offset, fname)
        exit(-1)
