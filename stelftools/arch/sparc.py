"""EM_SPARC (SPARC 32-bit) relocation wildcarding."""

import logging

# 0x00 R_SPARC_NONE, 0x03 R_SPARC_32, 0x07 R_SPARC_WDISP30, 0x08 R_SPARC_WDISP22, 0x09 R_SPARC_HI22
# 0x0b R_SPARC_13, 0x0c R_SPARC_LO10, 0x0d R_SPARC_GOT10, 0x0e R_SPARC_GOT13, 0x0f R_SPARC_GOT22
# 0x10 R_SPARC_PC10, 0x11 R_SPARC_PC22, 0x12 R_SPARC_WPLT30,
# 0x38 R_SPARC_TLS_GD_HI22, 0x39 R_SPARC_TLS_GD_LO10, 0x3a R_SPARC_TLS_GD_ADD, 0x3b R_SPARC_TLS_GD_CALL
# 0x43 R_SPARC_TLS_IE_HI22, 0x44 R_SPARC_TLS_IE_LO10, 0x45 R_SPARC_TLS_IE_LD
R_SPARC_TLS_GD_HI22 = 0x38
R_SPARC_TLS_GD_LO10 = 0x39
R_SPARC_TLS_GD_ADD = 0x3a
R_SPARC_TLS_GD_CALL = 0x3b

R_SPARC_TLS_IE_HI22 = 0x43
R_SPARC_TLS_IE_LO10 = 0x44
R_SPARC_TLS_IE_LD = 0x45

R_SPARC_GOTDATA_OP_HIX22 = 0x52
R_SPARC_GOTDATA_OP_LOX22 = 0x53
R_SPARC_GOTDATA_OP = 0x54


def apply_relocation(textsec, name, offset, rtype,
                    reloc_info, checked_offsets, ei_data, fname):
    if rtype in [0x00]:
        return
    # elif rtype in [R_SPARC_GOTDATA_OP_LOX22]:
    #     half_wild_hex = textsec[name][offset+2]
    #     textsec[name][offset+2:offset + 4] = [ half_wild_hex[0]+'?', '??']
    elif rtype in [0x0b, 0x0e, 0x12]:
        # textsec[name][offset+2:offset + 4] = ['??', '??']
        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    elif rtype in [0x0c, 0x0d, 0x10]:
        half_wild_hex = textsec[name][offset+2:offset + 4]
        textsec[name][offset+2:offset + 4] = [half_wild_hex[0][0]+'?', '??']
    elif rtype in [0x08, 0x09, 0x0f, 0x11,
            R_SPARC_TLS_GD_HI22, R_SPARC_TLS_GD_LO10, R_SPARC_TLS_GD_ADD, R_SPARC_TLS_GD_ADD]:  # , R_SPARC_GOTDATA_OP_HIX22]:
        textsec[name][offset+1:offset + 4] = ['??', '??', '??']
    elif rtype in [0x03, 0x07, 0x3b]:
        if rtype in [0x07]:
            if textsec[name][offset+0] == '40' and textsec[name][offset+4] == '9E':
                textsec[name][offset+4:offset+8] = ['( ' + textsec[name][offset+4] + ' | 01 )', '( ' + textsec[name][offset+5] + ' | 00 )', '( ' + textsec[name][offset+6] + ' | 00 )', '( ' + textsec[name][offset+7] + ' | 00 )']
        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    elif rtype in [R_SPARC_TLS_IE_HI22, R_SPARC_TLS_IE_LO10, R_SPARC_TLS_IE_LD,
            R_SPARC_GOTDATA_OP, R_SPARC_GOTDATA_OP_HIX22, R_SPARC_GOTDATA_OP_LOX22]:
        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    else:
        logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, offset, fname)
        # continue
        exit(-1)
