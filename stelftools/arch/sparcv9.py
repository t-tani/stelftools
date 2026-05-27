"""EM_SPARCV9 (SPARC 64-bit) relocation wildcarding.

The 64-bit ABI packs additional info in the high bits of the
relocation type field; the active type is the low byte
(``rtype & 0xff``).

Reloc type values cross-checked against mold's elf.h (commit b7102d2).
Reference: https://github.com/rui314/mold/blob/b7102d26ca42c7d72838f64c82835cb6d7ccdd7b/src/elf.h
"""

R_SPARC_NONE                = 0x00
R_SPARC_32                  = 0x03
R_SPARC_WDISP30             = 0x07
R_SPARC_WDISP22             = 0x08
R_SPARC_HI22                = 0x09
R_SPARC_13                  = 0x0b
R_SPARC_LO10                = 0x0c
R_SPARC_GOT10               = 0x0d
R_SPARC_GOT13               = 0x0e
R_SPARC_GOT22               = 0x0f
R_SPARC_PC10                = 0x10
R_SPARC_PC22                = 0x11
R_SPARC_WPLT30              = 0x12

R_SPARC_OLO10               = 0x21
R_SPARC_HH22                = 0x22
R_SPARC_HM10                = 0x23
R_SPARC_LM22                = 0x24

R_SPARC_TLS_GD_HI22         = 0x38
R_SPARC_TLS_GD_LO10         = 0x39
R_SPARC_TLS_GD_ADD          = 0x3a
R_SPARC_TLS_GD_CALL         = 0x3b

R_SPARC_TLS_IE_HI22         = 0x43
R_SPARC_TLS_IE_LO10         = 0x44
R_SPARC_TLS_IE_LD           = 0x45
R_SPARC_TLS_IE_LDX          = 0x46
R_SPARC_TLS_IE_ADD          = 0x47
R_SPARC_TLS_LE_HIX22        = 0x48
R_SPARC_TLS_LE_LOX10        = 0x49

R_SPARC_GOTDATA_OP_HIX22    = 0x52
# Mold names 0x53 R_SPARC_GOTDATA_OP_LOX10; older binutils releases and
# the pre-split implementation called it LOX22. Aliased so a corpus
# produced under either naming remains readable.
R_SPARC_GOTDATA_OP_LOX10    = 0x53
R_SPARC_GOTDATA_OP_LOX22    = 0x53  # legacy alias
R_SPARC_GOTDATA_OP          = 0x54


def apply_relocation(textsec, name, offset, rtype,
                    reloc_info, checked_offsets, ei_data, fname):
    fix_rtype = rtype & 0xff
    if fix_rtype in [R_SPARC_NONE]:
        return
    elif fix_rtype in [R_SPARC_13, R_SPARC_GOT13, R_SPARC_WPLT30]:
        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    elif fix_rtype in [R_SPARC_LO10, R_SPARC_GOT10, R_SPARC_PC10]:
        half_wild_hex = textsec[name][offset+2:offset + 4]
        textsec[name][offset+2:offset + 4] = [half_wild_hex[0][0]+'?', '??']
    elif fix_rtype in [R_SPARC_WDISP22, R_SPARC_HI22, R_SPARC_GOT22, R_SPARC_PC22,
                       R_SPARC_TLS_GD_HI22, R_SPARC_TLS_GD_LO10, R_SPARC_TLS_GD_ADD]:
        textsec[name][offset+1:offset + 4] = ['??', '??', '??']
    elif fix_rtype in [R_SPARC_32, R_SPARC_WDISP30, R_SPARC_TLS_GD_CALL]:
        if fix_rtype in [R_SPARC_WDISP30]:
            if textsec[name][offset+0] == '40' and textsec[name][offset+4] == '9E':
                textsec[name][offset+4:offset+8] = ['( ' + textsec[name][offset+4] + ' | 01 )', '( ' + textsec[name][offset+5] + ' | 00 )', '( ' + textsec[name][offset+6] + ' | 00 )', '( ' + textsec[name][offset+7] + ' | 00 )']
        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    elif fix_rtype in [R_SPARC_TLS_IE_HI22, R_SPARC_TLS_IE_LO10, R_SPARC_TLS_IE_LD,
                       R_SPARC_GOTDATA_OP, R_SPARC_GOTDATA_OP_HIX22, R_SPARC_GOTDATA_OP_LOX10]:
        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    elif fix_rtype in [R_SPARC_OLO10, R_SPARC_HM10, R_SPARC_TLS_LE_LOX10]:
        textsec[name][offset+2:offset+4] = ['??', '??']
    elif fix_rtype in [R_SPARC_HH22, R_SPARC_LM22, R_SPARC_TLS_LE_HIX22]:
        textsec[name][offset+1:offset+4] = ['??', '??', '??']
    elif fix_rtype in [R_SPARC_TLS_IE_LDX, R_SPARC_TLS_IE_ADD]:
        textsec[name][offset:offset+4] = ['??', '??', '??', '??']
    else:
        # logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', fix_rtype, offset, fname)
        # continue
        exit(-1)
