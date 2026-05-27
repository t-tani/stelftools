"""EM_ARC_COMPACT / EM_ARC_COMPACT2 (Synopsys ARC) relocation wildcarding.

Reloc type values cross-checked against binutils ``include/elf/arc-reloc.def``.
Reference: https://sourceware.org/git/?p=binutils-gdb.git;a=blob;f=include/elf/arc-reloc.def
"""

R_ARC_NONE              = 0x00
R_ARC_S21H_PCREL        = 0x0e
R_ARC_S21W_PCREL        = 0x0f
R_ARC_S25H_PCREL        = 0x10
R_ARC_S25W_PCREL        = 0x11
R_ARC_SDA_LDST          = 0x13
R_ARC_SDA_LDST2         = 0x15
R_ARC_SDA16_LD2         = 0x18
R_ARC_32_ME             = 0x1b
R_ARC_SDA32_ME          = 0x1e
R_ARC_SDA16_ST2         = 0x30
R_ARC_PC32              = 0x32
R_ARC_GOTPC32           = 0x33
R_ARC_S25H_PCREL_PLT    = 0x3d
R_ARC_TLS_DTPOFF        = 0x43
R_ARC_TLS_GD_GOT        = 0x45
R_ARC_TLS_GD_LD         = 0x46
R_ARC_TLS_IE_GOT        = 0x48
R_ARC_S25W_PCREL_PLT    = 0x4c


def apply_relocation(textsec, name, offset, rtype,
                    reloc_info, checked_offsets, ei_data, fname):
    if rtype in [R_ARC_NONE]:
        return
    elif rtype in [R_ARC_S25H_PCREL]:
        # S25H_PCREL targets a Bcc-class branch; widen the top nibble of
        # the leading opcode byte when the preceding byte is zero so the
        # signature accepts each Bcc variant the linker may relax to.
        if textsec[name][offset-1] == '00':
            textsec[name][offset:offset + 4] = ['( ?' + textsec[name][offset][1] + ' | DD | 45 )', '??', '??', '??']
        else:
            textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    elif rtype in [R_ARC_S25W_PCREL, R_ARC_32_ME, R_ARC_PC32, R_ARC_GOTPC32, R_ARC_S25H_PCREL_PLT,
                   R_ARC_TLS_DTPOFF, R_ARC_TLS_GD_GOT, R_ARC_TLS_GD_LD, R_ARC_TLS_IE_GOT, R_ARC_S25W_PCREL_PLT]:
        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    elif rtype in [R_ARC_S21H_PCREL, R_ARC_S21W_PCREL, R_ARC_SDA_LDST, R_ARC_SDA_LDST2,
                   R_ARC_SDA16_LD2, R_ARC_SDA32_ME, R_ARC_SDA16_ST2]:
        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    else:
        # logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, offset, fname)
        # continue
        exit(-1)
