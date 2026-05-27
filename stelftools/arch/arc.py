"""EM_ARC_COMPACT / EM_ARC_COMPACT2 (Synopsys ARC) relocation wildcarding."""

# 0x00 R_ARC_NONE, 0x10 R_ARC_S25H_PCREL, 0x11 R_ARC_S25W_PCREL, 0x1b R_ARC_32_ME
# 0x33 R_ARC_GOTPC32, 0x32 R_ARC_PC32, 0x3d R_ARC_S25H_PCREL_,
# 0x43 R_ARC_TLS_DTPOFF, 0x45 R_ARC_TLS_GD_GOT, 0x46 R_ARC_TLS_GD_LD,
# 0x48 R_ARC_TLS_IE_GOT, 0x4C R_ARC_S25W_PCREL


def apply_relocation(textsec, name, offset, rtype,
                    reloc_info, checked_offsets, ei_data, fname):
    if rtype in [0x00]:
        return
    elif rtype in [0x10]:
        # textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
        if textsec[name][offset-1] == '00':
            textsec[name][offset:offset + 4] = ['( ?' + textsec[name][offset][1] + ' | DD | 45 )', '??', '??', '??']
        else:
            textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    elif rtype in [0x11, 0x1b, 0x32, 0x33, 0x3d, 0x43, 0x45, 0x46, 0x48, 0x4c]:
        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    elif rtype in [0x0e, 0x0f, 0x13, 0x15, 0x18, 0x1e, 0x30]:
        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    else:
        # logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, offset, fname)
        # continue
        exit(-1)
