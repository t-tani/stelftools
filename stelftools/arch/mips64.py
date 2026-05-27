"""EM_MIPS / ELFCLASS64 relocation wildcarding."""

# 0x00 R_MIPS_NONE
# 0x07 R_MIPS_GPREL16, 0x0b R_MIPS_CALL16,
# 0x13 R_MIPS_GOT_DISP, 0x14 R_MIPS_GOT_PAGE, 0x15 R_MIPS_GOT_OFST
# 0x25 R_MIPS_JALR, 0x2e R_MIPS_TLS_GOTTPR


def apply_relocation(textsec, name, offset, rtype,
                    reloc_info, checked_offsets, ei_data, fname):
    if rtype in [0x00]:
        return
    elif rtype in [0x07, 0x0b, 0x13, 0x14, 0x15, 0x2e, 0xa, 0x2a, 0x31, 0x32]:
        if ei_data == 'ELFDATA2MSB':  # mips
            textsec[name][offset+2:offset + 4] = ['??', '??']
        elif ei_data == 'ELFDATA2LSB':  # mipsel
            textsec[name][offset:offset + 2] = ['??', '??']
    elif rtype in [0x25, 0xc]:
        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    else:
        print('Not implemented: unknown relocation type (0x%X) at 0x%X in %s' % (rtype, offset, fname))
        exit(-1)
