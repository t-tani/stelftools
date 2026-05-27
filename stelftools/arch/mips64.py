"""EM_MIPS / ELFCLASS64 relocation wildcarding.

Reloc type values cross-checked against binutils ``include/elf/mips.h``.
Reference: https://sourceware.org/git/?p=binutils-gdb.git;a=blob;f=include/elf/mips.h
"""

R_MIPS_NONE             = 0x00
R_MIPS_GPREL16          = 0x07
R_MIPS_PC16             = 0x0a
R_MIPS_CALL16           = 0x0b
R_MIPS_GPREL32          = 0x0c
R_MIPS_GOT_DISP         = 0x13
R_MIPS_GOT_PAGE         = 0x14
R_MIPS_GOT_OFST         = 0x15
R_MIPS_JALR             = 0x25
R_MIPS_TLS_GD           = 0x2a
R_MIPS_TLS_GOTTPREL     = 0x2e
R_MIPS_TLS_TPREL_HI16   = 0x31
R_MIPS_TLS_TPREL_LO16   = 0x32


def apply_relocation(textsec, name, offset, rtype,
                    reloc_info, checked_offsets, ei_data, fname):
    if rtype in [R_MIPS_NONE]:
        return
    elif rtype in [R_MIPS_GPREL16, R_MIPS_CALL16, R_MIPS_GOT_DISP, R_MIPS_GOT_PAGE,
                   R_MIPS_GOT_OFST, R_MIPS_TLS_GOTTPREL, R_MIPS_PC16, R_MIPS_TLS_GD,
                   R_MIPS_TLS_TPREL_HI16, R_MIPS_TLS_TPREL_LO16]:
        if ei_data == 'ELFDATA2MSB':  # mips
            textsec[name][offset+2:offset + 4] = ['??', '??']
        elif ei_data == 'ELFDATA2LSB':  # mipsel
            textsec[name][offset:offset + 2] = ['??', '??']
    elif rtype in [R_MIPS_JALR, R_MIPS_GPREL32]:
        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    else:
        print('Not implemented: unknown relocation type (0x%X) at 0x%X in %s' % (rtype, offset, fname))
        exit(-1)
