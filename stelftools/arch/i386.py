"""EM_386 (Intel 80386) relocation wildcarding."""

# R_386_32(1) and R_386_PC32(2)
# R_386_TLS_GD(18), R_386_TLS_LE(0x11), R_386_TLS_LDO_32(0x20), R_386_TLS_LDM(0x13)
# R_386_TLS_IE(0x0F) R_386_TLS_GOTIE(0x10) R_386_GOT32X(0x2b)


def apply_relocation(textsec, name, offset, rtype,
                    reloc_info, checked_offsets, ei_data, fname):
    if rtype in [0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x11, 0x12, 0x13, 0x20, 0x26, 0x2a]:
        if rtype in [0x12] and textsec[name][offset - 3] == '8D' and  textsec[name][offset - 2] == '04' and textsec[name][offset - 1] == '1D':
            textsec[name][offset-3:offset] = ['( ' + textsec[name][offset-3] + ' | 65 )', '( ' + textsec[name][offset-2] + ' | A1 )', '( ' + textsec[name][offset-1] + ' | 00 )']

        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    # R_386_TLS_IE(0x0F) R_386_TLS_GOTIE(0x10) R_386_GOT32X(0x2b)
    # ref) https://docs.oracle.com/cd/E19683-01/817-3677/chapter8-1/index.html
    elif rtype in [0x0f, 0x10, 0x2b]:
        if textsec[name][offset - 1] == 'A1':
            textsec[name][offset - 1:offset + 4] = ['( A1 | B? )', '??', '??', '??', '??']  # al-1.2.4-i586, centos-5.4-i386
        elif textsec[name][offset - 2] == '8B':
            textsec[name][offset - 2:offset + 4] = ['( 8B | C7 )', '??', '??', '??', '??', '??']
        elif textsec[name][offset - 2] == '03':  # 03 15 00 00 00 00: add reg, ds:[0x0] --> 81 C? 00 00 00 00: add reg, 0xffffff?? # centos-5.4-i586
            textsec[name][offset - 2:offset + 4] = ['( 03 | 81 )', '??', '??', '??', '??', '??']
        elif textsec[name][offset - 2] == '3B':  # 3b 98 00 00 00 00: cmp reg, dword ptr [reg] --> 81 F? 00 00 00 00 # fflush+0x13: gcc-7.4.0-i686+uClibc-ng-1.0.30
            textsec[name][offset - 2:offset + 4] = ['( 3B | 81 )', '??', '??', '??', '??', '??']
        else:
            # logging.warning('Unexpected opecode: %s %s type %x offset %x', textsec[name][offset - 2], textsec[name][offset - 1], rtype, offset)
            return
            exit(-1)
    elif rtype in [20, 21]:  # R_386_16(20), R_386_PC16(21)
        textsec[name][offset:offset + 2] = ['??', '??']
    else:
        # logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, offset, fname)
        return
        exit(-1)
