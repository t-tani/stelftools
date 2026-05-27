"""EM_68K (Motorola 68000) relocation wildcarding.

Reloc types come from the SVR4 m68k ABI (R_68K_*).
"""

# 0x00 R_68K_NONE, 0x01 R_68K_32, 0x04 R_68K_PC32, 0x07 R_68K_GOT32,
# 0x0a R_68K_GOT320, 0x0b R_68K_GOT160, 0x0d R_68K_PLT32


def apply_relocation(textsec, name, offset, rtype,
                    reloc_info, checked_offsets, ei_data, fname):
    if rtype in [0x00]:
        return
    elif rtype in [0x01, 0x04, 0x07, 0x0a, 0x0d]:
        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    elif rtype in [0x0b]:
        textsec[name][offset:offset + 2] = ['??', '??']
    else:
        # logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, offset, fname)
        return
        exit(-1)
