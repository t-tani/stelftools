"""EM_X86_64 (AMD64) relocation wildcarding."""

import logging

# readelf -r /usr/lib/x86_64-linux-gnu/libc.a | cut -f3-4 -d' ' | grep R_ | cut -b10- | sort | uniq -c
# 001 R_X86_64_64 002 R_X86_64_PC32 004 R_X86_64_PLT32 009 R_X86_64_GOTPCREL
# 00a R_X86_64_32 00b R_X86_64_32S 013 R_X86_64_TLSGD 014 R_X86_64_TLSLD
# 015 R_X86_64_DTPOFF32 016 R_X86_64_GOTTPOFF
# 017 R_X86_64_TPOFF32 01a R_X86_64_GOTPC32 029 R_X86_64_GOTPCREL 02a R_X86_64_REX_GOTP
R_X86_64_GOTTPOFF = 0x16
R_X86_64_REX_GOTPCRELX = 0x2a


def apply_relocation(textsec, name, offset, rtype,
                    reloc_info, checked_offsets, ei_data, fname):
    if rtype in [0x01]:
        textsec[name][offset:offset + 8] = ['??', '??', '??', '??', '??', '??', '??', '??']
    elif rtype in [0x02, 0x04, 0x09, 0x0A, 0x0B, 0x13, 0x14, 0x15, 0x17, 0x1A, 0x29]:
        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    elif rtype in [R_X86_64_GOTTPOFF, R_X86_64_REX_GOTPCRELX]:
        textsec[name][offset-2:offset + 4] = ['??', '??', '??', '??', '??', '??']
        # textsec[name][offset-3:offset-2] = ['( ' + textsec[name][offset-3] + ' | 4? )']
        textsec[name][offset-3:offset-2] = ['4?']
    else:
        logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, offset, fname)
        # continue
        exit(-1)
