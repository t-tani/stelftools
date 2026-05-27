"""EM_PPC64 (PowerPC 64-bit) relocation wildcarding.

Each PPC64 relocation is processed against a 4-byte-aligned offset
(``offset // 4 * 4``) because the 64-bit ELF ABI lets relocations sit
on byte boundaries inside an instruction while the instruction itself
is fixed-width 32-bit.
"""

import logging

# ToDo : need many fix
R_PPC64_NONE = 0x00
R_PPC64_REL24 = 0x0a
R_PPC64_REL14 = 0x0b
R_PPC64_REL32 = 0x1a
R_PPC64_TOC16_LO = 0x30
R_PPC64_TOC16_HA = 0x32
R_PPC64_TOC16_DS = 0x3f
R_PPC64_TOC16_LO_DS = 0x40
R_PPC64_TLS = 0x43
R_PPC64_TPREL16_LO = 0x46
R_PPC64_TPREL16_HA = 0x48
R_PPC64_GOT_TLSGD16 = 0x4f
R_PPC64_GOT_TPREL16_DS = 0x57
R_PPC64_GOT_TPREL16_LO_DS = 0x58
R_PPC64_GOT_TPREL16_HA = 0x5a
R_PPC64_TLSGD = 0x6b
R_PPC64_REL16_LO = 0xfa
R_PPC64_REL16_HA = 0xfc


def apply_relocation(textsec, name, offset, rtype,
                    reloc_info, checked_offsets, ei_data, fname):
    fix_offset = (offset // 4) * 4
    if rtype in [R_PPC64_NONE]:
        return
    elif rtype in [R_PPC64_TOC16_LO, R_PPC64_TOC16_HA, R_PPC64_TOC16_DS, R_PPC64_TOC16_LO_DS,
            R_PPC64_TPREL16_HA, R_PPC64_TPREL16_LO, R_PPC64_GOT_TPREL16_HA, R_PPC64_GOT_TPREL16_LO_DS,
            R_PPC64_GOT_TPREL16_DS, R_PPC64_GOT_TPREL16_DS, R_PPC64_GOT_TPREL16_DS, R_PPC64_GOT_TLSGD16,
            R_PPC64_REL16_LO, R_PPC64_REL16_HA]:
        # textsec[name][fix_offset:fix_offset + 2] = ['??', '??']
        textsec[name][fix_offset:fix_offset + 4] = ['??', '??', '??', '??']
    elif rtype in [R_PPC64_REL14]:
        # textsec[name][fix_offset+2:fix_offset + 4] = ['??', '??']
        textsec[name][fix_offset:fix_offset + 4] = ['??', '??', '??', '??']
    elif rtype in [R_PPC64_REL24]:
        _0_7byte = textsec[name][fix_offset:fix_offset+1][0][0]
        # 4? xx xx xx xx : bl instcuction
        # 60 00 00 00 00 : nop
        textsec[name][fix_offset:fix_offset + 4] = ['( 60 | ' + _0_7byte+'? )', '??', '??', '??']
        textsec[name][fix_offset+4:fix_offset + 8] = ['??', '??', '??', '??']
    elif rtype in [R_PPC64_REL32, R_PPC64_TLS, R_PPC64_TLSGD]:
        textsec[name][fix_offset:fix_offset + 4] = ['??', '??', '??', '??']
    else:
        # print(textsec[name][fix_offset-2:fix_offset + 4])
        logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, fix_offset, fname)
        exit(-1)
        # continue
