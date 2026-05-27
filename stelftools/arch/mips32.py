"""EM_MIPS / ELFCLASS32 relocation wildcarding.

Splits big- vs little-endian by ``EI_DATA``: ELFDATA2MSB wildcards the
low half (offset+2..offset+4) of the 32-bit instruction; ELFDATA2LSB
wildcards the low half at offset..offset+2.
"""

import logging

# 0x01 R_MIPS_NONE 0x05 R_MIPS_HI16 0x06 R_MIPS_LO16, 0x09 R_MIPS_GOT16, 0x0A R_MIPS_PC16
# 0x0c R_MIPS_GPREL32
R_MIPS_GOT16 = 0x09
R_MIPS_CALL16 = 0x0b
R_MIPS_TLS_TPREL_HI16 = 0x31
R_MIPS_TLS_TPREL_LO16 = 0x32


def apply_relocation(textsec, name, offset, rtype,
                    reloc_info, checked_offsets, ei_data, fname):
    if rtype in [0x00]:
        return
    elif rtype in [0x05, 0x06, 0x0a, 0x2e, R_MIPS_TLS_TPREL_HI16, R_MIPS_TLS_TPREL_LO16]:
        if ei_data == 'ELFDATA2MSB':  # mips
            textsec[name][offset+2:offset + 4] = ['??', '??']
        if ei_data == 'ELFDATA2LSB':  # mipsel
            textsec[name][offset:offset + 2] = ['??', '??']
    elif rtype in [0x0c]:
        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    elif rtype in [0x04, 0x25, 0x2a, 0x2b, 0x2c, 0x2d]:  # mips r3000
        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    elif rtype in [R_MIPS_GOT16, R_MIPS_CALL16]:
        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    else:
        logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, offset, fname)
        exit(-1)
