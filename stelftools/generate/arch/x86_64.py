"""EM_X86_64 (AMD64) relocation wildcarding.

Reloc type values cross-checked against mold's elf.h (commit b7102d2).
Reference: https://github.com/rui314/mold/blob/b7102d26ca42c7d72838f64c82835cb6d7ccdd7b/src/elf.h
"""

import logging

R_X86_64_NONE           = 0x00
R_X86_64_64             = 0x01
R_X86_64_PC32           = 0x02
R_X86_64_PLT32          = 0x04
R_X86_64_GOTPCREL       = 0x09
R_X86_64_32             = 0x0a
R_X86_64_32S            = 0x0b
R_X86_64_TLSGD          = 0x13
R_X86_64_TLSLD          = 0x14
R_X86_64_DTPOFF32       = 0x15
R_X86_64_GOTTPOFF       = 0x16
R_X86_64_TPOFF32        = 0x17
R_X86_64_GOTPC32        = 0x1a
R_X86_64_GOTPCRELX      = 0x29
R_X86_64_REX_GOTPCRELX  = 0x2a


def apply_relocation(textsec, name, offset, rtype,
                    reloc_info, checked_offsets, ei_data, fname):
    if rtype in [R_X86_64_64]:
        textsec[name][offset:offset + 8] = ['??', '??', '??', '??', '??', '??', '??', '??']
    elif rtype in [R_X86_64_PC32, R_X86_64_PLT32, R_X86_64_GOTPCREL,
                   R_X86_64_32, R_X86_64_32S,
                   R_X86_64_TLSGD, R_X86_64_TLSLD, R_X86_64_DTPOFF32,
                   R_X86_64_TPOFF32, R_X86_64_GOTPC32, R_X86_64_GOTPCRELX]:
        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    elif rtype in [R_X86_64_GOTTPOFF, R_X86_64_REX_GOTPCRELX]:
        # 6-byte wildcard for the instruction + 32-bit displacement, plus
        # widening the REX prefix to any value with a 4-bit-set high nibble.
        textsec[name][offset-2:offset + 4] = ['??', '??', '??', '??', '??', '??']
        textsec[name][offset-3:offset-2] = ['4?']
    else:
        logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, offset, fname)
        # continue
        exit(-1)
