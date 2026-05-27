"""EM_RISCV relocation wildcarding.

The handler is shared by RV32 and RV64; the original pre-split code
matched ``EM_RISCV`` without filtering ``EI_CLASS``.

R_RISCV_RELAX runs alongside another relocation at the same offset and
marks a window the linker may shorten. The handler coalesces the
window by walking forward over consecutive RELAX entries (4 bytes
each), emits a single ``[0-N]`` marker for the whole span, and records
the covered offsets in ``checked_offsets`` so the per-offset loop does
not double-process them.
"""

import logging

R_RISCV_BRANCH         = 0x10
R_RISCV_JAL            = 0x11
R_RISCV_CALL           = 0x12
R_RISCV_CALL_PLT       = 0x13
R_RISCV_GOT_HI20       = 0x14
R_RISCV_TLS_GOT_HI20   = 0x15
R_RISCV_TLS_GD_HI20    = 0x16
R_RISCV_PCREL_HI20     = 0x17
R_RISCV_PCREL_LO12_I   = 0x18
R_RISCV_PCREL_LO12_S   = 0x19
R_RISCV_HI20           = 0x1a
R_RISCV_LO12_I         = 0x1b
R_RISCV_LO12_S         = 0x1c
R_RISCV_TPREL_HI20     = 0x1d
R_RISCV_TPREL_LO12_I   = 0x1e
R_RISCV_TPREL_LO12_S   = 0x1f
R_RISCV_TPREL_ADD      = 0x20
R_RISCV_ADD8           = 0x21
R_RISCV_ADD16          = 0x22
R_RISCV_ADD32          = 0x23
R_RISCV_ADD64          = 0x24
R_RISCV_SUB8           = 0x25
R_RISCV_SUB16          = 0x26
R_RISCV_SUB32          = 0x27
R_RISCV_SUB64          = 0x28
R_RISCV_GNU_VTINHERIT  = 0x29
R_RISCV_GNU_VTENTRY    = 0x2a
R_RISCV_ALIGN          = 0x2b
R_RISCV_RVC_BRANCH     = 0x2c
R_RISCV_RVC_JUMP       = 0x2d
R_RISCV_LUI            = 0x2e
R_RISCV_GPREL_I        = 0x2f
R_RISCV_GPREL_S        = 0x30
R_RISCV_TPREL_I        = 0x31
R_RISCV_TPREL_S        = 0x32
R_RISCV_RELAX          = 0x33
R_RISCV_SUB6           = 0x34
R_RISCV_SET6           = 0x35
R_RISCV_SET8           = 0x36
R_RISCV_SET16          = 0x37
R_RISCV_SET32          = 0x38
R_RISCV_32_PCREL       = 0x39


def apply_relocation(textsec, name, offset, rtype,
                    reloc_info, checked_offsets, ei_data, fname):
    if not offset in checked_offsets \
            and len(reloc_info[offset]['rtype']) != 1 and R_RISCV_RELAX in reloc_info[offset]['rtype']:
        # check the size of the relaxation area
        relax_size = 4
        while offset + relax_size in reloc_info.keys() and R_RISCV_RELAX in reloc_info[offset+relax_size]['rtype']:
            relax_size += 4
        # case : 1
        if relax_size == 4 \
                and textsec[name][offset+relax_size:offset+relax_size+4] == ['E7', '80', '00', '00']:
            relax_size += 4
        # case : 2
        if textsec[name][offset+4:offset+relax_size+4] == ['67', '00', '03', '00']:
            textsec[name][offset+4:offset+8] = ['', '', '', '']
            textsec[name][offset] = '[0-' + str(relax_size) + ']'
            # textsec[name][offset] = '[0-' + str(relax_size-1) + ']'
        else:
            textsec[name][offset] = '[0-' + str(relax_size) + ']'
        for _i in range(1, relax_size):
            textsec[name][offset+_i] = ''
        # save checked r_offset to prevent reprocessing
        for _c_offset in range(0, relax_size, 4):
            checked_offsets.append(offset+_c_offset)

    # if False: # ToDo
    if offset in checked_offsets:
        return
    elif rtype in [R_RISCV_BRANCH]:
        return
    elif not rtype in [R_RISCV_RELAX]:  # ToDo
        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    else:
        # logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, offset, fname)
        logging.warning('Not implemented: unknown relocation type %d - 0x%X at 0x%X in %s', rtype, rtype, offset, fname)
        return
        exit(-1)
