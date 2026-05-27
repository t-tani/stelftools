"""EM_386 (Intel 80386) relocation wildcarding.

Reloc type values cross-checked against mold's elf.h (commit b7102d2).
Reference: https://github.com/rui314/mold/blob/b7102d26ca42c7d72838f64c82835cb6d7ccdd7b/src/elf.h
"""

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

R_386_32            = 0x01
R_386_PC32          = 0x02
R_386_GOT32         = 0x03
R_386_PLT32         = 0x04
R_386_GLOB_DAT      = 0x06
R_386_JUMP_SLOT     = 0x07
R_386_RELATIVE      = 0x08
R_386_GOTOFF        = 0x09
R_386_GOTPC         = 0x0a
R_386_32PLT         = 0x0b
R_386_TLS_IE        = 0x0f
R_386_TLS_GOTIE     = 0x10
R_386_TLS_LE        = 0x11
R_386_TLS_GD        = 0x12
R_386_TLS_LDM       = 0x13
R_386_16            = 0x14
R_386_PC16          = 0x15
R_386_TLS_LDO_32    = 0x20
R_386_SIZE32        = 0x26
R_386_IRELATIVE     = 0x2a
R_386_GOT32X        = 0x2b


def apply_relocation(textsec, name, offset, rtype,
                    reloc_info, checked_offsets, ei_data, fname):
    if rtype in [R_386_32, R_386_PC32, R_386_GOT32, R_386_PLT32,
                 R_386_GLOB_DAT, R_386_JUMP_SLOT, R_386_RELATIVE,
                 R_386_GOTOFF, R_386_GOTPC, R_386_32PLT,
                 R_386_TLS_LE, R_386_TLS_GD, R_386_TLS_LDM,
                 R_386_TLS_LDO_32, R_386_SIZE32, R_386_IRELATIVE]:
        if rtype in [R_386_TLS_GD] \
                and textsec[name][offset - 3] == '8D' \
                and textsec[name][offset - 2] == '04' \
                and textsec[name][offset - 1] == '1D':
            # ``lea 0(,%ebx,1),X`` prologue for the GD sequence; widen the
            # leading bytes to also accept the equivalent ``mov %gs:0,X``
            # form the linker may emit after IE/LE relaxation.
            textsec[name][offset-3:offset] = ['( ' + textsec[name][offset-3] + ' | 65 )', '( ' + textsec[name][offset-2] + ' | A1 )', '( ' + textsec[name][offset-1] + ' | 00 )']
        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
    elif rtype in [R_386_TLS_IE, R_386_TLS_GOTIE, R_386_GOT32X]:
        # https://docs.oracle.com/cd/E19683-01/817-3677/chapter8-1/index.html
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
    elif rtype in [R_386_16, R_386_PC16]:
        textsec[name][offset:offset + 2] = ['??', '??']
    else:
        # logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, offset, fname)
        return
        exit(-1)


def apply_exec_capstone(target_sec, sym, opecodes, baseaddr):
    """ET_EXEC i386: disassemble the symbol body via capstone and
    wildcard the displacement / immediate bytes of every call, jmp, and
    Jcc the function contains so the signature survives a relink that
    shifts those targets. The pre-split implementation only handled
    EM_386 here, and any other ET_EXEC arch was silently dropped.
    """
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    code = target_sec.data()[sym['st_value'] - baseaddr:sym['st_value'] + sym['st_size'] - baseaddr]
    index = 0
    for i in md.disasm(code, 0):
        if i.mnemonic == 'call' or i.mnemonic[0] == 'j':
            if i.disp_offset > 0:
                opecodes[index + i.disp_offset:index + len(i.bytes)] = ['??'] * (len(i.bytes) - i.disp_offset)
            elif i.imm_offset > 0:
                opecodes[index + i.imm_offset:index + len(i.bytes)] = ['??'] * (len(i.bytes) - i.imm_offset)
        else:
            # Non-branch instruction whose displacement fills the rest
            # of the encoding -- widen it too.
            if i.disp_offset > 0 and (len(i.bytes) - i.disp_offset) == 4:
                opecodes[index + i.disp_offset:index + len(i.bytes)] = ['??'] * (len(i.bytes) - i.disp_offset)
        index += len(i.bytes)
