"""Disassemble an ELF's executable region and parse the call sites.

The entry point :func:`get_func_addr` ties four stages together:
:func:`get_bin_arch` (from :mod:`.arch_info`) reports the architecture,
:func:`get_inst_area` fixes the executable region, the matching
back-end (:func:`capstone_disasm_bin` for every supported architecture
except ARC, :func:`objdump_disasm_bin` via :func:`_find_objdump` for
ARC) produces an ``{addr: instruction}`` map, and :func:`parse_inst`
walks it to extract a per-arch ``(call_inst_addr, call_inst_size,
callee_addr)`` table. MIPS adds a GOT-resolution post-pass via
:func:`._mips_got_map` so ``lw $reg, gp_offset($gp)`` loads resolve to
the callee.
"""

import os
import re
import shutil
import subprocess
import sys

from capstone import *
from elftools.elf.elffile import ELFFile
from elftools.common import exceptions

from .arch_info import get_bin_arch
from .mips_got import _mips_got_map


def get_inst_area(target, base_vaddr, t_bit):
    top_inst_addr = 0
    bot_inst_addr = 0
    # pyelftools
    try: # pyelftools
        e = ELFFile(target)
        # get elf instruction area
        _sh_addr_list = []
        _last_sec_addr = 0x0
        for sec in e.iter_sections():
            if sec.header['sh_type'] == 'SHT_PROGBITS' and sec.header['sh_flags'] == 6:
                _sh_addr_list.append(sec.header['sh_addr'])
                #print(hex(sec.header['sh_addr']), hex(sec.header['sh_size']))
                if _last_sec_addr < sec.header['sh_addr']:
                    _last_sec_addr = sec.header['sh_addr']
                    bot_inst_addr = sec.header['sh_addr'] + sec.header['sh_size']
        if len(_sh_addr_list) != 0:
            if 0x0 > min(_sh_addr_list) - base_vaddr: # ToDo: fix worng code
                top_inst_addr = min(_sh_addr_list)
                bot_inst_addr = bot_inst_addr - 1
            else:
                top_inst_addr = min(_sh_addr_list) - base_vaddr
                bot_inst_addr = bot_inst_addr - base_vaddr - 1
            #print(hex(top_inst_addr), '~', hex(bot_inst_addr))
        #exit(-1)
    except exceptions.ELFParseError:
        pass
    if top_inst_addr == bot_inst_addr == 0:
        # Fallback for ELFs whose section table is stripped or malformed:
        # derive the executable region from the first PT_LOAD with R+X.
        import lief
        b = lief.parse(target.name)
        if b is not None:
            for seg in b.segments:
                if str(seg.type).rsplit('.', 1)[-1].upper() != 'LOAD':
                    continue
                flags = int(seg.flags)
                # PF_R = 4, PF_X = 1
                if (flags & 0x4) == 0 or (flags & 0x1) == 0:
                    continue
                top_inst_addr = seg.virtual_address - base_vaddr
                bot_inst_addr = top_inst_addr + seg.physical_size
                break
    return top_inst_addr, bot_inst_addr


def capstone_disasm_bin(target, t_arch, t_bit, t_endian, top_inst_addr, bot_inst_addr):
    target_inst = {}
    # set capstone md
    if t_arch in ['EM_AARCH64']:
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    elif t_arch in ['EM_386']:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    elif t_arch in ['EM_X86_64']:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    elif t_arch in ['EM_ARM']:
        if t_endian == 'big':
            md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_BIG_ENDIAN) # armeb
        elif t_endian == 'little':
            md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN) # arml, armle
        #md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_THUMB | CS_MODE_MCLASS) # cortexm
    elif t_arch in ['EM_MIPS']: # not check
        if t_bit == 32:
            if t_endian == 'big':
                md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN)
            elif t_endian == 'little':
                md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
        elif t_bit == 64:
            if t_endian == 'big':
                md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN)
            elif t_endian == 'little':
                md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN)
    elif t_arch in ['EM_68K']:
        md = Cs(CS_ARCH_M68K, CS_MODE_M68K_040)
        md.skipdata = True
    elif t_arch in ['EM_PPC']:
        if t_endian == 'big':
            md = Cs(CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN)
        elif t_endian == 'little':
            md = Cs(CS_ARCH_PPC, CS_MODE_32 | CS_MODE_LITTLE_ENDIAN)
    elif t_arch in ['EM_PPC64']:
        if t_endian == 'big':
            md = Cs(CS_ARCH_PPC, CS_MODE_64 | CS_MODE_BIG_ENDIAN)
        elif t_endian == 'little':
            md = Cs(CS_ARCH_PPC, CS_MODE_64 | CS_MODE_LITTLE_ENDIAN)
    elif t_arch in ['EM_RISCV']:
        if t_bit == 32:
            md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32)
        elif t_bit == 64:
            md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)
    elif t_arch in ['EM_SPARC']:
        md = Cs(CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN)
    elif t_arch in ['EM_SPARCV9']:
        md = Cs(CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN + CS_MODE_V9)
    elif t_arch in ['EM_SH']:
        # Capstone 5.0 added CS_ARCH_SH. SH4 mode decodes the SH2/SH3
        # instruction subset that firmware libraries use.
        if t_endian == 'big':
            md = Cs(CS_ARCH_SH, CS_MODE_SH4 | CS_MODE_BIG_ENDIAN)
        elif t_endian == 'little':
            md = Cs(CS_ARCH_SH, CS_MODE_SH4 | CS_MODE_LITTLE_ENDIAN)
    else:
        print("[disasm/capstone] Not support arch : %s " % t_arch, file = sys.stderr)
        exit(-1)
    md.skipdata = True
    md.detail = True
    target.seek(top_inst_addr)
    target_code = target.read()
    for i in md.disasm(target_code, top_inst_addr):
        if i.address >= top_inst_addr and i.address <= bot_inst_addr:
            target_inst[i.address] = i
        elif bot_inst_addr != 0 and i.address > bot_inst_addr:
            break
    return target_inst


def _find_objdump(t_arch):
    """Locate an objdump that disassembles EM_ARC_COMPACT. Returns its path.

    Capstone has no ARC backend, so ARC is the one architecture still routed
    through an external objdump. The STELFTOOLS_ARC_OBJDUMP environment
    variable overrides the search. Otherwise probe PATH for an ARC
    cross-objdump, then fall back to a multiarch objdump whose `--info`
    reports an ARC BFD target (the binutils-multiarch package builds one).
    Raises RuntimeError with an actionable message when none is found.
    """
    if t_arch != 'EM_ARC_COMPACT':
        raise ValueError("objdump disassembly is only used for EM_ARC_COMPACT, got %s" % t_arch)
    override = os.environ.get('STELFTOOLS_ARC_OBJDUMP')
    if override:
        if shutil.which(override) is None and not os.path.isfile(override):
            raise RuntimeError(
                "STELFTOOLS_ARC_OBJDUMP is set to '%s' but no such executable exists" % override)
        return override
    for name in ['arc-linux-objdump', 'arc-linux-gnu-objdump',
                 'arc-elf32-objdump', 'arceb-linux-objdump',
                 'arc-snps-linux-uclibc-objdump']:
        path = shutil.which(name)
        if path:
            return path
    generic = shutil.which('objdump')
    if generic:
        info = subprocess.run([generic, '--info'], text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if re.search('arc', info.stdout, re.IGNORECASE):
            return generic
    raise RuntimeError(
        "no ARC-capable objdump found. Install binutils-multiarch, or an ARC "
        "cross-binutils, or point STELFTOOLS_ARC_OBJDUMP at one.")


def objdump_disasm_bin(target, t_arch, t_bit, t_endian, top_inst_addr, bot_inst_addr):
    target_inst = {}
    target_path = target.name
    OBJDUMP_PATH = _find_objdump(t_arch)
    objdump_res = subprocess.run([OBJDUMP_PATH, '-d', target_path], text=True, capture_output=True)
    for d_line in objdump_res.stdout.split('\n'):
        # del blank line
        if d_line == '':
            continue
        if re.search("^[ ]+[0-9a-fA-F]+", d_line) == None:
            continue
        _addr = int(re.sub(r'[\s+|:]', '', d_line.split('\t')[0]), 16)
        _hex = [_h for _h in (d_line.split('\t')[1].split(' ')) if _h != '']
        _inst = ' '.join([_i for _i in (d_line.split('\t')[2:]) if _i != ''])
        #print(hex(_addr), _hex, _inst)
        target_inst[_addr] = {'bytecode': _hex, 'inst': _inst}
    return target_inst


def parse_inst(target, target_inst, base_vaddr, t_arch, t_bit, t_endian, top_inst_addr, bot_inst_addr):
    func_addr = []
    call_map = []

    got_addr_resolve_map = []
    readelf_got_map = []
    if t_arch in ['EM_MIPS']:
        got_addr_map = []
        readelf_got_map = _mips_got_map(target.name)

    #inst_addrs = sorted([k for k, v in target_inst.items()])
    inst_addrs = sorted(target_inst.keys())
    for addr in inst_addrs:
        i = target_inst[addr]
        if t_arch in ['EM_AARCH64', 'EM_ARM']: # aarch64
            if i.mnemonic == 'bl' or i.mnemonic == 'blls' \
                    or i.mnemonic == 'blne' or i.mnemonic == 'b' \
                    or i.mnemonic == 'bx' and i.op_str.startswith('#0x'):
                call_addr = int(re.sub('^#',  '', i.op_str), 16)
                if call_addr >= top_inst_addr and call_addr <= bot_inst_addr:
                    func_addr.append(call_addr)
                    #print(hex(i.address), i.size, hex(call_addr))
                    call_map.append([ \
                            i.address, i.size, call_addr \
                            ])
        # i386, x86, x86-64
        elif t_arch in ['EM_386', 'EM_X86_64', 'EM_SPARC', 'EM_SPARCV9']: # ix86, x86_64, sparc
            if (i.mnemonic == 'call' and i.op_str.startswith('0x')) \
                    or (i.mnemonic == 'jmp' and i.op_str.startswith('0x') \
                    and len(i.bytes) == 5):
                call_addr = int(i.op_str, 16)
                if call_addr >= top_inst_addr and call_addr <= bot_inst_addr:
                    #print(hex(i.address), i.size, hex(call_addr))
                    func_addr.append(call_addr)
                    call_map.append([ \
                            i.address, i.size, call_addr \
                            ])
        elif t_arch in ['EM_68K']:
            if (i.mnemonic == 'bsr.l' or i.mnemonic == 'bsr.w' or i.mnemonic == 'bsr.s') \
                    and i.op_str.startswith('$'):
                if i.mnemonic == 'bsr.l':
                    inst_size = 6
                elif i.mnemonic == 'bsr.w':
                    inst_size = 4
                elif i.mnemonic == 'bsr.s':
                    inst_size = 2
                call_map.append([ \
                        i.address, inst_size, int(re.sub(r'^\$', '0x', i.op_str), 16) \
                        ])
        elif t_arch in ['EM_MIPS']: # mips, mipsel, mips64, mips64el
            try:
                if (i.mnemonic == 'lw' \
                        and re.search(r"\(\$gp\)$", i.op_str) != None) \
                        or ( i.mnemonic == 'ld' \
                        and (re.search(r"\(\$gp\)$", i.op_str) != None \
                        or re.search(r"\(\$a.\)$", i.op_str) != None)):
                    ref_got_offset = int( \
                            re.sub('-', '', i.op_str.split(' ')[1]).split('(')[0], \
                            16 \
                            )
                    got_addr_map.append([i.address, i.size, ref_got_offset])
                    #print(hex(i.address), i.size, hex(ref_got_offset), 'a')
                    got_addr_resolve_map.append([ \
                            i.address, i.size, ref_got_offset \
                            ])
            except ValueError:
                continue
            # for inst_addr, inst_size, ref_got_offset in list(map(list, set(map(tuple, got_addr_resolve_map)))):
            #     for got_addr, got_offset, callee_addr in readelf_got_map:
            #         if ref_got_offset == int(got_offset):
            #             if not [inst_addr, inst_size, int(callee_addr, 16)] in call_map:
            #                 #print([hex(inst_addr), inst_size, hex(int(callee_addr, 16))])
            #                 call_map.append([inst_addr, inst_size, int(callee_addr, 16)])
            #                 func_addr.append(callee_addr)
        elif t_arch in ['EM_PPC', 'EM_PPC64']: # powerpc, powerpc64
            #print(i)
            if i.mnemonic == 'bl': # or i.mnemonic == 'b':
                call_addr = int(i.op_str, 16)
                if call_addr >= top_inst_addr and call_addr <= bot_inst_addr:
                    func_addr.append(call_addr)
                    #print(hex(i.address), i.size, hex(call_addr))
                    call_map.append([i.address, i.size, call_addr])
        elif t_arch in ['EM_RISCV']: # risc-v-32, risc-v-64
            if i.mnemonic == 'jal':# or i.mnemonic == 'j':
                if i.op_str.startswith('0x'):
                    call_addr = addr + int(i.op_str, 16)
                    if call_addr >= top_inst_addr and call_addr <= bot_inst_addr:
                        func_addr.append(call_addr)
        elif t_arch in ['EM_ARC_COMPACT']:
            i_mnemonic = i['inst'].split(' ')[0]
            if i_mnemonic in ['b', 'b.d', 'bl', 'bl.d', 'breq', 'beq.d'] and '+0x' not in i['inst']:
                size = int(len("".join(i['bytecode']))/2)
                call_addr = int(i['inst'].split(';')[1].split(' ')[0], 16)
                func_addr.append(call_addr)
                call_map.append([addr, size, call_addr])
                #print(hex(addr), size, i['inst'], hex(call_addr))
        elif t_arch in ['EM_SH']:
            # SH has no call-with-immediate; function pointers reach the
            # code through `mov.l @(disp,pc),Rn` literal-pool loads. GNU
            # objdump annotated those with the dereferenced pointer value.
            # Capstone resolves the operand to the literal-pool slot
            # address instead, so read the 4-byte pointer from that slot.
            if i.mnemonic == 'mov.l':
                slot = re.match(r'^(0x[0-9a-fA-F]+),', i.op_str)
                if slot:
                    target.seek(int(slot.group(1), 16))
                    raw = target.read(4)
                    if len(raw) == 4:
                        call_addr = int.from_bytes(raw, t_endian)
                        func_addr.append(call_addr)
                        call_map.append([i.address, i.size, call_addr])
                        #print(hex(i.address), i.size, i.mnemonic, hex(call_addr))
        else:
            print("[disasm/capstone] Not support arch : %s " % t_arch, file = sys.stderr)
            exit(-1)

    if t_arch in ['EM_MIPS']: # mips, mipsel, mips64, mips64el
        for inst_addr, inst_size, ref_got_offset in list(map(list, set(map(tuple, got_addr_resolve_map)))):
            for got_addr, got_offset, callee_addr in readelf_got_map:
                if ref_got_offset == int(got_offset):
                    if not [inst_addr, inst_size, int(callee_addr, 16)] in call_map:
                        #print([hex(inst_addr), inst_size, hex(int(callee_addr, 16))])
                        call_map.append([inst_addr, inst_size, int(callee_addr, 16)])
                        func_addr.append(callee_addr)
        # fmt call instruction address
        for _idx in range(len(call_map)):
            call_map[_idx][0] += base_vaddr
    elif t_arch in ['EM_SH']:
        None
    else:
        for _idx in range(len(call_map)):
            # fmt call instruction address
            call_map[_idx][0] += base_vaddr
            call_map[_idx][2] += base_vaddr
    return call_map


def get_func_addr(target, base_vaddr):
    # get information about the architecture
    t_arch, t_bit, t_endian = get_bin_arch(target)
    #print(t_arch, t_bit, t_endian)
    # get instruction area
    top_inst_addr, bot_inst_addr = get_inst_area(target, base_vaddr, t_bit)
    #print('->', hex(top_inst_addr), hex(bot_inst_addr))
    # # get instruction
    if t_arch not in ['EM_ARC_COMPACT']:
        target_inst = capstone_disasm_bin (target, t_arch, t_bit, t_endian, top_inst_addr, bot_inst_addr)
    else:
        target_inst = objdump_disasm_bin(target, t_arch, t_bit, t_endian, top_inst_addr, bot_inst_addr)
    #exit(-1)
    # get function address
    call_map = parse_inst(target, target_inst, base_vaddr, t_arch, t_bit, t_endian, top_inst_addr, bot_inst_addr)
    #print('---')
    #for cm1, cm2, cm3 in sorted(call_map):
    #    print(hex(cm1), cm2, hex(cm3))
    #exit(-1)
    return call_map, top_inst_addr, bot_inst_addr
