#! /usr/bin/env python3

import glob
import re
import sys
import os
import struct
import yara_x
import argparse
import json
import hashlib
import subprocess
import shutil
from pathlib import Path

from capstone import *
from elftools.elf.elffile import ELFFile
from elftools.common import exceptions

from . import dub_maker as DubMaker

# Anchor at the repository root (the parent of the stelftools/ package
# directory). Resolves through any symlinks so plugins set up by the
# host tool (IDA/Ghidra) still find the signatures tree.
STELFTOOLS_PATH = str(Path(__file__).resolve().parent.parent) + "/"

INIT_CRT_FUNC_LIST = ['__init', '_init', '.init', \
        '_start', '_start_c', '__start', 'hlt', '__gmon_start__', 'set_fast_math', \
        'deregister_tm_clones', 'register_tm_clones', '__do_global_dtors_aux', 'frame_dummy', \
        'call___do_global_dtors_aux', 'call_frame_dummy']
FINI_CRT_FUNC_LIST = ['__fini', '_fini', '.fini', \
        '__do_global_ctors_aux', '__get_pc_thunk_bx', 'call___do_global_ctors_aux']
skip_libc_func = ['abort', '_dl_start', 'fini', '_start', 'exit'] + INIT_CRT_FUNC_LIST
_CRT_INIT_LIST = ['__init', '_init', '.init']
_CRT_FINI_LIST = ['__fini', '_fini', '.fini']
TOP_LIBC_FUNC_LIST = set(['puts', 'fcntl', 'fcntl64', 'close', 'fork', 'vfork', \
        'getppid', 'open', 'time', 'closedir', 'opendir', 'readdir', '__fcntl_nocancel', \
        '__close_nocancel', 'sysconf', 'prctl', 'syscall', 'pipe', '__init_libc', \
        '__libc_start_init', 'libc_start_init', 'dummy', 'dummy1', '__aeabi_uidiv', \
        '__aeabi_uidivmod', '__divsi3', '__aeabi_idivmod', '__div0', 'memset', \
        'generic_start_main', '__libc_start_main', 'check_one_fd', '__libc_check_standard_fds', \
        '__libc_setup_tls', '__tls_get_addr', '__libc_csu_init', '__libc_csu_fini'])

GLIBC_BOT_LIBC_FUNC_LIST = ['free_mem']
MAX_PATTERN_LENGTH = 15000

def get_top_addr(functions, skip_libc_func):
    top_addr = 0
    for _addr in sorted(functions.keys()):
        if len(set(functions[_addr]['names']) & set(INIT_CRT_FUNC_LIST)) == 0 \
                and len(set(functions[_addr]['names']) & set(skip_libc_func)) == 0 \
                and len(set(functions[_addr]['names']) & set(TOP_LIBC_FUNC_LIST)) >= 1 \
                and functions[_addr]['size'] >= 10:
            top_addr = _addr
            break
    return top_addr
def get_bot_addr(functions):
    bot_addr = 0
    for _addr in list(reversed(sorted(functions.keys()))):
        if len(set(functions[_addr]['names']) & set(FINI_CRT_FUNC_LIST)) != 0:
            bot_addr = _addr + functions[_addr]['size']
            break
    if bot_addr == 0:
        for _addr in list(reversed(sorted(functions.keys()))):
            if len(set(functions[_addr]['names']) & set(GLIBC_BOT_LIBC_FUNC_LIST)) != 0:
                bot_addr = _addr + functions[_addr]['size']
                break
    if bot_addr == 0 and len(functions.keys()) != 0:
        bot_addr = sorted(functions.keys())[-1]
    #print(hex(bot_addr))
    return bot_addr
def libc_func_in_crt_area(functions, libc_area_top, skip_libc_func):
    skip_func_addr = []
    for _addr in sorted(functions.keys()):
        if _addr < libc_area_top:
            if len(set(functions[_addr]['names']) & set(skip_libc_func)) == len(set(functions[_addr]['names'])) \
                    or len(set(functions[_addr]['names']) & set(INIT_CRT_FUNC_LIST + FINI_CRT_FUNC_LIST)) == len(set(functions[_addr]['names'])):

                #print(functions[_addr]['names'], hex(_addr), '-', hex(_addr + functions[_addr]['size'] - 1)) # dbg
                skip_func_addr.append(_addr)
    #print(skip_func_addr)
    return skip_func_addr

def calc_libc_to_data_ratio(target_info, libc_area_top, libc_area_bot, skip_func_addr):
    func_num = 0
    target_area = []
    for i in range(target_info['size']):
        target_area.append(0)
    # print(hex(libc_area_top), hex(libc_area_bot))
    for addr in sorted(target_info['functions'].keys()): # pending function area
        if not addr in skip_func_addr:
            if libc_area_top != 0 and addr < libc_area_top:
                continue
            if libc_area_bot != 0 and addr > libc_area_bot:
                continue
            func_num += 1
            f_start = addr
            if not 'max_size' in target_info['functions'][addr].keys():
                f_end = target_info['functions'][addr]['size']+addr-1
            else:
                f_end = target_info['functions'][addr]['max_size']+addr-1
            for i in range(f_start, f_end+1):
                i -= target_info['base_vaddr']
                try:
                    target_area[i] = target_info['functions'][addr]['names']
                except IndexError:
                    continue
            continue
    no_match_area = 0
    #print(hex(libc_area_top - target_info['base_vaddr']), hex(libc_area_bot + 1 - target_info['base_vaddr']))
    for libc_area_hex in target_area[ \
            libc_area_top - target_info['base_vaddr']:libc_area_bot + 1 - target_info['base_vaddr']\
            ]:
        if libc_area_hex == 0:
            no_match_area += 1
    if (libc_area_bot - libc_area_top) == 0:
        return 0.00, [0x0, 0x0]
    bin_to_libc_ratio = 1 - (no_match_area / (libc_area_bot - libc_area_top + 1))
    return bin_to_libc_ratio, target_area

def output(target_info, target_path, output_mode):
    # get libc area top/bot address
    libc_area_top = get_top_addr(target_info['functions'], skip_libc_func)
    libc_area_bot = get_bot_addr(target_info['functions'])
    skip_func_addr = libc_func_in_crt_area(target_info['functions'], libc_area_top, skip_libc_func)
    #print("area :", hex(libc_area_top), '-', hex(libc_area_bot))

    if output_mode in ['no']:
        None
    # default output mode
    elif output_mode in ['compare', 'ida', 'ghidra']:
        match_info = {}
        matched_func_addrs = []
        for addr in sorted(target_info['functions'].keys()):
            #print('dbg :', target_info['functions'][addr])
            # skip
            if not addr in skip_func_addr:
                if libc_area_top != 0 and addr < libc_area_top:
                    continue
                if libc_area_bot != 0 and addr > libc_area_bot:
                    continue
            matched_func_addrs.append(addr)
            if output_mode == 'compare':
                match_func = ','.join([x for x in sorted(target_info['functions'][addr]['names'])])
            elif output_mode in ['ida', 'ghidra']:
                match_func = '_OR_'.join([x for x in sorted(target_info['functions'][addr]['names'])])
            #if len(set(target_info['functions'][addr]['names']) \
            #        & set(INIT_CRT_FUNC_LIST+FINI_CRT_FUNC_LIST)) >= 1:
            #    print(hex(addr), ': crt tp :', match_func, target_info['functions'][addr]['size'])
            if addr >= libc_area_top:
                if target_info['functions'][addr]['names'] != ['']:

                    print(hex(addr) + ':' + match_func)
                    match_info[addr] = {'names' : match_func}
        return match_info
    elif output_mode in ['default']:
        #print(hex(libc_area_top), '-', hex(libc_area_bot))
        matched_func_addrs = []
        for addr in sorted(target_info['functions'].keys()):
            #print('dbg :', target_info['functions'][addr])
            # # skip
            # if not addr in skip_func_addr:
            #     if libc_area_top != 0 and addr < libc_area_top:
            #         print('skip(a) :', target_info['functions'][addr])
            #         continue
            #     if libc_area_bot != 0 and addr > libc_area_bot:
            #         print('skip(b) :', target_info['functions'][addr])
            #         continue
            # if target_info['functions'][addr]['names'] == ['']:
            #     print('skip(c) :', target_info['functions'][addr])
            #     continue
            matched_func_addrs.append(addr)
            match_func = ','.join([x for x in sorted(target_info['functions'][addr]['names'])])
            print(hex(addr), match_func)
    elif output_mode in ['count']:
        print('%s : %d' % ( \
                target_path, \
                len(target_info['functions'].keys())
                ))
    else:
        print("[error] does not support output style : %s" % output_mode)
        exit(-1)

def get_bin_arch(target):
    try:
        e = ELFFile(target)
        arch = e['e_machine']
        if e['e_ident']['EI_CLASS'] == 'ELFCLASS32':
            bit = 32
        elif e['e_ident']['EI_CLASS'] == 'ELFCLASS64':
            bit = 64
        if e['e_ident']['EI_DATA'] == 'ELFDATA2LSB':
            endian = 'little'
        elif e['e_ident']['EI_DATA'] == 'ELFDATA2MSB':
            endian = 'big'
    except exceptions.ELFParseError:
        # pyelftools refuses unusual/packed headers. LIEF tolerates more
        # ELF dialects, so retry there before giving up. LIEF 0.16+
        # uppercased some enum labels (i386 -> I386, ARCH_68K -> M68K)
        # and uses CLASS.ELF32 in place of the older ELF_CLASS.CLASS32,
        # so the comparisons below normalise both forms.
        import lief
        b = lief.parse(target.name)
        if b is None:
            raise
        machine_raw = str(b.header.machine_type).rsplit('.', 1)[-1].upper()
        # capstone-side names live in EM_* form (matching pyelftools).
        # LIEF's ARCH_68K / M68K both map to EM_68K, X86_64 to EM_X86_64.
        arch = 'EM_' + {'ARCH_68K': '68K', 'M68K': '68K'}.get(machine_raw, machine_raw)
        cls = str(b.header.identity_class).rsplit('.', 1)[-1].upper()
        bit = 32 if cls in ('CLASS32', 'ELF32') else 64
        endian = 'little' \
            if str(b.header.identity_data).rsplit('.', 1)[-1].upper() == 'LSB' \
            else 'big'
    return arch, bit, endian

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
    objdump_res = subprocess.run([OBJDUMP_PATH, '-d', target_path], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for d_line in objdump_res.stdout.split('\n'):
        # del blank line
        if d_line == '':
            continue
        if re.search("^[ ]+[0-9a-fA-F]+", d_line) == None:
            continue
        _addr = int(re.sub('[\s+|:]', '', d_line.split('\t')[0]), 16)
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
                        i.address, inst_size, int(re.sub('^\$', '0x', i.op_str), 16) \
                        ])
        elif t_arch in ['EM_MIPS']: # mips, mipsel, mips64, mips64el
            try:
                if (i.mnemonic == 'lw' \
                        and re.search("\(\$gp\)$", i.op_str) != None) \
                        or ( i.mnemonic == 'ld' \
                        and (re.search("\(\$gp\)$", i.op_str) != None \
                        or re.search("\(\$a.\)$", i.op_str) != None)):
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

def get_symtab_info_by_capstone(target):
    symtab_info = []
    offset = 0
    size = 0
    vaddr = 0
    PH_EXEC = 0x1
    PH_WRITE = 0x2
    PH_READ = 0x4
    with open(target, 'rb') as f:
        e = ELFFile(f)
        for s in e.iter_segments():
            if s.header['p_type'] != 'PT_LOAD':
                continue
            # exclude other section
            if s.header['p_flags'] & PH_EXEC == 0 or s.header['p_flags'] & PH_READ == 0:
                continue
            offset = s.header['p_offset']
            size   = s.header['p_filesz']
            vaddr  = s.header['p_vaddr']
            symtab_info.append((offset, offset + size, vaddr - offset))
    return symtab_info

def get_symtab_info_by_reaelf(target):
    # LIEF fallback for ELFs that pyelftools cannot parse (corrupted /
    # packed section headers). Iterates PT_LOAD with R+X just like
    # get_symtab_info_by_capstone().
    import lief
    symtab_info = []
    b = lief.parse(target)
    if b is None:
        return symtab_info
    for seg in b.segments:
        # LIEF spells the LOAD type as either SEGMENT_TYPES.LOAD (older)
        # or TYPE.LOAD (newer); compare on the trailing token only.
        if str(seg.type).rsplit('.', 1)[-1].upper() != 'LOAD':
            continue
        flags = int(seg.flags)
        # PF_R = 4, PF_X = 1
        if (flags & 0x4) == 0 or (flags & 0x1) == 0:
            continue
        offset = seg.file_offset
        size = seg.physical_size
        vaddr = seg.virtual_address
        symtab_info.append((offset, offset + size, vaddr - offset))
    return symtab_info

def _mips_got_map(target_path):
    # Reproduce `llvm-readelf -A` Local-entries table directly from .got
    # and .reginfo, so MIPS GOT resolution does not need an external
    # toolchain. Returns the same shape func_ident expects:
    # [(got_addr_hex, abs_gp_offset_decimal_str, callee_addr_hex), ...].
    #
    # The section-header path runs when .got and .reginfo are present.
    # Section-header-stripped firmware ELFs carry the same data in the
    # PT_DYNAMIC and PT_MIPS_REGINFO segments, so a program-header
    # fallback derives the GOT bounds and GP value from there.
    with open(target_path, 'rb') as fp:
        e = ELFFile(fp)
        endian = '<' if e['e_ident']['EI_DATA'] == 'ELFDATA2LSB' else '>'
        word = 4 if e['e_ident']['EI_CLASS'] == 'ELFCLASS32' else 8
        got = e.get_section_by_name('.got')
        reginfo = e.get_section_by_name('.reginfo')
        if got is not None and reginfo is not None:
            return _mips_got_map_from_data(
                endian, word, got['sh_addr'], got.data(), reginfo.data())
    return _mips_got_map_from_segments(target_path, endian, word)

def _mips_got_map_from_data(endian, word, got_base, got_data, reginfo_data):
    # Build the GOT map from the raw GOT bytes and the MIPS_REGINFO
    # blob. Shared by the section-header path and the program-header
    # fallback, which differ only in how they locate these two blobs.
    got_map = []
    word_fmt = endian + ('I' if word == 4 else 'Q')
    # MIPS_REGINFO: ri_gprmask(4) + ri_cprmask[4]*4 + ri_gp_value(4|8)
    if len(reginfo_data) >= 24 and word == 4:
        gp_value = struct.unpack(endian + 'I 4I I', reginfo_data[:24])[5]
    elif len(reginfo_data) >= 40 and word == 8:
        gp_value = struct.unpack(endian + 'I 4I Q', reginfo_data[:32])[5]
    else:
        return got_map
    for i in range(len(got_data) // word):
        got_entry_addr = got_base + i * word
        callee = struct.unpack_from(word_fmt, got_data, i * word)[0]
        gp_offset_abs = abs(gp_value - got_entry_addr)
        got_map.append([
            '%08x' % got_entry_addr,
            str(gp_offset_abs),
            '%08x' % callee,
        ])
    return got_map

def _mips_got_map_from_segments(target_path, endian, word):
    # Program-header fallback for section-header-stripped MIPS ELFs.
    # DT_PLTGOT gives the GOT base; the GOT entry count is the MIPS ABI
    # formula DT_MIPS_LOCAL_GOTNO + (DT_MIPS_SYMTABNO - DT_MIPS_GOTSYM).
    # GP comes from the PT_MIPS_REGINFO segment.
    with open(target_path, 'rb') as fp:
        e = ELFFile(fp)
        # Virtual-address-to-file-offset map over the PT_LOAD segments.
        loads = []
        reginfo_data = b''
        dynamic = None
        for s in e.iter_segments():
            ptype = s.header['p_type']
            if ptype == 'PT_LOAD':
                loads.append((s.header['p_vaddr'],
                              s.header['p_offset'],
                              s.header['p_filesz']))
            elif ptype in ('PT_MIPS_REGINFO', 0x70000000):
                reginfo_data = s.data()
            elif ptype == 'PT_DYNAMIC':
                dynamic = s
        if not reginfo_data or not loads or dynamic is None:
            return []

        def vaddr_to_offset(va):
            for vaddr, off, filesz in loads:
                if vaddr <= va < vaddr + filesz:
                    return off + (va - vaddr)
            return None

        dyn = {}
        for tag in dynamic.iter_tags():
            dyn[tag.entry.d_tag] = tag.entry.d_val
        got_base = dyn.get('DT_PLTGOT')
        local_gotno = dyn.get('DT_MIPS_LOCAL_GOTNO')
        symtabno = dyn.get('DT_MIPS_SYMTABNO')
        gotsym = dyn.get('DT_MIPS_GOTSYM')
        if None in (got_base, local_gotno, symtabno, gotsym):
            return []
        got_entries = local_gotno + (symtabno - gotsym)
        got_off = vaddr_to_offset(got_base)
        if got_off is None:
            return []
        fp.seek(got_off)
        got_data = fp.read(got_entries * word)
    return _mips_got_map_from_data(
        endian, word, got_base, got_data, reginfo_data)

def format_match_res(match_res, symtab_info, risc_v_flag):
    # match_res: iterable of yara_x.Rule (ScanResults.matching_rules).
    # The yara-x API replaces yara-python's m.strings[*].instances[*]
    # with rule.patterns[*].matches[*], and m.meta (dict) with
    # rule.metadata (tuple of (name, value) pairs).
    functions = {}
    for m in match_res:
        meta = dict(m.metadata)
        for pattern in m.patterns:
            for match in pattern.matches:
                addr = match.offset
                # match.length is the real matched span; the historical
                # yara-python code overrode it with meta['size'] whenever
                # max_match_data capped the reported length. Keep the
                # semantic so signature-length-based heuristics downstream
                # (del_mismatch, marge_functions) see the rule's declared
                # function size, not the raw scan return.
                if int(meta['size']) > MAX_PATTERN_LENGTH or risc_v_flag == False:
                    matched_len = int(meta['size'])
                for begin, end, vaddr in symtab_info:
                    if begin <= addr < end or begin == end == 0:
                        addr += vaddr
                        # fix risc-v relaxation size
                        if 'hex_only_num' in meta and (matched_len % 4) != 0:
                            matched_len = (matched_len // 4) * 4
                        if addr in functions:
                            # exclude risc-v mismatch many relaxation function
                            if 'hex_only_num' in meta:
                                if matched_len > int(meta['hex_only_num']):
                                    continue
                            if functions[addr]['size'] < matched_len: # overwrite big func info
                                functions[addr]['names'] = [x for x in meta['aliases'].split(', ')]
                                functions[addr]['size'] = matched_len
                                functions[addr]['detected'] = True
                            elif functions[addr]['size'] == matched_len:
                                functions[addr]['names'].extend([x for x in meta['aliases'].split(', ')])
                        else:
                            functions[addr] = { \
                                    'names': [x for x in meta['aliases'].split(', ')], \
                                    'size' : matched_len, \
                                    'detected' : True, \
                                    'category' : 'library function'
                                    }
    return functions

def yara_matching(rules, target):
    data = _get_target_data(target)
    scanner = yara_x.Scanner(rules)
    return scanner.scan(data).matching_rules

def _get_target_data(f):
    f.seek(0)
    return f.read()

def get_target_fp(target_path):
    if not os.path.exists(target_path):
        print('%s : No such target file' % (target_path), file=sys.stderr)
        exit(-1)
    target = open(target_path, 'rb')
    return target

#def marge_nomatch_functions(_functions, call_map, base_vaddr):
def marge_nomatch_functions(_functions, call_map):
    # add addresses to the dict that do not have a pattern match from the function being called
    _exclude_addr_list = []
    for _, _, _c_addr in call_map:
        #call_addr = _c_addr + base_vaddr
        call_addr = _c_addr# + base_vaddr
        if not call_addr in _functions.keys():
            #_functions[call_addr] = {}
            _functions[call_addr] = { \
                    'names': [''], \
                    'size' : 0, \
                    'detected' : True, \
                    'category' : 'unmatch'
                    }
    _func_addr_list = sorted(_functions.keys())
    for _idx, _addr in enumerate(_func_addr_list):
        if _functions[_addr] == {} and _idx != 0:
            _prev_addr = _func_addr_list[_idx-1]
            try:
                if _addr < _prev_addr + _functions[_prev_addr]['size']:
                    _exclude_addr_list.append(_addr)
            except KeyError:
                continue
    # exclude address other than the first address of the function
    for _exclude_addr in _exclude_addr_list:
        del _functions[_exclude_addr]
    return _functions

def marge_functions(functions, _functions):
    _func_addr_list = sorted(functions.keys())
    for _addr in _func_addr_list:
        if functions[_addr]['names'] != ['']:
            continue
        if _addr in _functions.keys():
            functions[_addr] = _functions[_addr]
    return functions

# Todo : fix the hardcode point
def get_yara_rule(yara_rule_path, r_type, r_length):
#def get_yara_rule(yara_rule_path, rule_length, start_rule_length):
    risc_v_flag = False

    use_rule_list = []
    all_rule_line = []
    with open(yara_rule_path, 'r') as yfp:
        for rule_line in yfp:
            rule_line_fmt = rule_line.replace('\n', '')
            all_rule_line.append(rule_line_fmt)
    rule_version = all_rule_line[0].split(' ')[4]
    if rule_version == '0.2.0_2021_07_29':
        for line_index, yara_rule_line in enumerate(all_rule_line):
            if yara_rule_line.startswith('rule'):
                y_pattern = str(all_rule_line[line_index+7].strip('\t').strip('$pattern = {').strip(' }'))
                # get yara rule real length
                fmt_y_pattern = re.sub('(?<=\().*?(?=\))', 'XX', y_pattern).split(' ')
                y_pattern_length = len(fmt_y_pattern) - fmt_y_pattern.count('??') # pattern len - wildcard len
                # get yara rule type
                fmt_r_type = str(all_rule_line[line_index+3].strip('\t').replace('type = \"', '').replace('\"', ''))
                r_func_list = sorted(all_rule_line[line_index+2].strip('\t').split('\"')[1].split(' '))
                #print(r_func_list)
                if fmt_r_type == r_type and y_pattern_length >= r_length \
                        or len(set(_CRT_INIT_LIST + _CRT_FINI_LIST) & set(r_func_list)) > 0:
                    for index in range(11):
                        use_rule_list.append(all_rule_line[line_index+index])
    else: # default yara format
        use_rule_list = all_rule_line
    rule_str = '\n'.join(use_rule_list)
    use_rule_list = yara_x.compile(rule_str)
    return use_rule_list, risc_v_flag


def _parse_rule_lengths(yara_rule_path):
    # Build {rule_identifier: y_pattern_length} by parsing the .yara
    # source once. CRT init/fini rules get a sentinel length large
    # enough that any L >= 1 keeps them, matching the historical
    # `or len(set(_CRT_*) & set(r_func_list)) > 0` clause in
    # get_yara_rule(). Used by run_one() to filter a single compiled
    # rule set per length bucket without re-parsing/recompiling.
    lengths = {}
    with open(yara_rule_path, 'r') as fp:
        lines = [line.rstrip('\n') for line in fp]
    if not lines:
        return lengths
    head = lines[0].split(' ')
    rule_version = head[4] if len(head) > 4 else ''
    if rule_version != '0.2.0_2021_07_29':
        return lengths  # legacy yara format: no per-rule metadata to parse
    crt_set = set(_CRT_INIT_LIST + _CRT_FINI_LIST)
    for i, line in enumerate(lines):
        if not line.startswith('rule '):
            continue
        name = line.split(' ')[1].rstrip('{').strip()
        pattern = lines[i + 7].strip('\t').strip('$pattern = {').strip(' }')
        fmt = re.sub(r'(?<=\().*?(?=\))', 'XX', pattern).split(' ')
        y_pattern_length = len(fmt) - fmt.count('??')
        r_funcs = set(lines[i + 2].strip('\t').split('"')[1].split(' '))
        if r_funcs & crt_set:
            y_pattern_length = 10**9  # always keep CRT init/fini rules
        lengths[name] = y_pattern_length
    return lengths


CACHE_DIR = STELFTOOLS_PATH + ".cache/yara/"


def compile_yara_file(yara_rule_path):
    # Compile the entire .yara file once and return
    # (rules, {rule_identifier: y_pattern_length}). Callers replicate
    # the historical multi-pass behaviour by filtering matching rules
    # whose identifier has length >= L per merge iteration, avoiding
    # the per-L recompile that the loop in run_one used to do.
    #
    # Compiled rules are persisted under STELFTOOLS_PATH/.cache/yara/ as
    # <basename>.yarc + <basename>.lengths.json. A warm hit deserialises
    # ~8x faster than recompiling, which is the dominant per-cfg cost
    # in the bruteforce driver. Cache invalidates when the .yara file
    # is newer than the cached pair.
    name = os.path.basename(yara_rule_path)
    cache_yarc = os.path.join(CACHE_DIR, name + ".yarc")
    cache_lens = os.path.join(CACHE_DIR, name + ".lengths.json")
    try:
        yara_mtime = os.path.getmtime(yara_rule_path)
        if os.path.getmtime(cache_yarc) >= yara_mtime \
                and os.path.getmtime(cache_lens) >= yara_mtime:
            with open(cache_yarc, 'rb') as fp:
                rules = yara_x.Rules.deserialize_from(fp)
            with open(cache_lens, 'r') as fp:
                lengths = json.load(fp)
            return rules, lengths
    except (FileNotFoundError, OSError):
        pass

    with open(yara_rule_path, 'r') as fp:
        src = fp.read()
    rules = yara_x.compile(src)
    lengths = _parse_rule_lengths(yara_rule_path)

    # Write cache. tmp + atomic rename so a SIGINT mid-write does not
    # leave a half-baked .yarc that future runs would deserialise.
    # Parallel workers racing on the same file are safe because every
    # writer writes its own pid-suffixed .tmp before rename. Cache
    # writes are best-effort — a read-only cache dir or full disk just
    # forfeits the warm-up benefit.
    tmp_yarc = cache_yarc + '.tmp.' + str(os.getpid())
    tmp_lens = cache_lens + '.tmp.' + str(os.getpid())
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        with open(tmp_yarc, 'wb') as fp:
            rules.serialize_into(fp)
        with open(tmp_lens, 'w') as fp:
            json.dump(lengths, fp)
        os.replace(tmp_yarc, cache_yarc)
        os.replace(tmp_lens, cache_lens)
    except OSError:
        for path in (tmp_yarc, tmp_lens):
            try:
                os.unlink(path)
            except OSError:
                pass

    return rules, lengths


def compute_target_state(target_path):
    # Compute the target-side state used by run_one_with_state():
    # the executable-segment table, callsite map, instruction bounds,
    # and file size. Cfg-independent — bruteforce drivers compute it
    # once per binary and reuse across every candidate cfg.
    target = get_target_fp(target_path)
    target.read()
    try:
        symtab_info = get_symtab_info_by_capstone(target_path)
    except exceptions.ELFParseError:
        symtab_info = get_symtab_info_by_reaelf(target_path)
    base_vaddr = symtab_info[0][2]
    call_map, top_inst_addr, bot_inst_addr = get_func_addr(target, base_vaddr)
    target_size = int(target.seek(0, os.SEEK_END))
    target.seek(0)
    target_bytes = target.read()
    target.close()
    return {
        'path': target_path,
        'bytes': target_bytes,
        'symtab_info': symtab_info,
        'call_map': call_map,
        'top_inst_addr': top_inst_addr,
        'bot_inst_addr': bot_inst_addr,
        'target_size': target_size,
        'base_vaddr': base_vaddr,
    }

def del_mismatch(functions):
    def del_mismatch_minimal_func(functions):
        _deleted_key = []
        for addr in sorted(set(functions.keys())):
            # exlude delete key
            if addr in _deleted_key:
                continue
            #print(addr, hex(addr), functions[addr])
            for in_offset in range(addr, addr+functions[addr]['size']):
                if in_offset != addr and in_offset in functions.keys():
                    #print('del(mini) :', hex(in_offset), functions[in_offset], '<-', hex(addr), functions[addr])
                    if functions[in_offset]['size'] > functions[addr]['size']:
                        continue
                    del functions[in_offset] # delete mismatch minimal function
                    _deleted_key.append(in_offset)
        return functions

    def del_mismatch_of_userdef_func(functions):
        top_libc_addr = 0
        # get top libc functions addr
        sort_functions_addr = sorted(functions.keys())
        for _idx, addr in enumerate(sort_functions_addr):
            if len(set(functions[addr]['names']) & TOP_LIBC_FUNC_LIST) >= 1 \
                    and functions[addr]['size'] >= 12 and len(functions[addr]['names']) <= 6: # ToDo
                top_libc_addr = addr
                #print(hex(top_libc_addr), functions[top_libc_addr])
                #exit(-1)
                break
        # delete mismatch functions
        for addr in sorted(functions.keys()):
            if len(set(functions[addr]['names']) & set(INIT_CRT_FUNC_LIST)) >= 1:
                #print(hex(addr), functions[addr])
                continue
            if addr == top_libc_addr:
                break
            #print('del(user) :', hex(addr), functions[addr])
            del functions[addr] # delete mismatch minimal function
        return functions

    def del_mismatch_below_crt(functions):
        current_fini_crt_func_name = []
        fin_crt_addr = 0
        fin_fin_crt_func = ['__fini', '_fini', '.fini']
        # case 1
        for addr in sorted(functions.keys()):
            if len(set(functions[addr]['names']) & set(FINI_CRT_FUNC_LIST)) == len(functions[addr]['names']):
                fin_crt_addr = addr
                for _addr in sorted(functions.keys()):
                    if addr < _addr:
                        if len(set(functions[_addr]['names']) & set(FINI_CRT_FUNC_LIST)) > 0:
                            fin_crt_addr = _addr
                        else:
                            break
                break
        if fin_crt_addr != 0:
            for addr in sorted(functions.keys()):
                if addr > fin_crt_addr:
                    if len(set(functions[addr]['names']) & set(FINI_CRT_FUNC_LIST)) == len(functions[addr]['names']) \
                            and len(set(functions[addr]['names']) & set(current_fini_crt_func_name)) != len(functions[addr]['names']):
                                #print(current_fini_crt_func_name)
                                current_fini_crt_func_name += functions[addr]['names']
                                continue
                    #print('del(b_crt) :', hex(addr), functions[addr])
                    del functions[addr]
        # del mismatch fini crt
        fin_fini_crt_func_addr = 0
        for addr in reversed(sorted(functions.keys())):
            if len(set(functions[addr]['names']) & set(fin_fin_crt_func)) == len(functions[addr]['names']):
                fin_fini_crt_func_addr = addr
        if fin_fini_crt_func_addr != 0:
            for addr in reversed(sorted(functions.keys())):
                if addr > fin_fini_crt_func_addr:
                    #print('del(f_crt) :', hex(addr), functions[addr])
                    del functions[addr]
                else:
                    break
        return functions

    def del_mismatch_many_addr(functions):
        _delete_key = []
        func_num = {}
        for addr in functions.keys():
            _link_func_name = ",".join(functions[addr]['names'])
            if _link_func_name == '':
                continue
            if _link_func_name in func_num.keys():
                func_num[_link_func_name] = func_num[_link_func_name] + 1
            else:
                func_num[_link_func_name] = 1
        for _link_func_name in func_num.keys():
            _list_func_name = _link_func_name.split(',')
            # skip glibc 'free_mem' function
            if len(set(_list_func_name) & set(GLIBC_BOT_LIBC_FUNC_LIST)) == len(set(_list_func_name)):
                continue
            duplic_match_num = func_num[_link_func_name] / len(_list_func_name)
            if duplic_match_num > 5:
                #print(_link_func_name, ':', func_num[_link_func_name], duplic_match_num)
                for addr in functions.keys():
                    if functions[addr]['names'] == _list_func_name:# and functions[addr]['size'] <= 12:
                        #print('del', hex(addr), functions[addr])
                        _delete_key.append(addr)
            elif duplic_match_num > 2:
                for addr in functions.keys():
                    if functions[addr]['size'] < 20 and functions[addr]['names'] == _list_func_name:# and functions[addr]['size'] <= 12:
                        #print('del', hex(addr), functions[addr])
                        _delete_key.append(addr)
        # delete key
        for _del_addr in sorted(set(_delete_key)):
            #print('del(many) :', hex(_del_addr), functions[_del_addr])
            del functions[_del_addr]
        return functions

    # delete unmatch address
    for _addr in sorted(functions.keys()):
        if functions[_addr]['category'] == 'unmatch':
            del functions[_addr]

    # delete mismatched patterns outside the libc range
    #functions = del_outside_the_libc_area(functions, top_inst_addr, bot_inst_addr)
    # delete mismatched minimal function
    functions = del_mismatch_minimal_func(functions) # a
    ## delete mismatch of the user define function
    #functions = del_mismatch_of_userdef_func(functions) # b
    ## delete mismatch of the
    #functions = del_mismatch_below_crt(functions) # c
    ## ToDo : Implement a function to delete functions that match more than 10 address and have short patterns.
    #functions = del_mismatch_many_addr(functions)
    return functions

def get_alias_list(alias_list_path):
    alias_list = []
    with open(alias_list_path, 'rt') as al_fp:
        for alias in al_fp.readlines():
            alias_list.append(alias.rstrip('\n').split(','))
    return alias_list

def del_alias(functions, alias_list):
    for _addr in sorted(functions.keys()):
        # skip
        if len(functions[_addr]['names']) == 1:
            continue
        for alias in alias_list:
            compare_list = sorted(set(functions[_addr]['names']) & set(alias))
            no_compare_list = sorted(set(functions[_addr]['names']) - set(alias))
            # phase 1: delete all alias
            if len(compare_list) == len(functions[_addr]['names']):
                #print('alias match 1 :', functions[_addr]['names'], '->', [ min(alias, key=len) ] )
                functions[_addr]['names'] = [min(compare_list, key=len)]
            # phase 2:
            elif len(compare_list) > 1:
                #print('alias match 2 :', functions[_addr]['names'], '->', [ min(alias, key=len) ] + no_compare_list)
                functions[_addr]['names'] = sorted([min(compare_list, key=len)] + no_compare_list)
        #print(hex(_addr), functions[_addr]['names'])
    return functions

def _match_array_index_list(_list, func_name_list):
    index_list= []
    for func_name in func_name_list:
        index_list.extend(_match_array_index(_list, func_name))
    return sorted(set(index_list))
def _match_array_index(_list, func_name):
    return sorted(set([index for index, _func_name in enumerate(_list) if _func_name == func_name]))

def link_order_base_identificate(functions, alias_list, func_link_order_list):
    #SEARCH_DEPTH = 10
    SEARCH_DEPTH = 5
    MAX_AREA_LENGTH = 15
    matched_func_num = 0
    libfunc_addr_list = []
    multi_libfunc_addr_list = []
    matched_func_dict = {}
    for addr, funcs in functions.items():
        #print(addr, funcs)
        libfunc_addr_list.append(addr)
        if funcs['detected'] == True and len(funcs['names']) > 1:
            multi_libfunc_addr_list.append(addr)

    libfunc_addr_list = sorted(libfunc_addr_list)
    multi_libfunc_addr_list = sorted(multi_libfunc_addr_list)

    #print('\n-----------\n')
    for multi_func_addr in multi_libfunc_addr_list:
        match_func_list = []
        #print('---')
        #print('main ->' ,hex(multi_func_addr), functions[multi_func_addr])
        #print(functions[multi_func_addr]['names']) # dbg
        candidate_func_index = libfunc_addr_list.index(multi_func_addr)
        base_top_func_addr = 0
        base_bot_func_addr = 0
        base_top_func_alias_list = []
        base_bot_func_alias_list = []
        for i in range(1, SEARCH_DEPTH+1):
            if base_top_func_addr != 0 and base_bot_func_addr != 0:
                break
            try:
                top_func_addr = libfunc_addr_list[candidate_func_index - i]
                bot_func_addr = libfunc_addr_list[candidate_func_index + i]
            except IndexError:
                continue

            #print(top_func_addr)
            #print(bot_func_addr)
            #print('-')
            if base_top_func_addr == 0:
                if len(functions[top_func_addr]['names']) == 1:
                    _top_alias = []
                    base_top_func_alias_list = []# reinitialized list
                    for alias in alias_list:
                        if functions[top_func_addr]['names'][0] in alias:
                            _top_alias.extend(alias)
                    if len(_top_alias) != 0:
                        base_top_func_alias_list = sorted(set(_top_alias))
                    else:
                        base_top_func_alias_list = [functions[top_func_addr]['names'][0]]
                    #func_link_order_list check
                    exists_flag = False
                    for base_top_func_alias in base_top_func_alias_list:
                        if base_top_func_alias in func_link_order_list:
                            exists_flag = True
                    if exists_flag == True:
                        base_top_func_addr = top_func_addr
                        #print('top:', hex(base_top_func_addr), base_top_func_alias_list)
            if base_bot_func_addr == 0:
                if len(functions[bot_func_addr]['names']) == 1:
                    _bot_alias = []
                    base_bot_func_alias_list = []# reinitialized list
                    for alias in alias_list:
                        if functions[bot_func_addr]['names'][0] in alias:
                            _bot_alias.extend(alias)
                    if len(_bot_alias) != 0:
                        base_bot_func_alias_list = sorted(set(_bot_alias))
                    else:
                        base_bot_func_alias_list = [functions[bot_func_addr]['names'][0]]
                    #func_link_order_list check
                    exists_flag = False
                    for base_bot_func_alias in base_bot_func_alias_list:
                        if base_bot_func_alias in func_link_order_list:
                            exists_flag = True
                    if exists_flag == True:
                        base_bot_func_addr = bot_func_addr
                        #print('bot:', hex(base_bot_func_addr), base_bot_func_alias_list)
            if base_top_func_addr != 0 and base_bot_func_addr != 0:
                top_func_name = functions[base_top_func_addr]['names'][0]
                bot_func_name = functions[base_bot_func_addr]['names'][0]
                #print('if :', top_func_name, bot_func_name, base_top_func_alias_list, base_bot_func_alias_list)
                link_order_top_func_index_list = \
                        _match_array_index_list(func_link_order_list, base_top_func_alias_list)
                link_order_bot_func_index_list = \
                        _match_array_index_list(func_link_order_list, base_bot_func_alias_list)
                #exit(-1)
                # check index
                if len(link_order_top_func_index_list) ==  len(link_order_bot_func_index_list) == 0:
                    continue
                for link_order_top_func_index in link_order_top_func_index_list:
                    for link_order_bot_func_index in link_order_bot_func_index_list:
                        hit_index_area_length = link_order_bot_func_index - link_order_top_func_index
                        # if 0 < hit_index_area_length <= MAX_AREA_LENGTH
                        if hit_index_area_length > 0 and hit_index_area_length <= MAX_AREA_LENGTH:
                            match_func_list += sorted(set(functions[multi_func_addr]['names']) & \
                                    set(func_link_order_list[link_order_top_func_index+1:link_order_bot_func_index]))


        if len(match_func_list) > 0 and len(functions[multi_func_addr]['names']) > len(match_func_list):
            #print('-')
            #print(func_link_order_list[link_order_top_func_index])
            # print('[matched : func link order] : 0x%x : %s -> %s ' % \
            #         (multi_func_addr, functions[multi_func_addr]['names'], match_func_list) \
            #         ) # dbg
            #print(func_link_order_list[link_order_bot_func_index])
            #functions[multi_func_addr]['names'] = match_func_list
            if multi_func_addr in matched_func_dict.keys():
                matched_func_dict[multi_func_addr] =  matched_func_dict[multi_func_addr] + match_func_list
            else:
                matched_func_dict[multi_func_addr] = match_func_list

    for addr, match_func_list in matched_func_dict.items():
        if len(functions[addr]['names']) > len(match_func_list):
            #print('matched! %s : %s -> %s ' % (hex(addr), functions[addr]['names'], match_func_list))
            functions[addr]['names'] = match_func_list
        matched_func_num = matched_func_num + 1
    #exit(-1)
    return functions, matched_func_num

def id_func_name_for_linkorder(functions, target_path, toolchain_path, alias_list, call_map, id_l_count, exclude_func_list):
    def get_func_list(functions, call_map):
        check_link_order_func_list = []
        libfunc_callee_addr_list = [] # library function call function address list
        userfunc_callee_addr_list = [] # library function call function address list
        func_addr_list = []
        for addr in functions.keys():
            func_addr_list.append(addr)
        func_addr_list = sorted(set(func_addr_list))
        # set first library function address
        for f_addr in func_addr_list:
            if len(TOP_LIBC_FUNC_LIST) == 0:
                if len(functions[f_addr]['names']) > 0 and functions[f_addr]['detected'] == True \
                        and len(set(functions[f_addr]['names']) & set(INITIAL_CRT_FUNCTIONS)) == 0 : # case of HEUL     ISTIC_FIRST_FUNCTION is empty
                    entry_libfunc_addr = f_addr
                    break
            elif len(set(functions[f_addr]['names']) & set(TOP_LIBC_FUNC_LIST)) > 0: # if the address of a l     ibrary function
                entry_libfunc_addr = f_addr
                break
            else:
                entry_libfunc_addr = 0
        # format call map
        fmt_call_map = []
        for call_map_index, _ in enumerate(call_map):
            fmt_call_map.append([call_map[call_map_index][0], call_map[call_map_index][2]])
        # get library function call library function address
        for call_inst_addr, callee_addr in fmt_call_map:
            #print(hex(call_inst_addr), hex(callee_addr))
            try:
                if entry_libfunc_addr <= call_inst_addr and functions[callee_addr]['detected'] == True:
                    #print(functions[callee_addr]['names'])
                    libfunc_callee_addr_list.append(callee_addr)
            except KeyError:
                continue
        # get user define function call library function address
        for call_inst_addr, callee_addr in fmt_call_map:
            try:
                if entry_libfunc_addr > call_inst_addr and functions[callee_addr]['detected'] == True:
                    #print(hex(call_inst_addr), '-', hex(callee_addr), ':', functions[callee_addr]['names'])
                    userfunc_callee_addr_list.append(callee_addr)
            except KeyError:
                continue
        # get not call library function address
        not_call_func_addr_list = \
                sorted(set(func_addr_list) - set(libfunc_callee_addr_list+userfunc_callee_addr_list))
        # check link order function address
        check_link_order_func_addr_list = sorted(set(userfunc_callee_addr_list + not_call_func_addr_list))
        # create check link order function list
        for check_link_order_func_addr in userfunc_callee_addr_list:
            for func in functions[check_link_order_func_addr]['names']:
                check_link_order_func_list.append(func)
        # all function
        all_func_list = []
        for addr in sorted(functions.keys()):
            for func in functions[addr]['names']:
                all_func_list.append(func)
        return check_link_order_func_list, all_func_list


    #func_list = sorted(sum( [v['names'] for v in functions.values()], []))
    use_func_list, all_func_list = get_func_list(functions, call_map)
    #print(len(use_func_list), len(all_func_list))
    #exit(-1)
    id_l_num = 0
    #print(func_list, toolchain_path, target_path.split('/')[-1])
    # link order path
    link_order_list_path = \
            STELFTOOLS_PATH + '.cache/runtime/link_order_list/' \
            + target_path.split('/')[-1] + '_'  + str(id_l_count) + '.olist'
    # global link order path
    global_link_order_list_path = \
            STELFTOOLS_PATH + '.cache/runtime/link_order_list/' \
            + target_path.split('/')[-1] + '_'  + str(id_l_count) + 'g.olist'
    # global link order path
    all_link_order_list_path = \
            STELFTOOLS_PATH + '.cache/runtime/link_order_list/' \
            + target_path.split('/')[-1] + '_'  + str(id_l_count) + 'all.olist'
    # get real link order list
    check_func_list = sorted(set(use_func_list) - set(exclude_func_list))
    dummy_bin_name = target_path.split('/')[-1] + '.' + str(id_l_count)
    func_link_order_list, global_func_link_order_list, _exclude_func_list \
            = DubMaker.get_order_list(check_func_list, toolchain_path, dummy_bin_name)
    exclude_func_list += _exclude_func_list
    # save link order list
    with open(link_order_list_path, 'wt') as f:
        for func_link_order in func_link_order_list:
            f.write("%s\n" % func_link_order)
    # check
    while True:
        functions, mf_num = link_order_base_identificate(functions, alias_list, func_link_order_list)
        if mf_num == 0:
            break
        else:
            id_l_num += 1

    #print(len(exclude_func_list))
    # check only first
    if id_l_count == 0:
        while True:
            functions, mf_num = link_order_base_identificate(functions, alias_list, global_func_link_order_list)
            if mf_num == 0:
                break
        #aa
        check_all_func_list = sorted(set(all_func_list) - set(exclude_func_list))
        func_link_order_list, _, _ \
                = DubMaker.get_order_list(check_all_func_list, toolchain_path, dummy_bin_name)
        while True:
            functions, mf_num = link_order_base_identificate(functions, alias_list, func_link_order_list)
            if mf_num == 0:
                break
    return functions, id_l_num, func_link_order_list

def get_func_name_list_alias_list(multi_func_name_list, alias_list):
    func_name_alias_list = []
    for multi_func_name in multi_func_name_list:
        for alias in alias_list:
            if multi_func_name in alias:
                func_name_alias_list.extend(alias)
    if func_name_alias_list == []:
        func_name_alias_list = multi_func_name_list
    return sorted(set(func_name_alias_list))

_DEPEND_CACHE = {}  # depend_path -> (depend_data, caller_alias_index)


def _load_depend(d_list_path):
    # Parse the .dlist file once per path and cache the rows plus a
    # caller-alias -> rows index. The original loop scanned 174K rows
    # per (function, call_site) pair on a glibc cfg, dominating wall
    # time on busybox-class targets. The index turns the inner scan
    # into an O(1) dictionary hit keyed on the caller's resolved
    # symbol name. Cached at module scope so repeated
    # id_func_name_for_depend() invocations within run_one_with_state's
    # convergence loop reuse the same parsed structure.
    cached = _DEPEND_CACHE.get(d_list_path)
    if cached is not None:
        return cached
    depend_data = []
    caller_alias_index = {}
    try:
        with open(d_list_path, 'r') as d_list:
            for d in d_list:
                d = d.strip().split(' ')
                if len(d) < 3:
                    continue
                alias = d[0].split(',')
                d[0] = alias
                try:
                    offset_int = int(d[2])
                except ValueError:
                    continue
                # (caller_alias_list, callee_name, offset_int)
                row = (alias, d[1], offset_int)
                depend_data.append(row)
                for name in alias:
                    caller_alias_index.setdefault(name, []).append(row)
    except FileNotFoundError:
        print('Dependency file not found : %s' % d_list_path, file=sys.stderr)
        exit(1)
    cached = (depend_data, caller_alias_index)
    _DEPEND_CACHE[d_list_path] = cached
    return cached


def id_func_name_for_depend(functions, call_map, depend_path, alias_list):
    depend_data, caller_alias_index = _load_depend(depend_path)

    def caller_base_name_filter(functions, call_map):
        # For each function with a unique resolved name, look up the
        # short list of dependency rows whose caller alias contains
        # that name (O(1) index hit), then verify the call site offset
        # falls within the call instruction. Replaces the historical
        # O(functions x call_map x depend_data) scan with
        # O(functions x call_map x avg_rows_per_name).
        matched_func_num = 0
        for key, value in functions.items():
            if not (value['detected'] and len(value['names']) == 1):
                continue
            single_name = value['names'][0]
            candidates = caller_alias_index.get(single_name)
            if not candidates:
                continue
            func_end = key + functions[key]['size']
            for opecode_addr, inst_size, operand_callee_addr in call_map:
                if not (key <= opecode_addr <= func_end):
                    continue
                callee_entry = functions.get(operand_callee_addr)
                if callee_entry is None:
                    continue
                functions_callee = callee_entry['names']
                if len(functions_callee) <= 1:
                    continue
                call_offset_start = opecode_addr - key
                call_offset_end = call_offset_start + inst_size
                # Mirror the original behaviour: if multiple depend rows
                # match this call site, every match applies (last-wins
                # rename), and matched_func_num counts every match. The
                # iteration is bounded by candidates (=index hit list),
                # so the cost is small even without an early break.
                functions_callee_aliases = None
                for caller_alias, callee, offset_int in candidates:
                    if not (call_offset_start <= offset_int < call_offset_end):
                        continue
                    if functions_callee_aliases is None:
                        functions_callee_aliases = \
                            get_func_name_list_alias_list(
                                functions_callee, alias_list)
                    if callee in functions_callee_aliases:
                        functions[operand_callee_addr]['names'] = [callee]
                        matched_func_num += 1
        return functions, matched_func_num

    def callee_base_name_filter(functions, call_map):
        matched_func_num = 0
        # get multi funcname address
        multi_funcname_addr_list = []
        for f_addr, f_info in functions.items():
            if len(f_info['names']) > 1:
                try:
                    if f_info['size'] >= 0:
                        multi_funcname_addr_list.append(f_addr)
                        # print(hex(f_addr), f_info['names'], f_info['size'])
                except KeyError:
                    continue
        multi_funcname_addr_list = sorted(set(multi_funcname_addr_list))
        for multi_addr in multi_funcname_addr_list:
            # search depend function info
            candidate_func_depend_dict = {}
            for candidate_func in functions[multi_addr]['names']:
                # Index-based lookup replaces the historical scan over
                # the full 174K-row depend_data per candidate function.
                for d_caller_funcs, d_callee_func, d_offset in \
                        caller_alias_index.get(candidate_func, []):
                    if candidate_func in d_caller_funcs:
                        #print('-')
                        #print(','.join(d_caller_funcs), d_callee_func, d_offset)
                        d_caller_alias_str = ','.join(d_caller_funcs)
                        #print(candidate_func, d_caller_funcs, ':', d_callee_func, d_offset)
                        if not d_caller_alias_str in candidate_func_depend_dict:
                            candidate_func_depend_dict[d_caller_alias_str] = { \
                                    'callees' : [[d_callee_func, d_offset]], \
                                    'func_num' : 1 } # initialize
                        elif [d_callee_func, d_offset] not in candidate_func_depend_dict[d_caller_alias_str]['callees']:
                            candidate_func_depend_dict[d_caller_alias_str]['callees'].append([d_callee_func, d_offset])
                            candidate_func_depend_dict[d_caller_alias_str]['func_num'] = \
                                    candidate_func_depend_dict[d_caller_alias_str]['func_num'] + 1
            #print('-----')
            #print(hex(multi_addr), functions[multi_addr])
            matched_func_list = []
            # check call
            for candidate_func in functions[multi_addr]['names']:
                compare_callee_num = 0
                offset_recode_list = [] # ToDo bad fix style
                for inst_addr, inst_size, callee_addr in call_map:
                    if multi_addr <= inst_addr < (multi_addr + int(functions[multi_addr]['size'])):
                        callee_inst_offset = inst_addr - multi_addr
                        for d_caller_alias_str, callee_info in candidate_func_depend_dict.items():
                            if candidate_func in d_caller_alias_str.split(','):
                                #print(hex(int(callee_addr, 16)), \
                                #        hex(multi_addr), hex(multi_addr + int(functions[multi_addr]['size'])))
                                try:
                                    #callee_func = functions[int(callee_addr, 16)]['names']
                                    callee_func = functions[callee_addr]['names']
                                    #print(candidate_func, callee_func)
                                except KeyError: # case of refere object (non function)
                                    continue
                                for callee in callee_info['callees']:
                                    #print(hex(multi_addr), candidate_func, ':', d_caller_alias_str, callee_func, callee)
                                    callee_func_alias_list = get_func_name_list_alias_list([callee[0]], alias_list)
                                    #print('-')
                                    #print(candidate_func, set(callee_func), set(callee_func_alias_list), \
                                    #         len(set(callee_func) & set(callee_func_alias_list)))
                                    #print(len(callee_func), len(callee_func_alias_list))
                                    _callee_func_len = len(callee_func)
                                    #print('co', callee_inst_offset, int(callee[1]), callee_inst_offset+inst_size)
                                    if len(set(callee_func) & set(callee_func_alias_list)) == _callee_func_len \
                                            and callee_inst_offset <= int(callee[1]) < callee_inst_offset+inst_size \
                                            or _callee_func_len == 1 and callee_func[0] == callee[0]:
                                        if not int(callee[1]) in offset_recode_list: # ToDo bad fix style
                                            offset_recode_list.append(int(callee[1]))
                                            compare_callee_num += 1
                                            #print(candidate_func, callee[0], '(', int(callee[1]), ')',  ':', compare_callee_num)
                                #print('cc',compare_callee_num, candidate_func_depend_dict[d_caller_alias_str]['func_num'])
                                if compare_callee_num == candidate_func_depend_dict[d_caller_alias_str]['func_num']:
                                    for matched_func in sorted(set([candidate_func]) & set(d_caller_alias_str.split(','))):
                                        if not matched_func in matched_func_list:
                                            #print('m :', matched_func)
                                            matched_func_list.append(matched_func)
            if len(matched_func_list):
                if len(functions[multi_addr]['names']) > len(matched_func_list):
                    matched_func_num += 1
                    if len(matched_func_list) > 1:
                        for alias in alias_list:
                            if len(matched_func_list) ==  len(set(matched_func_list) & set(alias)):
                                matched_func_list = [min(alias, key=len)]
                    #print('[matched! : callee base] (%s) : %s -> %s' % (hex(multi_addr), functions[multi_addr]['names'], matched_func_list))
                    functions[multi_addr]['names'] = matched_func_list
        return functions, matched_func_num

    id_d_num = 0
    while True:
        functions, r_matched_func_num = caller_base_name_filter(functions, call_map)
        functions, e_matched_func_num = callee_base_name_filter(functions, call_map)
        if e_matched_func_num == r_matched_func_num == 0:
            break
        else:
            id_d_num += 1
    return functions, id_d_num

def multiple_consecutive_candidate_filt(functions, link_order_list, alias_list):
    #for l in link_order_list:
    #    print(l)
    #exit(-1)
    libfunc_addr_list = []
    multi_libfunc_addr_list = []
    for addr, funcs in functions.items():
        if funcs['detected'] == True:
            libfunc_addr_list.append(addr)
            if len(funcs['names']) > 1:
                multi_libfunc_addr_list.append(addr)
    libfunc_addr_list = sorted(libfunc_addr_list)
    multi_libfunc_addr_list = sorted(multi_libfunc_addr_list)

    consective_multi_funcname_addr_dict = {}
    for i in range(len(libfunc_addr_list)):
        if libfunc_addr_list[i] in multi_libfunc_addr_list:
            #print('---')
            s_multi_func_name_addr = libfunc_addr_list[i]
            #print('s', hex(libfunc_addr_list[i]), functions[libfunc_addr_list[i]]['names'])
            s_multi_func_name_alias_list = get_func_name_list_alias_list(functions[libfunc_addr_list[i]]['names'], alias_list)
            #print(s_multi_func_name_alias_list)
            for s_multi_func_name_alias in s_multi_func_name_alias_list:
                s_multi_func_name_alias_index_list = _match_array_index(link_order_list, s_multi_func_name_alias)
                for s_multi_func_name_alias_index in s_multi_func_name_alias_index_list:
                    # check
                    if len(set(functions[s_multi_func_name_addr]['names']) & set([link_order_list[s_multi_func_name_alias_index-1]])) \
                            or len(set(functions[s_multi_func_name_addr]['names']) & set([link_order_list[s_multi_func_name_alias_index-2]])):
                        continue
                    #print('-')
                    next_i = 0
                    consective_addr_list = []
                    while True:
                        if len(libfunc_addr_list) <= i+next_i:
                            break
                        candidate_func_name_list = functions[libfunc_addr_list[i+next_i]]['names']
                        candidate_func_name_alias_list = \
                                get_func_name_list_alias_list(candidate_func_name_list, alias_list)
                        #print(hex(libfunc_addr_list[i+next_i]), candidate_func_name_alias_list, '-', \
                        #        link_order_list[s_multi_func_name_alias_index+next_i], s_multi_func_name_alias_index+next_i)
                        if not link_order_list[s_multi_func_name_alias_index+next_i] in candidate_func_name_alias_list:
                            #print('b', link_order_list[s_multi_func_name_alias_index+next_i])
                            break
                        next_i+=1
                    if next_i >= 3:
                        for count_i in range(next_i):
                            if len(functions[libfunc_addr_list[i+count_i]]['names']) == 1:
                                continue
                            detect_fname = link_order_list[s_multi_func_name_alias_index+count_i]
                            for _alias in alias_list:
                                if detect_fname in _alias:
                                    detect_fname = min(_alias, key=len)
                            #print('[matched : additional func link order] (%s) %s -> %s' % ( \
                            #        hex(libfunc_addr_list[i+count_i]), \
                            #        functions[libfunc_addr_list[i+count_i]]['names'], \
                            #        detect_fname))
                            functions[libfunc_addr_list[i+count_i]]['names'] = [detect_fname]
    return functions


def arch_pattern_length(arch):
    length = 0
    if arch in ['aarch64']:
        length = 9
    elif arch in ['arm', \
            'armv4eb', 'armv4l', 'armv4tl', \
            'armv5-eabi', 'armv5l', \
            'armv6-eabihf', 'armv6l', \
            'armv7-eabihf', 'armv7l', 'armv7m' \
            ]:
        length = 4
    elif arch in ['x86', 'x86-i686', 'i386', 'i486', 'i586', 'i686', 'x86-core2', '80386']:
        length = 4
    elif arch in ['mips', 'mips32', 'mipsel', 'mips32el']:
        length = 9
    elif arch in ['mips64', 'mips64el']:
        length = 9
    elif arch in ['ppc', 'powerpc', 'powerpc-440fp', 'powerpc-e300c3', 'powerpc-e500mc']:
        length = 8
    elif arch in ['ppc64', 'powerpc64', 'powerpc64-e6500', 'powerpc64-pwoer8']:
        length = 16
    elif arch in ['risc-v', 'riscv', 'risc-v-32', 'risc-v-64']:
        length = 9
    elif arch in ['sparc', 'sparc64']:
        length = 9
    elif arch in ['x86_64', 'x86-64', 'x86-64-core-i7']:
        length = 8
    elif arch in ['arc']:
        length = 4
    elif arch in ['sh4']:
        length = 4
    elif arch in ['m68k', 'm68k-q800', 'm68k-mcf', 'm68k-mcf5208', 'm68000']:
        length = 4
    return length

def get_target_list(targets, lm_flag):
    if lm_flag == True:
        with open(targets[0], "rt") as f:
            target_list = f.readlines()
            target_list = [l.replace('\n', '') for l in target_list]
            return target_list
    else:
        return targets

def set_args():
    parser = argparse.ArgumentParser()
    # new
    parser.add_argument('-cfg', help = 'target path')
    parser.add_argument('-target', help = 'target path')
    # old
    parser.add_argument('--yara', help = 'yara rule path')
    parser.add_argument('--arch', help = 'yara rule path')
    #parser.add_argument('--pattern_length', '-pl', default = 8, type = int)
    parser.add_argument('--output_style', '-o', default='default', help = 'output style')
    parser.add_argument('--virtual_addr', '-va', action='store_true', help = 'output virtual address')
    parser.add_argument('--list_mode', '-lm', action='store_true', help = 'list mode')
    parser.add_argument('--alias_list', '-al', help = 'Enable function name identification by function dependency')
    parser.add_argument('--id_linkorder', '-id_l', help = 'Path to toolchain used to indentify function names by function link order')
    parser.add_argument('--id_depend', '-id_d', help = 'Enable function name identification by function dependency')
    args = parser.parse_args()
    return args

def run_one_with_state(target_state, cfg_info, relative_paths=True):
    # Run a single (target, cfg) ident pass using a pre-computed
    # target_state (see compute_target_state()). The historical
    # multi-pass inner loop is collapsed into one yara-x compile + one
    # scan + length-bucket filtering, which gives byte-identical
    # results to the old N-length loop while cutting per-cfg wall time
    # by 2-7x.
    if relative_paths:
        yara_path        = STELFTOOLS_PATH + cfg_info['yara_path']
        alias_list_path  = STELFTOOLS_PATH + cfg_info['alias_list_path']
        depend_list_path = STELFTOOLS_PATH + cfg_info['dependency_list_path']
    else:
        yara_path        = cfg_info['yara_path']
        alias_list_path  = cfg_info.get('alias_list_path') or ''
        depend_list_path = cfg_info.get('dependency_list_path') or ''
    compiler_path    = cfg_info.get('compiler_path') or ''

    alias_flag     = bool(alias_list_path) and os.path.exists(alias_list_path)
    linkorder_flag = bool(compiler_path)   and os.path.exists(compiler_path)
    depend_flag    = bool(depend_list_path) and os.path.exists(depend_list_path)

    start_rule_length = arch_pattern_length(cfg_info['arch'])
    target_path = target_state['path']
    symtab_info = target_state['symtab_info']
    call_map    = target_state['call_map']

    # Single compile + single scan, materialised once for repeated
    # length-bucket iteration below.
    rules, rule_lengths = compile_yara_file(yara_path)
    scanner = yara_x.Scanner(rules)
    all_matches = list(scanner.scan(target_state['bytes']).matching_rules)

    # Replay the historical multi-pass merge over the cached match list
    # by filtering on the rule identifier -> y_pattern_length map.
    # Legacy .yara files (rule_version != '0.2.0_2021_07_29') produce
    # an empty lengths map; for those we fall back to the original
    # behaviour where every iteration sees every rule.
    functions = None
    for L in range(start_rule_length, 0, -1):
        if rule_lengths:
            subset = [r for r in all_matches
                      if rule_lengths.get(r.identifier, 0) >= L]
        else:
            subset = all_matches
        _functions = format_match_res(subset, symtab_info, False)
        if L == start_rule_length:
            functions = marge_nomatch_functions(_functions, call_map)
        else:
            functions = marge_functions(functions, _functions)
    functions = del_mismatch(functions)

    alias_list = get_alias_list(alias_list_path) if alias_flag else []
    functions = del_alias(functions, alias_list)

    id_loop_count = 0
    link_order_list = None
    while True:
        id_l_num = 0
        if linkorder_flag:
            functions, id_l_num, link_order_list = id_func_name_for_linkorder(
                functions, target_path, compiler_path,
                alias_list, call_map, id_loop_count, [],
            )
        id_d_num = 0
        if depend_flag:
            functions, id_d_num = id_func_name_for_depend(
                functions, call_map, depend_list_path, alias_list,
            )
        if id_l_num == id_d_num == 0:
            break
        id_loop_count += 1

    if linkorder_flag and alias_flag:
        functions = multiple_consecutive_candidate_filt(functions, link_order_list, alias_list)

    return {
        'name': target_path,
        'functions': functions,
        'size': target_state['target_size'],
        'base_vaddr': target_state['base_vaddr'],
    }


def run_one(target_path, cfg_info, relative_paths=True):
    # Single-shot convenience wrapper. compute_target_state() does the
    # ELF parse + capstone disassembly + call-map extraction; bruteforce
    # drivers should call those two stages separately so target state
    # is shared across every candidate cfg.
    state = compute_target_state(target_path)
    return run_one_with_state(state, cfg_info, relative_paths=relative_paths)


def main():
    args = set_args()

    if args.cfg and os.path.exists(args.cfg):
        with open(args.cfg) as cfg_fp:
            cfg_info = json.load(cfg_fp)
        target_info = run_one(args.target, cfg_info, relative_paths=True)
    elif args.yara is not None:
        cfg_info = {
            'arch': args.arch,
            'yara_path': args.yara,
            'compiler_path': args.id_linkorder or '',
            'alias_list_path': args.alias_list or '',
            'dependency_list_path': args.id_depend or '',
        }
        target_info = run_one(args.target, cfg_info, relative_paths=False)
    else:
        print("[ERROR] wrong argument")
        exit(-1)

    output(target_info, args.target, args.output_style)

if __name__ == '__main__':
    main()
