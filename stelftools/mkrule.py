#! /usr/bin/env python3
#
# mkrule.py - yara rule generator
#
# Usage: ./mkrule.py archive_files
# - e.g., ./libfunc_mkrule.py /opt/cross-compilter/i586/lib/lib*.a
# - e.g., ./libfunc_mkrule.py $(find /opt/cross-compiler/i586/ -type f -name '*.[a|o]')
#
# Output: patterns.yara
#
# Requirements:
# - pyelftools: ELF file tools
# - capstone: disassembler
# - arpy
# Changes:
# - genptn.py -> mkrule.py -> libfunc_mkrule.py

import os
import sys
import shutil
import arpy
#import ar
from elftools.elf.elffile import ELFFile
from elftools.elf.constants import *
import logging
import hashlib
import magic
import argparse

import cxxfilt

from . import arch as arch_pkg
from .arch import i386 as _arch_i386
from .arch import ppc64 as _arch_ppc64
from .arch import riscv as _arch_riscv

col, row = shutil.get_terminal_size()

# Precomputed byte -> 'XX' lookup so the per-section hex conversion does not
# pay a fresh format-string parse per byte. About 6x faster than the prior
# `['%02X' % x for x in struct.unpack('B'*N, data)]` shape on 1 MB inputs.
_BYTE_TO_HEX = ['%02X' % x for x in range(256)]

# logging.basicConfig(level=logging.DEBUG)
logging.basicConfig(level=logging.WARNING)
# logging.basicConfig(level=logging.INFO)

# Needed for c++ because function names are too long in C++
MAX_RULE_INDENTIFIER_LENGTH = 30
# Needed for c++ because there are too many same opecode functions
#MAX_ALIASES = 50 # TODO: C++ function names may cause too long string errors
MAX_ALIASES = 70 # TODO: C++ function names may cause too long string errors
#VERSION = '0.1.1_2020_04_26'
VERSION = '0.2.0_2021_07_29'
# MINIMUM_PATTERN_LENGTH = 6 # TODO: parameter tuning
MINIMUM_PATTERN_LENGTH = 0
#MAXIMUM_PATTERN_LENGTH = 1000 # 600  # TODO: parameter tuning
MAXIMUM_PATTERN_LENGTH = 15000 # 600  # TODO: risc-v

CRT_INIT_FINI_FUNC_LIST = ['.init', '_init', '__init', '.fini', '_fini', '__fini']

def fetch_opecodes(f, arfile = '', exapis = []):
    global MAXIMUM_PATTERN_LENGTH
    tab = {}
    crt_marge_tab = {}
    if hasattr(f, 'header'):
        fname = f.header.name.decode('utf-8')
    elif hasattr(f, 'name'):
        fname = f.name
    else:
        logging.error('Could not identify the file name')
        exit(-1)
    if len(arfile) > 0:
        arfile = '@' + arfile
    e = ELFFile(f)

    # Materialise the section list once. fetch_opecodes walks it three
    # times (text discovery, relocation processing, PPC64 .opd probe);
    # each iter_sections() call re-instantiates the Section objects, and
    # libc.a had ~80k of those across its 2k object files. The PPC64
    # opd_flag scan further down also runs against this list.
    sections = list(e.iter_sections())

    # Resolved lazily inside the per-relocation-section loop because a
    # binary without relocations should not fail for an unsupported
    # architecture -- the pre-split implementation held the unsupported
    # check inside the per-relocation entry loop, never reached when no
    # relocations were processed.
    handler = None
    ei_data = e['e_ident']['EI_DATA']

    # create hex string based text code
    textsec = {}
    for sec in sections:
        # The original code also walked .rodata.* / .rdata.* sections to
        # collect aliases into a `rodatasec` dict, but that dict was never
        # read by any other code path (write-only). The per-section
        # get_section_by_name('.symtab') + iter_symbols() inside the
        # rodata branch dominated short-archive runtime, so the branch
        # is dropped here. The text-discovery semantics are unchanged.
        if (sec['sh_type'] == 'SHT_PROGBITS' and (sec['sh_flags'] & SH_FLAGS.SHF_EXECINSTR) == SH_FLAGS.SHF_EXECINSTR):
            # if not sec.name.startswith('.text'): continue
            logging.debug('%s: %s' % (fname, sec.name))
            # extract a .text section corresponding to this relocation table
            hexstr = [_BYTE_TO_HEX[b] for b in sec.data()]
            textsec[sec.name] = hexstr

    ## 1. text section : statically functions
    # analyze relocation sections
    relnames = set()
    for tname in textsec.keys():
        relnames.add('.rel' + tname)
        relnames.add('.rela' + tname)
    #print(relnames)

    for sec in sections:
        if not sec['sh_type'] in ['SHT_REL', 'SHT_RELA']:
            continue
        if not sec.name in relnames:
            continue
        logging.debug('%s: %s' % (fname, sec.name))

        # extract a .text section corresponding to this relocation table
        if sec.name.startswith('.rela'):
            name = sec.name[5:]
        elif sec.name.startswith('.rel'):
            name = sec.name[4:]
        else:
            logging.error('Unsupported section name: %s' % sec.name)
            exit(-1)

        # test: RISCV : prefetch reloc info
        # save relocation info
        _reloc_info = {}
        # checked r_offset
        _checked_r_offset = []
        for r in sec.iter_relocations():
            offset = r['r_offset']
            rtype = r['r_info_type']
            if not offset in _reloc_info.keys():
                _reloc_info[offset] = { 'rtype' : [rtype] }
            else:
                _marge_rtype = _reloc_info[offset]['rtype'] + [rtype]
                _reloc_info[offset]['rtype'] = _marge_rtype

        if handler is None:
            try:
                handler = arch_pkg.dispatch(e)
            except arch_pkg.UnsupportedArch:
                logging.warning('Not supported architecture: %s %s' % (e['e_machine'], e['e_ident']['EI_CLASS']))
                exit(-1)

        for r in sec.iter_relocations():
            offset = r['r_offset']
            rtype = r['r_info_type']
            handler.apply_relocation(
                textsec, name, offset, rtype,
                _reloc_info, _checked_r_offset, ei_data, fname,
            )

    #print(textsec)
    #print(textsec.keys())
    for _sym_name in textsec.keys():
        if _sym_name in CRT_INIT_FINI_FUNC_LIST:
            if fname.split('/')[-1] in ['crti.o', 'crtn.o']:
                opecodes_str = ' '.join(textsec[_sym_name])
                t_fname = fname.split('/')[-1]
                if t_fname in crt_marge_tab.keys():
                    crt_marge_tab[t_fname] = crt_marge_tab[t_fname] + [{'name': _sym_name, 'type': 'func', \
                            'size': len(textsec[_sym_name]), 'exports': [], 'imports': [], 'opecodes': opecodes_str}]
                else:
                    crt_marge_tab[t_fname] = [{'name': _sym_name, 'type': 'func', \
                            'size': len(textsec[_sym_name]), 'exports': [], 'imports': [], 'opecodes': opecodes_str}]

    if e['e_type'] == 'ET_DYN':
        symtab = e.get_section_by_name('.dynsym')
    else:
        symtab = e.get_section_by_name('.symtab')
    if symtab is None:
        return tab, crt_marge_tab
    exsymtab = {}

    # RISC-V post-relocation text rewrite (bnez / bgeu / call thunks).
    if e['e_machine'] == 'EM_RISCV':
        _arch_riscv.postprocess_text(textsec)

    # PPC64 .opd path: build a parallel {name: opecode-slice} dict; when
    # it is non-empty the main symbol loop below is skipped and the
    # entries land directly in `tab` via the trailing PPC64 block.
    opd_func_dict = {}
    if e['e_machine'] == 'EM_PPC64':
        opd_func_dict = _arch_ppc64.build_opd_dict(e, sections, symtab, textsec)

    # dbg
    exclude_alias_list = []
    f_info_dict = {}
    _offset_list = []
    _offset_idx = 0
    for sym in symtab.iter_symbols():
        if sym.name == '':
            continue
        #print('-')
        if sym['st_info']['type'] == "STT_FUNC":
            #print("%s: 0x%X %d %s " % ( sym.name, sym['st_value'], sym['st_size'], sym['st_shndx']) )
            _offset_list.append(sym['st_value'])
            for _f_key, _f_value in f_info_dict.items():
                if _f_value == {'value':sym['st_value'], 'size':sym['st_size'], 'st_shndx':sym['st_shndx']}:
                    exclude_alias_list.append(max([_f_key, sym.name], key=len))
            f_info_dict[sym.name] = {'value':sym['st_value'], 'size':sym['st_size'], 'st_shndx':sym['st_shndx']}
    _offset_list = sorted(set(_offset_list))

    # The PPC64 .opd path bypasses the symbol loop and inserts straight
    # from opd_func_dict (see the trailing block); every other arch runs
    # the loop here.
    if not opd_func_dict:
        for sym in symtab.iter_symbols():
            if sym.name in exclude_alias_list: # exclude long alias
                #print(sym.name)
                continue
            if sym.name in exapis:
                continue
            if e['e_machine'] == 'EM_RISCV' and _arch_riscv.should_skip_symbol(sym):
                continue
            if sym['st_info']['bind'] == 'STB_LOCAL':
                pass #continu
            if sym['st_info']['type'] == 'STT_NOTYPE' and sym['st_shndx'] == 'SHN_UNDEF' and len(sym.name) != 0:
                exsymtab[sym.name] = 'imports'
                continue
            if sym['st_info']['type'] != 'STT_FUNC':
                continue
            if sym['st_shndx'] == 'SHN_UNDEF':
                exsymtab[sym.name] = 'imports'
                continue
            else:
                exsymtab[sym.name] = 'exports'
            # if sym['st_other']['visibility'] == 'STV_HIDDEN': continue
            logging.debug('\t%s: offset = %d, size = %d' % (sym.name, sym['st_value'], sym['st_size']))

            # ToDo fix bug
            # arm glibc
            try:
                e.get_section(sym['st_shndx']).name
            except TypeError:
                continue
            target_sec = e.get_section(sym['st_shndx'])
            fix_sec_flag = False
            if e['e_machine'] == 'EM_PPC64':
                target_sec, fix_sec_flag = _arch_ppc64.retarget_section(e, sym, target_sec, textsec)

            # check sec
            if not target_sec.name in textsec.keys():
                logging.error('error: %s was not found (%s)' % (target_sec.name, sym.name))
                exit(-1)  # continue #exit(-1)
            baseaddr = target_sec.header['sh_addr']

            # because there are functions whose size is set to zero, but its size is not zero.
            #print(target_sec.name, sym.name, sym['st_value'], textsec[target_sec.name])
            if sym['st_size'] == 0:
                # TODO: check valid length of the function
                _offset_idx += 1
                try:
                    _top = sym['st_value'] - baseaddr
                    _bot = _offset_list[_offset_idx]
                    #print('a', _top, _bot)
                except IndexError:
                    _top = sym['st_value'] - baseaddr
                    _bot = _top + len(textsec[target_sec.name][sym['st_value'] - baseaddr: ])
                    #print('b', _top, _bot)
                opecodes = textsec[target_sec.name][_top:_bot]
                size = len(opecodes)
            else:
                #print(sym['st_value'], baseaddr)
                #print('fix_sec_flag :', fix_sec_flag)
                if fix_sec_flag == False:
                    opecodes = textsec[target_sec.name][sym['st_value'] - baseaddr:sym['st_value'] + sym['st_size'] - baseaddr]
                    size = sym['st_size']
                else:
                    opecodes = textsec[target_sec.name][baseaddr:sym['st_size'] - baseaddr]
                    size = sym['st_size']
            #if e['e_machine'] in ['EM_386', 'EM_X86_64']:
            #    opecodes[0] = '( CC | %s )' % opecodes[0] # matches INT3 prologue for api hooking # TODO: sohuld modify functions code of crt*.o?

            # ET_EXEC: capstone-driven branch wildcarding. The pre-split
            # code only handled EM_386 here; any other ET_EXEC arch is
            # dropped via the trailing ``continue``.
            if e.header['e_type'] == 'ET_EXEC':
                if e['e_machine'] == 'EM_386' and e['e_ident']['EI_CLASS'] == 'ELFCLASS32':
                    _arch_i386.apply_exec_capstone(target_sec, sym, opecodes, baseaddr)
                else:
                    continue

            # RISC-V records a ``min_size`` annotation alongside the
            # pattern; every other arch leaves it at 0 (field omitted).
            opecode_minimum_length = 0
            if e['e_machine'] == 'EM_RISCV':
                opecode_minimum_length = _arch_riscv.compute_min_length(opecodes)

            if size > MAXIMUM_PATTERN_LENGTH:
                opecodes = opecodes[:MAXIMUM_PATTERN_LENGTH]

            # Normalise RELAX-window markers at the slice edges (RISC-V).
            if e['e_machine'] == 'EM_RISCV':
                _arch_riscv.finalize_opecodes(opecodes)
            opecodes_str = ' '.join(opecodes)
            # The original guard ran every symbol through cxxfilt to drop
            # names that the demangler rewrites (i.e. actual C++ mangled
            # symbols). Itanium ABI mangled names always start with '_Z',
            # so calling cxxfilt on the long tail of C symbols is pure
            # overhead — short-circuit on the prefix and only consult
            # cxxfilt when it could change the answer.
            add_func = True
            if sym.name.startswith('_Z'):
                try:
                    if sym.name != cxxfilt.demangle(sym.name):
                        add_func = False
                except cxxfilt.InvalidName:
                    continue
            if add_func:
                if sym.name in CRT_INIT_FINI_FUNC_LIST:
                    continue
                if opecode_minimum_length == 0:
                    if opecodes_str in tab.keys():
                        tab[opecodes_str].append({'name': sym.name, 'type': 'func', \
                                'size': size, 'exports': [], 'imports': [], 'objname': fname.split('/')[-1] + arfile})
                    else:
                        tab[opecodes_str] = [{'name': sym.name, 'type': 'func', \
                                'size': size, 'exports': [], 'imports': [], 'objname': fname.split('/')[-1] + arfile}]
                else:
                    if opecodes_str in tab.keys():
                        tab[opecodes_str].append({'name': sym.name, 'type': 'func', \
                                'size': size, 'min_size': opecode_minimum_length, \
                                'exports': [], 'imports': [], 'objname': fname.split('/')[-1] + arfile})
                    else:
                        tab[opecodes_str] = [{'name': sym.name, 'type': 'func', \
                                'size': size, 'min_size': opecode_minimum_length, \
                                'exports': [], 'imports': [], 'objname': fname.split('/')[-1] + arfile}]
        for opecodes_str in tab.keys():
            for i in range(len(tab[opecodes_str])):
                for symname, export_or_import in exsymtab.items():
                    tab[opecodes_str][i][export_or_import].append(symname)
    # PPC64 .opd: insert the parallel dict's entries directly into tab.
    # Other arches produced an empty opd_func_dict above so this block
    # is a no-op for them.
    if opd_func_dict:
        for func_name, func_info in opd_func_dict.items():
            #print(func_name, func_info)
            if func_info != 'checked':
                opecodes = func_info['func_opecode']
                size = func_info['func_size']
                # LIMIT LENGTH
                if size > MAXIMUM_PATTERN_LENGTH:
                    opecodes = opecodes[:MAXIMUM_PATTERN_LENGTH]
                opecodes_str = ' '.join(opecodes)
                add_func = True
                if func_name.startswith('_Z'):
                    try:
                        if func_name != cxxfilt.demangle(func_name):
                            add_func = False
                    except cxxfilt.InvalidName:
                        continue
                if add_func:
                    if opecodes_str in tab.keys():
                        tab[opecodes_str].append({'name': func_name, 'type': 'func', \
                                'size': size, 'exports': [], 'imports': [], 'objname': fname.split('/')[-1] + arfile})
                    else:
                        tab[opecodes_str] = [{'name': func_name, 'type': 'func', \
                                'size': size, 'exports': [], 'imports': [], 'objname': fname.split('/')[-1] + arfile}]
                opd_func_dict[func_name] = 'checked'

    return tab, crt_marge_tab

def merge_dicts(src, dst):
    # dst[key] += src[key] was the hot path: dict.keys() materialises the
    # key view on each iteration and the `+=` allocates a fresh
    # concatenated list. setdefault + extend amortises both. Profiling
    # libc.a's 4k merge calls showed ~0.75 s here, dominated by hashing
    # and list reallocation; this form drops that by roughly half.
    for key, value in src.items():
        existing = dst.get(key)
        if existing is None:
            dst[key] = value
        else:
            existing.extend(value)
    return dst


def fetch_opecodes_from_arfile(arfile):
    tab = {}
    crt_tab = {}
    rel_arfile = arfile.split('/')[-1]
    arfile = os.path.abspath(arfile)
    objfiles = arpy.Archive(arfile)
    #print(objfiles)
    #for f in objfiles:
    #    print(f)
    #exit(1)
    for f in objfiles:
        # ToDo investigate the cause of the error
        fname = f.header.name.decode('utf-8')
        if fname in ['aeabi_sighandlers.os', 'aeabi_sighandlers.o']:
            continue
        #print('\x1b[2K\033[%d;1H%s' % (row, f.header.name.decode('utf-8')), end='', flush=True)
        newtab, new_crt_tab = fetch_opecodes(f, arfile = rel_arfile)
        tab = merge_dicts(tab, newtab)
        crt_tab = merge_dicts(crt_tab, new_crt_tab)
    #print('\x1b[2K\033[%d;1H' % row, end='', flush=True)
    return tab, crt_tab

def create_rule(syms, hexstr_opecodes, options = []):
    # rule = 'rule %s {\n' % funcs[-1]
    # TODO: rule name
    global MAX_RULE_INDENTIFIER_LENGTH
    global MAX_ALIASES
    funcs = sorted(set([syminfo['name'] for syminfo in syms])) # TODO: keep an order of names
    objnames = set([syminfo['objname'].replace('.o', '').replace('-', '_') for syminfo in syms])
    exports = set([(syminfo['objname'].split('.')[0].replace('-', '_'), ', '.join(syminfo['exports'])) for syminfo in syms])
    imports = set([(syminfo['objname'].split('.')[0].replace('-', '_'), ', '.join(syminfo['imports'])) for syminfo in syms])
    rule = 'rule %s {\n' % (funcs[-1][:MAX_RULE_INDENTIFIER_LENGTH].replace('.', '_DOT_').replace('@', '_AT_').replace('$', '_DOLLER_') + '_' + hashlib.md5(hexstr_opecodes.encode('utf-8')).hexdigest())
    #rule = 'rule %s {\n' % (min(funcs, key=len).replace('.', '_DOT_').replace('@', '_AT_').replace('$', '_DOLLER_') + '_' + hashlib.md5(hexstr_opecodes.encode('utf-8')).hexdigest())
    rule += '\tmeta:\n'
    #rule += '\t\taliases = "%s"\n' % ', '.join(funcs)
    rule += '\t\taliases = "%s"\n' % ', '.join(funcs[:MAX_ALIASES])
    rule += '\t\ttype = "%s"\n' % (syms[0]['type'])
    # if 'min_size' in syms[0].keys():
    #     rule += '\t\tsize = "%d"//\t\tmin_size = "%d"\n' % (syms[0]['size'], syms[0]['min_size'])
    # else:
    #     rule += '\t\tsize = "%d"\n' % (syms[0]['size'])
    rule += '\t\tsize = "%d"\n' % (syms[0]['size'])
    if 'objfiles' in options:
        # Sort before truncating so the 5 objfiles recorded in the rule are
        # deterministic across runs. The prior list(set(...)) iterated in
        # set-hash order, which varies with insertion sequence — a
        # cosmetic concern that became real when the [:5] slice picked
        # different five names depending on how merge_dicts had appended
        # archive contributions.
        rule += '\t\tobjfiles = "%s"\n' % ', '.join(sorted(objnames)[:5])
    if 'exports' in options:
        for objname, syms in sorted(exports):
            rule += '\t\texports_%s = "%s"\n' % (objname, syms)
    if 'imports' in options:
        for objname, syms in sorted(imports):
            rule += '\t\timports_%s = "%s"\n' % (objname, syms)
    if 'prototype' in options:
        rule += '\t\tprototype = "%s, %s"\n' % ('void', 'void')
    rule += '\tstrings:\n'
    rule += '\t\t$pattern = { %s }\n' % (hexstr_opecodes)
    rule += '\tcondition:\n'
    rule += '\t\t$pattern\n'
    rule += '}\n'
    return rule

def get_rules(tab):

    global VERSION
    rules_list = []
    rule_ver = '// YARA rules, version ' + VERSION + '\n\n'
    rules_list.append(rule_ver)
    #print('// YARA rules, version %s\n\n' % (VERSION))
    #f.write('// YARA rules, version %s\n\n' % (VERSION))
    for opecodes in sorted(tab.keys()):
        # TODO: remove wildcards (acc decreased in the evaluation of al-1.4.4 because of false positives: functions of size 5)

        question_mark_size = tab[opecodes][0]['size'] - opecodes.count('??')
        zero_hex_size = tab[opecodes][0]['size'] - opecodes.count('00')
        # if tab[opecodes][0]['size'] <= MINIMUM_PATTERN_LENGTH:
        if question_mark_size + zero_hex_size <= MINIMUM_PATTERN_LENGTH:
            #logging.warning('Skipped %s (%s)' % (', '.join(set([x['name'] for x in tab[opecodes]])),opecodes))
            continue
        opecode_list = opecodes.split(' ')
        wildcard_num = opecode_list.count('??')
        zero_hex_num = opecode_list.count('00')
        if len(opecodes.split(' ')) >= 1 and not opecode_list == [''] \
                and not wildcard_num == len(opecode_list) \
                and not zero_hex_num == len(opecode_list):
            rules = create_rule(tab[opecodes], opecodes, ['objfiles'])
            rules_list.extend(rules.split('\n'))
        #print(rules)
        #print(rules.split('\n'))
        #f.write(rules)
        #logging.info(rules)
    return rules_list

def output_function_names(fname, funcslist):
    uniqfunc = set()
    for funcs in funcslist:
        for func in funcs:
            uniqfunc.add(func)
    with open(fname, 'w') as f:
        for func in sorted(uniqfunc):
            #f.write(func + '\n')
            continue

def output_rules(rules_list, output_path):
    with open(output_path, 'w') as f:
        for rule in rules_list:
            f.write("%s\n" % rule)
    #print('Completed successfully ->', output_path)

def main():
    parser = argparse.ArgumentParser(prog = sys.argv[0])
    parser.add_argument('--version', '-v', action = 'version', version = '%s %s' % (sys.argv[0], VERSION))
    parser.add_argument('--excluded-api', type = str, help = 'File name of a list that includes api names to be excluded')
    parser.add_argument('--save-api', type = str, help = 'File name of an api list')
    #parser.add_argument('--yara', '-y', default = 'patterns.yara', help = 'YARA file name to be saved')
    parser.add_argument('--min', '-m', default = 0, type = int, help = 'Minimum size of a function')
    parser.add_argument('--output_path', '-o', help = 'YARA file name to be saved')

    parser.add_argument('files', nargs = '+', help = 'File names of archive, object, executable files')
    args = parser.parse_args()
    MINIMUM_PATTERN_LENGTH = args.min

    logging.info('Analyzing archive files...')
    tab = {}
    crt_tab = {}

    EXCLUDE_OBJ_FILES = []#['Scrt1.o', 'rcrt1.o', 'crtbegin.o', 'crtbeginS.o', 'crtendS.o']

    for filename in args.files:
        # skip dynamic link object
        if filename.split('/')[-1] in EXCLUDE_OBJ_FILES:
            #print(filename.split('/')[-1])
            continue
        # c-lang only fast mode
        #skip c++ objfile (libstdc++)
        cpp_obj_list = ['libstdc++.a']
        if filename.split('/')[-1] in cpp_obj_list:
            continue

        #print('%s' % filename, flush=True)
        ftype = magic.from_file(filename, mime = True)

        if ftype == 'application/x-archive': #filename[-2:] == '.a':
            newtab, new_crt_tab = fetch_opecodes_from_arfile(filename)
        elif ftype == 'application/x-object': #filename[-2:] == '.o':
            with open(filename, 'rb') as f:
                newtab, new_crt_tab = fetch_opecodes(f)
        elif ftype in ['application/x-executable', 'application/x-sharedlib', 'application/x-pie-executable']: # TODO: support other executables
            if args.excluded_api and os.path.exists(args.excluded_api):
                with open(args.excluded_api) as f:
                    exapis = f.read().split('\n')
            else:
                exapis = []
            with open(filename, 'rb') as f:
                newtab, new_crt_tab = fetch_opecodes(f, exapis)
        elif ftype in ['text/plain', 'inode/symlink']:
            continue
        else:
            logging.error('Not supported file type of %s: %s' % (filename, ftype))
            #continue
            exit(-1)
        tab = merge_dicts(tab, newtab)
        crt_tab = merge_dicts(crt_tab, new_crt_tab)

    # marge crt opecode
    _tmp_crt_info = {}
    crt_obj_list = ['crti.o', 'crtn.o']
    if len(set(crt_tab.keys()) & set(crt_obj_list)) == len(crt_obj_list):
        crt_func_name_list = []
        # get connect crt function name list
        for info_in_obj in crt_tab['crti.o']:
            crt_func_name_list.append(info_in_obj['name'])

        for crt_obj,  crt_info_list in crt_tab.items():
            if crt_obj == 'crti.o':
                for crt_info in crt_info_list:
                    for crt_func_name in crt_func_name_list:
                        if crt_info['name'] == crt_func_name:
                            opecodes_str = crt_info['opecodes']
                            _tmp_crt_info[crt_func_name] = {'i-opecode' : opecodes_str}
        for crt_obj,  crt_info_list in crt_tab.items():
            if crt_obj == 'crtn.o':
                for crt_info in crt_info_list:
                    for crt_func_name in crt_func_name_list:
                        if crt_info['name'] == crt_func_name:
                            opecodes_str = crt_info['opecodes']
                            _tmp_crt_info[crt_func_name]['n-opecode'] = opecodes_str
        # marge
        marged_crt_func_opecs = {}
        for func_name in _tmp_crt_info.keys():
            for t_opecodes_str in _tmp_crt_info[func_name].values():
                if not func_name in marged_crt_func_opecs.keys():
                    marged_crt_func_opecs[func_name] = t_opecodes_str
                else:
                    marged_crt_func_opecs[func_name] = marged_crt_func_opecs[func_name] + ' [0-12] ' +  t_opecodes_str

        for _crt_func_name, _crt_func_opecodes in marged_crt_func_opecs.items():
            if _crt_func_opecodes in tab.keys():
                tab[_crt_func_opecodes] = [ \
                        tab[_crt_func_opecodes][0], \
                        { 'name': _crt_func_name, 'type': 'func', \
                        'size': len(_crt_func_opecodes.split(' ')), 'exports': [], 'imports': [], \
                        'objname': 'crti.o'} \
                        ]
            else:
                tab[_crt_func_opecodes] = [{'name': _crt_func_name, 'type': 'func', \
                        'size': len(_crt_func_opecodes.split(' ')), 'exports': [], 'imports': [], \
                        'objname': 'crti.o'}]

    # show shinked functions
    for v in tab.values():
        if v[0]['size'] > MAXIMUM_PATTERN_LENGTH:
            #logging.warning('Shrinked %s: %d -> %d' % (v[0]['name'], v[0]['size'], MAXIMUM_PATTERN_LENGTH))
            continue

    logging.info('\n\nGenerating a yara file...\n\n')
    rules_list = get_rules(tab)

    # output yara rule
    if args.output_path == 'no': # no output
        None
    elif args.output_path: # file output
        output_rules(rules_list, args.output_path)
    else: # stdout
        for rules in rules_list:
            print(rules)

if __name__ == '__main__':
    main()

    #if args.save_api:
    #    output_function_names(args.save_api, tab.values())
    #print('Completed successfully.')

