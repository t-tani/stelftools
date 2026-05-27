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

def _resolve_name(f):
    """Recover the file name from either an arpy member or a raw file object."""
    if hasattr(f, 'header'):
        return f.header.name.decode('utf-8')
    if hasattr(f, 'name'):
        return f.name
    logging.error('Could not identify the file name')
    exit(-1)


def _harvest_text_sections(sections, fname):
    """Materialise every executable SHT_PROGBITS section into a {name: hex-list} map.

    The original implementation also walked .rodata.* / .rdata.* into a
    side dict that was never read, so the rodata branch is omitted here;
    the text-discovery semantics are unchanged.
    """
    textsec = {}
    for sec in sections:
        if (sec['sh_type'] == 'SHT_PROGBITS'
                and (sec['sh_flags'] & SH_FLAGS.SHF_EXECINSTR) == SH_FLAGS.SHF_EXECINSTR):
            logging.debug('%s: %s' % (fname, sec.name))
            textsec[sec.name] = [_BYTE_TO_HEX[b] for b in sec.data()]
    return textsec


def _build_relnames(textsec):
    """For each text section, the names of the .rel / .rela sections that patch it."""
    relnames = set()
    for tname in textsec.keys():
        relnames.add('.rel' + tname)
        relnames.add('.rela' + tname)
    return relnames


def _apply_all_relocations(e, sections, relnames, textsec, ei_data, fname):
    """Walk every relocation section that patches a known text section.

    The per-arch ``apply_relocation`` is dispatched lazily: a binary
    that has no relocations does not trigger an UnsupportedArch exit,
    matching the pre-split semantic where the unsupported check lived
    inside the per-relocation entry loop.
    """
    handler = None
    for sec in sections:
        if not sec['sh_type'] in ['SHT_REL', 'SHT_RELA']:
            continue
        if not sec.name in relnames:
            continue
        logging.debug('%s: %s' % (fname, sec.name))

        if sec.name.startswith('.rela'):
            name = sec.name[5:]
        elif sec.name.startswith('.rel'):
            name = sec.name[4:]
        else:
            logging.error('Unsupported section name: %s' % sec.name)
            exit(-1)

        # RISC-V RELAX windows need to know every relocation at the same
        # offset; build the lookup once per section.
        _reloc_info = {}
        _checked_r_offset = []
        for r in sec.iter_relocations():
            offset = r['r_offset']
            rtype = r['r_info_type']
            if not offset in _reloc_info.keys():
                _reloc_info[offset] = {'rtype': [rtype]}
            else:
                _reloc_info[offset]['rtype'] = _reloc_info[offset]['rtype'] + [rtype]

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
    return handler


def _collect_crt_funcs(textsec, fname):
    """Pick up the ``_init`` / ``_fini`` entries from crti.o / crtn.o.

    The trailing pass in ``main`` knits the two halves together into a
    single ``[0-12]``-spanning rule that matches the linked ``crt`` glue
    regardless of how the loader concatenates them.
    """
    crt_marge_tab = {}
    leaf = fname.split('/')[-1]
    if leaf not in ['crti.o', 'crtn.o']:
        return crt_marge_tab
    for _sym_name in textsec.keys():
        if _sym_name not in CRT_INIT_FINI_FUNC_LIST:
            continue
        opecodes_str = ' '.join(textsec[_sym_name])
        entry = {
            'name': _sym_name, 'type': 'func',
            'size': len(textsec[_sym_name]),
            'exports': [], 'imports': [],
            'opecodes': opecodes_str,
        }
        crt_marge_tab.setdefault(leaf, []).append(entry)
    return crt_marge_tab


def _select_symtab(e):
    """Pick ``.dynsym`` for ET_DYN inputs, otherwise ``.symtab``."""
    if e['e_type'] == 'ET_DYN':
        return e.get_section_by_name('.dynsym')
    return e.get_section_by_name('.symtab')


def _build_alias_index(symtab):
    """Index STT_FUNC symbols so the main loop can drop alias siblings.

    Returns ``(exclude_alias_list, offset_list)``. ``exclude_alias_list``
    holds the longer of each (value, size, st_shndx)-tied symbol pair so
    the shorter (canonical) name reaches the tab. ``offset_list`` is the
    sorted set of distinct st_value entries; the size-zero recovery path
    walks it to guess the next function boundary.
    """
    exclude_alias_list = []
    f_info_dict = {}
    offset_list = []
    for sym in symtab.iter_symbols():
        if sym.name == '':
            continue
        if sym['st_info']['type'] != "STT_FUNC":
            continue
        offset_list.append(sym['st_value'])
        signature = {
            'value': sym['st_value'],
            'size': sym['st_size'],
            'st_shndx': sym['st_shndx'],
        }
        for _f_key, _f_value in f_info_dict.items():
            if _f_value == signature:
                exclude_alias_list.append(max([_f_key, sym.name], key=len))
        f_info_dict[sym.name] = signature
    return exclude_alias_list, sorted(set(offset_list))


def _opecodes_for_symbol(sym, target_sec, textsec, baseaddr,
                        offset_list, offset_state, fix_sec_flag):
    """Slice the function's bytes out of textsec[target_sec.name].

    ``offset_state`` is a ``[int]`` container the size-zero recovery
    path advances; this carries the running index into ``offset_list``
    across the main loop's iterations.
    """
    if sym['st_size'] == 0:
        offset_state[0] += 1
        try:
            _top = sym['st_value'] - baseaddr
            _bot = offset_list[offset_state[0]]
        except IndexError:
            _top = sym['st_value'] - baseaddr
            _bot = _top + len(textsec[target_sec.name][sym['st_value'] - baseaddr:])
        opecodes = textsec[target_sec.name][_top:_bot]
        return opecodes, len(opecodes)
    if fix_sec_flag:
        opecodes = textsec[target_sec.name][baseaddr:sym['st_size'] - baseaddr]
    else:
        opecodes = textsec[target_sec.name][sym['st_value'] - baseaddr:sym['st_value'] + sym['st_size'] - baseaddr]
    return opecodes, sym['st_size']


def _insert_tab_entry(tab, opecodes_str, name, size, fname, arfile, *, min_size=0):
    """Append one function entry to ``tab[opecodes_str]``, creating the
    bucket on demand. ``min_size`` is only recorded when non-zero so
    arches that do not compute it keep their entries dict-equal to the
    pre-split form.
    """
    entry = {
        'name': name, 'type': 'func', 'size': size,
        'exports': [], 'imports': [],
        'objname': fname.split('/')[-1] + arfile,
    }
    if min_size:
        entry['min_size'] = min_size
    tab.setdefault(opecodes_str, []).append(entry)


def _populate_tab_from_symbols(tab, exsymtab, e, symtab, textsec,
                               exclude_alias_list, offset_list,
                               exapis, fname, arfile):
    """Walk ``symtab`` and insert per-function opecode patterns into
    ``tab``. ``exsymtab`` is filled with ``imports`` / ``exports`` and
    merged into every tab entry at the end so each rule carries the
    full import / export view of the object it came from.
    """
    offset_state = [0]
    for sym in symtab.iter_symbols():
        if sym.name in exclude_alias_list:
            continue
        if sym.name in exapis:
            continue
        if e['e_machine'] == 'EM_RISCV' and _arch_riscv.should_skip_symbol(sym):
            continue
        if sym['st_info']['bind'] == 'STB_LOCAL':
            pass  # left as a documentation marker for STB_LOCAL handling
        if sym['st_info']['type'] == 'STT_NOTYPE' and sym['st_shndx'] == 'SHN_UNDEF' and len(sym.name) != 0:
            exsymtab[sym.name] = 'imports'
            continue
        if sym['st_info']['type'] != 'STT_FUNC':
            continue
        if sym['st_shndx'] == 'SHN_UNDEF':
            exsymtab[sym.name] = 'imports'
            continue
        exsymtab[sym.name] = 'exports'
        logging.debug('\t%s: offset = %d, size = %d' % (sym.name, sym['st_value'], sym['st_size']))

        # Arm glibc occasionally leaves a symbol pointing at a section
        # the file does not actually carry; treat that as an opaque drop.
        try:
            e.get_section(sym['st_shndx']).name
        except TypeError:
            continue
        target_sec = e.get_section(sym['st_shndx'])
        fix_sec_flag = False
        if e['e_machine'] == 'EM_PPC64':
            target_sec, fix_sec_flag = _arch_ppc64.retarget_section(e, sym, target_sec, textsec)

        if not target_sec.name in textsec.keys():
            logging.error('error: %s was not found (%s)' % (target_sec.name, sym.name))
            exit(-1)
        baseaddr = target_sec.header['sh_addr']

        opecodes, size = _opecodes_for_symbol(
            sym, target_sec, textsec, baseaddr,
            offset_list, offset_state, fix_sec_flag,
        )

        # ET_EXEC: capstone-driven branch wildcarding. The pre-split
        # code only handled EM_386 here; any other ET_EXEC arch falls
        # through the trailing ``continue``.
        if e.header['e_type'] == 'ET_EXEC':
            if e['e_machine'] == 'EM_386' and e['e_ident']['EI_CLASS'] == 'ELFCLASS32':
                _arch_i386.apply_exec_capstone(target_sec, sym, opecodes, baseaddr)
            else:
                continue

        opecode_minimum_length = 0
        if e['e_machine'] == 'EM_RISCV':
            opecode_minimum_length = _arch_riscv.compute_min_length(opecodes)

        if size > MAXIMUM_PATTERN_LENGTH:
            opecodes = opecodes[:MAXIMUM_PATTERN_LENGTH]

        if e['e_machine'] == 'EM_RISCV':
            _arch_riscv.finalize_opecodes(opecodes)
        opecodes_str = ' '.join(opecodes)

        # cxxfilt drops mangled C++ symbols (their demangled form differs
        # from the raw name). The Itanium ABI prefix ``_Z`` short-circuits
        # the long tail of C symbols.
        if sym.name.startswith('_Z'):
            try:
                if sym.name != cxxfilt.demangle(sym.name):
                    continue
            except cxxfilt.InvalidName:
                continue
        if sym.name in CRT_INIT_FINI_FUNC_LIST:
            continue
        _insert_tab_entry(
            tab, opecodes_str, sym.name, size, fname, arfile,
            min_size=opecode_minimum_length,
        )

    # Stamp every tab entry with the object's full import / export view.
    for opecodes_str in tab.keys():
        for i in range(len(tab[opecodes_str])):
            for symname, export_or_import in exsymtab.items():
                tab[opecodes_str][i][export_or_import].append(symname)


def _populate_tab_from_opd(tab, opd_func_dict, fname, arfile):
    """PPC64-only: insert opecode slices the ``.opd`` walker produced.
    Iterates the dict produced by ``_arch_ppc64.build_opd_dict``;
    other arches keep the dict empty so this is a no-op for them.
    """
    for func_name, func_info in opd_func_dict.items():
        if func_info == 'checked':
            continue
        opecodes = func_info['func_opecode']
        size = func_info['func_size']
        if size > MAXIMUM_PATTERN_LENGTH:
            opecodes = opecodes[:MAXIMUM_PATTERN_LENGTH]
        if func_name.startswith('_Z'):
            try:
                if func_name != cxxfilt.demangle(func_name):
                    opd_func_dict[func_name] = 'checked'
                    continue
            except cxxfilt.InvalidName:
                continue
        opecodes_str = ' '.join(opecodes)
        _insert_tab_entry(tab, opecodes_str, func_name, size, fname, arfile)
        opd_func_dict[func_name] = 'checked'


def fetch_opecodes(f, arfile='', exapis=()):
    """Top-level driver: read one ELF object and return its
    ``(tab, crt_marge_tab)`` pair. Walks the input as a fixed pipeline
    of phases; each phase is a free function above. info_create.py
    treats the return shape as ``(tab, crt_marge_tab)`` so the function
    signature is the load-bearing API of this module.
    """
    fname = _resolve_name(f)
    arfile = '@' + arfile if arfile else ''
    e = ELFFile(f)
    sections = list(e.iter_sections())
    ei_data = e['e_ident']['EI_DATA']

    textsec = _harvest_text_sections(sections, fname)
    relnames = _build_relnames(textsec)
    _apply_all_relocations(e, sections, relnames, textsec, ei_data, fname)

    if e['e_machine'] == 'EM_RISCV':
        _arch_riscv.postprocess_text(textsec)

    crt_marge_tab = _collect_crt_funcs(textsec, fname)
    symtab = _select_symtab(e)
    if symtab is None:
        return {}, crt_marge_tab

    opd_func_dict = {}
    if e['e_machine'] == 'EM_PPC64':
        opd_func_dict = _arch_ppc64.build_opd_dict(e, sections, symtab, textsec)

    exclude_alias_list, offset_list = _build_alias_index(symtab)
    tab = {}
    exsymtab = {}

    if not opd_func_dict:
        _populate_tab_from_symbols(
            tab, exsymtab, e, symtab, textsec,
            exclude_alias_list, offset_list,
            exapis, fname, arfile,
        )
    else:
        _populate_tab_from_opd(tab, opd_func_dict, fname, arfile)

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

