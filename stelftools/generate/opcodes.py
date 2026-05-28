"""Extract opcodes from static library objects into YARA rule bodies.

The entry points :func:`extract_opcodes` and
:func:`extract_opcodes_from_arfile` walk one ELF object (or every
member of an ``ar`` archive) and return the per-function ``(tab,
crt_merge_tab)`` pair that the package's rule renderer consumes.

The pipeline per object:

1. Harvest every executable SHT_PROGBITS section into a byte map.
2. Wildcard relocatable addresses with the per-architecture handler
   under :mod:`stelftools.generate.arch`.
3. Hand the CRT init / fini pair (crti.o / crtn.o) to
   :mod:`stelftools.generate.crt` so they can be merged into a single
   spanning rule once every input has been walked.
4. Populate ``tab`` keyed on the function's opcode hex string, with
   the symbol name(s) it covered. PPC64 routes through the .opd
   helper in :mod:`stelftools.generate.arch.ppc64`.

The rule body length is capped by ``MAXIMUM_PATTERN_LENGTH``.
stelftools originally capped this at 200 bytes; the current value
(15000) was raised to accommodate RISC-V linker relaxation, where a
single function's opcode stream can span thousands of bytes before
reaching a relocation boundary.
"""

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
from . import crt
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
# Needed for c++ because there are too many same opcode functions
#MAX_ALIASES = 50 # TODO: C++ function names may cause too long string errors
MAX_ALIASES = 70 # TODO: C++ function names may cause too long string errors
#VERSION = '0.1.1_2020_04_26'
VERSION = '0.2.0_2021_07_29'
# MINIMUM_PATTERN_LENGTH = 6 # TODO: parameter tuning
MINIMUM_PATTERN_LENGTH = 0
#MAXIMUM_PATTERN_LENGTH = 1000 # 600  # TODO: parameter tuning
MAXIMUM_PATTERN_LENGTH = 15000 # 600  # TODO: risc-v

# ---------------------------------------------------------------------------
# extract_opcodes pipeline -- phase helpers in execution order, then the
# orchestrator. Per-arch hooks live in stelftools.generate.arch; CRT-glue
# handling lives in stelftools.generate.crt; this module owns the
# cross-arch control flow.
# ---------------------------------------------------------------------------


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


def _opcodes_for_symbol(sym, target_sec, textsec, baseaddr,
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
        opcodes = textsec[target_sec.name][_top:_bot]
        return opcodes, len(opcodes)
    if fix_sec_flag:
        opcodes = textsec[target_sec.name][baseaddr:sym['st_size'] - baseaddr]
    else:
        opcodes = textsec[target_sec.name][sym['st_value'] - baseaddr:sym['st_value'] + sym['st_size'] - baseaddr]
    return opcodes, sym['st_size']


def _insert_tab_entry(tab, opcodes_str, name, size, fname, arfile, *, min_size=0):
    """Append one function entry to ``tab[opcodes_str]``, creating the
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
    tab.setdefault(opcodes_str, []).append(entry)


def _populate_tab_from_symbols(tab, exsymtab, e, symtab, textsec,
                               exclude_alias_list, offset_list,
                               exapis, fname, arfile):
    """Walk ``symtab`` and insert per-function opcode patterns into
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

        opcodes, size = _opcodes_for_symbol(
            sym, target_sec, textsec, baseaddr,
            offset_list, offset_state, fix_sec_flag,
        )

        # ET_EXEC: capstone-driven branch wildcarding. The pre-split
        # code only handled EM_386 here; any other ET_EXEC arch falls
        # through the trailing ``continue``.
        if e.header['e_type'] == 'ET_EXEC':
            if e['e_machine'] == 'EM_386' and e['e_ident']['EI_CLASS'] == 'ELFCLASS32':
                _arch_i386.apply_exec_capstone(target_sec, sym, opcodes, baseaddr)
            else:
                continue

        opcode_minimum_length = 0
        if e['e_machine'] == 'EM_RISCV':
            opcode_minimum_length = _arch_riscv.compute_min_length(opcodes)

        if size > MAXIMUM_PATTERN_LENGTH:
            opcodes = opcodes[:MAXIMUM_PATTERN_LENGTH]

        if e['e_machine'] == 'EM_RISCV':
            _arch_riscv.finalize_opcodes(opcodes)
        opcodes_str = ' '.join(opcodes)

        # cxxfilt drops mangled C++ symbols (their demangled form differs
        # from the raw name). The Itanium ABI prefix ``_Z`` short-circuits
        # the long tail of C symbols.
        if sym.name.startswith('_Z'):
            try:
                if sym.name != cxxfilt.demangle(sym.name):
                    continue
            except cxxfilt.InvalidName:
                continue
        if sym.name in crt.INIT_FINI_FUNC_LIST:
            continue
        _insert_tab_entry(
            tab, opcodes_str, sym.name, size, fname, arfile,
            min_size=opcode_minimum_length,
        )

    # Stamp every tab entry with the object's full import / export view.
    for opcodes_str in tab.keys():
        for i in range(len(tab[opcodes_str])):
            for symname, export_or_import in exsymtab.items():
                tab[opcodes_str][i][export_or_import].append(symname)


def _populate_tab_from_opd(tab, opd_func_dict, fname, arfile):
    """PPC64-only: insert opcode slices the ``.opd`` walker produced.
    Iterates the dict produced by ``_arch_ppc64.build_opd_dict``;
    other arches keep the dict empty so this is a no-op for them.
    """
    for func_name, func_info in opd_func_dict.items():
        if func_info == 'checked':
            continue
        opcodes = func_info['func_opcode']
        size = func_info['func_size']
        if size > MAXIMUM_PATTERN_LENGTH:
            opcodes = opcodes[:MAXIMUM_PATTERN_LENGTH]
        if func_name.startswith('_Z'):
            try:
                if func_name != cxxfilt.demangle(func_name):
                    opd_func_dict[func_name] = 'checked'
                    continue
            except cxxfilt.InvalidName:
                continue
        opcodes_str = ' '.join(opcodes)
        _insert_tab_entry(tab, opcodes_str, func_name, size, fname, arfile)
        opd_func_dict[func_name] = 'checked'


def extract_opcodes(f, arfile='', exapis=()):
    """Top-level driver: read one ELF object and return its
    ``(tab, crt_merge_tab)`` pair. Walks the input as a fixed pipeline
    of phases; each phase is a free function above. info_create.py
    treats the return shape as ``(tab, crt_merge_tab)`` so the function
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

    crt_merge_tab = crt.collect_funcs(textsec, fname)
    symtab = _select_symtab(e)
    if symtab is None:
        return {}, crt_merge_tab

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

    return tab, crt_merge_tab


# ---------------------------------------------------------------------------
# Multi-file aggregation -- merge per-file extract_opcodes outputs and the
# ar-archive wrapper that drives them.
# ---------------------------------------------------------------------------


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


def extract_opcodes_from_arfile(arfile):
    """Walk an ``ar`` archive and merge each member's extract_opcodes
    output into one ``(tab, crt_tab)`` pair. The arpy iteration order
    is deterministic per-archive, so the merge sequence is stable.
    """
    tab = {}
    crt_tab = {}
    rel_arfile = arfile.split('/')[-1]
    arfile = os.path.abspath(arfile)
    objfiles = arpy.Archive(arfile)
    for f in objfiles:
        fname = f.header.name.decode('utf-8')
        # ARM aeabi_sighandlers triggers a pyelftools edge case; skipped
        # historically and kept skipped until the underlying parser is
        # patched.
        if fname in ['aeabi_sighandlers.os', 'aeabi_sighandlers.o']:
            continue
        newtab, new_crt_tab = extract_opcodes(f, arfile=rel_arfile)
        tab = merge_dicts(tab, newtab)
        crt_tab = merge_dicts(crt_tab, new_crt_tab)
    return tab, crt_tab


# ---------------------------------------------------------------------------
# YARA rule rendering -- turn the in-memory tab into the on-disk rule text.
# ---------------------------------------------------------------------------


_RULE_NAME_SUBS = {'.': '_DOT_', '@': '_AT_', '$': '_DOLLER_'}


def _rule_identifier(funcs, hexstr_opcodes):
    """Derive a YARA-legal rule name from the symbol set + opcode hash.

    Picks the alphabetically last function name (deterministic across
    runs) as a prefix, sanitises ASCII punctuation YARA does not allow
    in identifiers, and appends an md5 of the opcode hex string so two
    distinct patterns sharing a prefix get distinct rules.
    """
    name = funcs[-1][:MAX_RULE_INDENTIFIER_LENGTH]
    for ch, repl in _RULE_NAME_SUBS.items():
        name = name.replace(ch, repl)
    return name + '_' + hashlib.md5(hexstr_opcodes.encode('utf-8')).hexdigest()


def create_rule(syms, hexstr_opcodes, options=[]):
    """Render one YARA rule for a group of symbols sharing the same
    opcode pattern. ``options`` toggles the optional meta fields
    (``objfiles`` / ``exports`` / ``imports`` / ``prototype``).
    """
    funcs = sorted(set([syminfo['name'] for syminfo in syms]))
    objnames = set([syminfo['objname'].replace('.o', '').replace('-', '_') for syminfo in syms])
    exports = set([(syminfo['objname'].split('.')[0].replace('-', '_'), ', '.join(syminfo['exports'])) for syminfo in syms])
    imports = set([(syminfo['objname'].split('.')[0].replace('-', '_'), ', '.join(syminfo['imports'])) for syminfo in syms])

    rule = 'rule %s {\n' % _rule_identifier(funcs, hexstr_opcodes)
    rule += '\tmeta:\n'
    rule += '\t\taliases = "%s"\n' % ', '.join(funcs[:MAX_ALIASES])
    rule += '\t\ttype = "%s"\n' % (syms[0]['type'])
    # RISC-V tab entries also carry a ``min_size`` annotation but it is
    # intentionally not emitted here -- the pre-cleanup code kept the
    # ``size // min_size`` variant commented out so the YARA output
    # stays single-field across arches.
    rule += '\t\tsize = "%d"\n' % (syms[0]['size'])
    if 'objfiles' in options:
        # Sort before truncating so the 5 objfiles recorded in the rule
        # are deterministic across runs; the prior list(set(...)) order
        # depended on insertion sequence and the [:5] slice picked
        # different names depending on archive iteration.
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
    rule += '\t\t$pattern = { %s }\n' % (hexstr_opcodes)
    rule += '\tcondition:\n'
    rule += '\t\t$pattern\n'
    rule += '}\n'
    return rule

def get_rules(tab):
    """Render every tab entry to a YARA rule, in opcode-sorted order.

    Skips entries whose literal byte content (size minus wildcard ``??``
    and zero-hex slots) does not clear ``MINIMUM_PATTERN_LENGTH`` and
    skips degenerate patterns whose opcodes are entirely wildcards or
    entirely ``00`` bytes -- both would match anything.
    """
    rules_list = ['// YARA rules, version ' + VERSION + '\n\n']
    for opcodes in sorted(tab.keys()):
        # TODO: tighten wildcard handling for short functions. Past
        # benchmarks showed an accuracy regression on size-~5 patterns
        # dominated by ?? / 00 slots; the filter immediately below is a
        # partial mitigation, not a fix.
        question_mark_size = tab[opcodes][0]['size'] - opcodes.count('??')
        zero_hex_size = tab[opcodes][0]['size'] - opcodes.count('00')
        if question_mark_size + zero_hex_size <= MINIMUM_PATTERN_LENGTH:
            continue
        opcode_list = opcodes.split(' ')
        wildcard_num = opcode_list.count('??')
        zero_hex_num = opcode_list.count('00')
        if len(opcodes.split(' ')) >= 1 and not opcode_list == [''] \
                and not wildcard_num == len(opcode_list) \
                and not zero_hex_num == len(opcode_list):
            rules = create_rule(tab[opcodes], opcodes, ['objfiles'])
            rules_list.extend(rules.split('\n'))
    return rules_list

def output_rules(rules_list, output_path):
    """Write each rendered rule line to ``output_path``, one per line."""
    with open(output_path, 'w') as f:
        for rule in rules_list:
            f.write("%s\n" % rule)


# ---------------------------------------------------------------------------
# CLI driver -- argparse, per-file dispatch, output. The stelftools-mkrule
# console script targets stelftools.generate:main; the main below is a
# standalone "scan one toolchain dir without the merge / dlist / alist
# steps" entry point still useful when iterating on the opcode extraction.
# ---------------------------------------------------------------------------


# Object leaves the CLI skips before feeding extract_opcodes. libstdc++.a
# carries the C++ runtime, which is out of scope for the C-function
# signature corpus this tool produces.
_SKIP_OBJ_LEAVES = frozenset({'libstdc++.a'})
_EXEC_MIMES = (
    'application/x-executable',
    'application/x-sharedlib',
    'application/x-pie-executable',
)


def _load_excluded_apis(path):
    """Read the optional ``--excluded-api`` file into a list. Returns
    ``[]`` when the path is missing so the executable branch's
    extract_opcodes call still receives a real (empty) list.
    """
    if path and os.path.exists(path):
        with open(path) as f:
            return f.read().split('\n')
    return []


def _process_input_file(filename, exapis):
    """Dispatch one input file to extract_opcodes via libmagic.

    Returns ``(newtab, new_crt_tab)`` for archives / object files /
    executables, or ``None`` when the file should be skipped (C++
    stdlib, plain text, symlink). Exits on an unsupported MIME so the
    CLI surfaces the failure loudly.
    """
    leaf = filename.split('/')[-1]
    if leaf in _SKIP_OBJ_LEAVES:
        return None
    ftype = magic.from_file(filename, mime=True)
    if ftype == 'application/x-archive':
        return extract_opcodes_from_arfile(filename)
    if ftype == 'application/x-object':
        with open(filename, 'rb') as f:
            return extract_opcodes(f)
    if ftype in _EXEC_MIMES:
        with open(filename, 'rb') as f:
            # The pre-cleanup call passed ``exapis`` positionally, which
            # landed on ``extract_opcodes``'s ``arfile`` parameter and
            # would later raise TypeError on a ``str + list`` concat. The
            # kwarg form is what info_create.py already uses.
            return extract_opcodes(f, exapis=exapis)
    if ftype in ['text/plain', 'inode/symlink']:
        return None
    logging.error('Not supported file type of %s: %s' % (filename, ftype))
    exit(-1)


def _emit_output(rules_list, output_path):
    """Write the rendered rules to ``output_path``, or stdout if no
    path was given. The literal string ``"no"`` disables output so a
    build harness can measure rule generation in isolation.
    """
    if output_path == 'no':
        return
    if output_path:
        output_rules(rules_list, output_path)
        return
    for rules in rules_list:
        print(rules)


def main():
    parser = argparse.ArgumentParser(prog=sys.argv[0])
    parser.add_argument('--version', '-v', action='version',
                        version='%s %s' % (sys.argv[0], VERSION))
    parser.add_argument('--excluded-api', type=str,
                        help='File listing API names to skip')
    parser.add_argument('--save-api', type=str,
                        help='File name of an api list')
    parser.add_argument('--min', '-m', default=0, type=int,
                        help='Minimum size of a function')
    parser.add_argument('--output_path', '-o',
                        help='YARA file name to be saved')
    parser.add_argument('files', nargs='+',
                        help='File names of archive, object, executable files')
    args = parser.parse_args()

    # Make --min actually take effect; the pre-cleanup assignment created
    # a local that shadowed the module global without ever being read.
    global MINIMUM_PATTERN_LENGTH
    MINIMUM_PATTERN_LENGTH = args.min

    logging.info('Analyzing archive files...')
    exapis = _load_excluded_apis(args.excluded_api)
    tab = {}
    crt_tab = {}
    for filename in args.files:
        result = _process_input_file(filename, exapis)
        if result is None:
            continue
        newtab, new_crt_tab = result
        tab = merge_dicts(tab, newtab)
        crt_tab = merge_dicts(crt_tab, new_crt_tab)

    crt.merge_pairs(tab, crt_tab)

    logging.info('\n\nGenerating a yara file...\n\n')
    rules_list = get_rules(tab)
    _emit_output(rules_list, args.output_path)


if __name__ == '__main__':
    main()

