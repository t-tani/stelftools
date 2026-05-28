#! /usr/bin/env python3

import os
import yara_x
import argparse
import json
from pathlib import Path

# Anchor at the repository root (the parent of the stelftools/ package
# directory). Resolves through any symlinks so plugins set up by the
# host tool (IDA/Ghidra) still find the signatures tree. The triple
# parent climb steps out of stelftools/ident/ (this file) -> stelftools/
# (package dir) -> repo root.
STELFTOOLS_PATH = str(Path(__file__).resolve().parent.parent.parent) + "/"

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


# ``yara`` is imported here, after the constants block, because the
# sub-module reads MAX_PATTERN_LENGTH / _CRT_*_LIST / STELFTOOLS_PATH
# off this partially-initialised package on its way up. Only the names
# the orchestrator below calls are re-bound -- consumers that want
# ``get_yara_rule`` / ``yara_matching`` import them from
# ``stelftools.match.yara`` directly.
from .yara import (  # noqa: E402
    compile_yara_file,
    format_match_res,
    marge_functions,
    marge_nomatch_functions,
)


# ---------------------------------------------------------------------------
# Output formatting -- libc-area heuristics that classify which matched
# addresses belong to the linked-in library code and the four output
# styles the CLI exposes (default, compare, ida/ghidra, count).
# ---------------------------------------------------------------------------


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
        pass
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
        matched_func_addrs = []
        for addr in sorted(target_info['functions'].keys()):
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


# State + cleanup live in :mod:`.state`; re-bind here so internal
# callers (run_one, run_one_with_state) keep their existing names. The
# heuristics reach into ``stelftools.match.state`` directly for
# ``_match_array_index``.
from .state import (  # noqa: E402
    compute_target_state,
    del_alias,
    del_mismatch,
    get_alias_list,
)
from .heuristics.linkorder import id_func_name_for_linkorder  # noqa: E402


# ---------------------------------------------------------------------------
# Identification strategy shared helper -- the three heuristics
# (linkorder / depend / consecutive) under
# :mod:`stelftools.match.heuristics` all reach back to
# ``get_func_name_list_alias_list`` to expand a function name into its
# toolchain-recorded alias set before comparing against linker /
# dependency / order signals.
# ---------------------------------------------------------------------------


def get_func_name_list_alias_list(multi_func_name_list, alias_list):
    func_name_alias_list = []
    for multi_func_name in multi_func_name_list:
        for alias in alias_list:
            if multi_func_name in alias:
                func_name_alias_list.extend(alias)
    if func_name_alias_list == []:
        func_name_alias_list = multi_func_name_list
    return sorted(set(func_name_alias_list))


# ``depend`` and ``consecutive`` reach back here for
# get_func_name_list_alias_list, so the imports must follow that
# definition.
from .heuristics.consecutive import multiple_consecutive_candidate_filt  # noqa: E402
from .heuristics.depend import id_func_name_for_depend  # noqa: E402


# ---------------------------------------------------------------------------
# CLI driver + orchestrator -- ``arch_pattern_length`` is the per-arch
# starting bucket size the multi-pass YARA match loop counts down from;
# ``run_one_with_state`` is the library entry point bruteforce drivers
# call; ``main`` is the ``python -m stelftools.match`` route.
# ---------------------------------------------------------------------------


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
        with open(targets[0]) as f:
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
    parser.add_argument('--arch', help = 'target architecture')
    #parser.add_argument('--pattern_length', '-pl', default = 8, type = int)
    parser.add_argument('--output_style', '-o', default='default', help = 'output style')
    parser.add_argument('--virtual_addr', '-va', action='store_true', help = 'output virtual address')
    parser.add_argument('--list_mode', '-lm', action='store_true', help = 'list mode')
    parser.add_argument('--alias_list', '-al', help = 'Enable function name identification by function dependency')
    parser.add_argument('--id_linkorder', '-id_l', help = 'Path to toolchain used to indentify function names by function link order')
    parser.add_argument('--id_depend', '-id_d', help = 'Enable function name identification by function dependency')
    args = parser.parse_args()
    return args

def run_one_with_state(target_state, cfg_info, cfg_path=None):
    # Run a single (target, cfg) ident pass using a pre-computed
    # target_state (see compute_target_state()). The historical
    # multi-pass inner loop is collapsed into one yara-x compile + one
    # scan + length-bucket filtering, which gives byte-identical
    # results to the old N-length loop while cutting per-cfg wall time
    # by 2-7x.
    #
    # When ``cfg_path`` is provided, the yara / alias / depend files are
    # looked up as siblings of the cfg JSON (signatures/<family>/<arch>/
    # layout). Otherwise the caller must seed absolute paths in
    # ``cfg_info`` (the ident-without-cfg CLI path does this).
    if cfg_path is not None:
        cfg_path = Path(cfg_path)
        yara_path        = str(cfg_path.with_suffix('.yara'))
        alias_list_path  = str(cfg_path.with_suffix('.alist'))
        depend_list_path = str(cfg_path.with_suffix('.dlist'))
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


def run_one(target_path, cfg_info, cfg_path=None):
    # Single-shot convenience wrapper. compute_target_state() does the
    # ELF parse + capstone disassembly + call-map extraction; bruteforce
    # drivers should call those two stages separately so target state
    # is shared across every candidate cfg.
    state = compute_target_state(target_path)
    return run_one_with_state(state, cfg_info, cfg_path=cfg_path)


def main():
    args = set_args()

    if args.cfg and os.path.exists(args.cfg):
        with open(args.cfg) as cfg_fp:
            cfg_info = json.load(cfg_fp)
        target_info = run_one(args.target, cfg_info, cfg_path=args.cfg)
    elif args.yara is not None:
        cfg_info = {
            'arch': args.arch,
            'yara_path': args.yara,
            'compiler_path': args.id_linkorder or '',
            'alias_list_path': args.alias_list or '',
            'dependency_list_path': args.id_depend or '',
        }
        target_info = run_one(args.target, cfg_info)
    else:
        print("[ERROR] wrong argument")
        exit(-1)

    output(target_info, args.target, args.output_style)
