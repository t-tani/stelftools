#! /usr/bin/env python3

import sys
import os
import yara_x
import argparse
import json
from pathlib import Path

from elftools.common import exceptions

from ..elf import (
    get_func_addr,
    get_symtab_info_by_capstone,
    get_symtab_info_by_reaelf,
)

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
# ``stelftools.ident.yara`` directly.
from .yara import (  # noqa: E402
    compile_yara_file,
    format_match_res,
    get_target_fp,
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




# ---------------------------------------------------------------------------
# Target state + mismatch / alias cleanup -- compute_target_state caches
# the cfg-independent per-binary state for the bruteforce driver;
# del_mismatch drops nested / overlapping rule hits; the alias passes
# strip duplicate names recorded in the per-toolchain ``.alist``.
# ---------------------------------------------------------------------------


def compute_target_state(target_path):
    # Compute the target-side state used by run_one_with_state():
    # the executable-segment table, callsite map, instruction bounds,
    # and file size. Cfg-independent — bruteforce drivers compute it
    # once per binary and reuse across every candidate cfg.
    target = get_target_fp(target_path)
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
    with open(alias_list_path) as al_fp:
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

def _match_array_index(_list, func_name):
    return sorted(set([index for index, _func_name in enumerate(_list) if _func_name == func_name]))


# ``linkorder`` reaches back here for _match_array_index, so the import
# must follow that definition.
from .linkorder import id_func_name_for_linkorder  # noqa: E402


# ---------------------------------------------------------------------------
# Identification strategies (dependency + consecutive-candidate) --
# ``run_one_with_state`` loops over the linkorder + depend pair until
# both report zero new identifications; the consecutive-candidate
# filter then runs once at the end. Each pass narrows the alias
# multiset on a matched address using a different external signal:
# recorded caller-callee dependencies from the corpus build (depend),
# or runs of consecutive single-candidate addresses (consecutive).
# The link-order pass lives in :mod:`stelftools.ident.linkorder`.
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
        with open(d_list_path) as d_list:
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


# ---------------------------------------------------------------------------
# CLI driver + orchestrator -- ``arch_pattern_length`` is the per-arch
# starting bucket size the multi-pass YARA match loop counts down from;
# ``run_one_with_state`` is the library entry point bruteforce drivers
# call; ``main`` is the legacy ``python -m stelftools.ident`` route.
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
