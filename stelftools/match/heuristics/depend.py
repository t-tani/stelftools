"""Dependency-based identification pass for the matcher.

The generator records, for every library function in a static archive,
which symbols it calls and the relative offset of each call site
(:mod:`stelftools.deparse` writes this as the ``.dlist`` artifact).
When a YARA rule matches multiple aliased function names, the
recorded caller-callee pairs at the right offsets narrow the
candidate set: a "memcpy" candidate is unlikely if the call site at
offset 0x18 is not in any toolchain's memcpy dependency list.

:func:`id_func_name_for_depend` is the entry point. It runs a
caller-side filter (eliminate callee aliases that no caller depends
on) and a callee-side filter (eliminate caller aliases that no
callee chain matches) until both report zero new identifications.

:func:`_load_depend` parses the ``.dlist`` file once per path and
caches the rows plus a caller-alias index; repeated invocations
inside the orchestrator's convergence loop reuse the same parsed
structure.
"""

import sys

from .. import get_func_name_list_alias_list


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
