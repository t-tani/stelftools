"""Consecutive-candidate identification pass for the matcher.

Runs once after the linkorder + depend convergence loop. The pass
scans the matched-address table for stretches where the linker-
provided order pins three or more consecutive entries: when three
or more sibling addresses each carry a unique candidate that lines
up with the toolchain's link order, the table's multi-candidate
slots between them get pinned too.

The conservative ``next_i >= 3`` threshold (a 3-function consecutive
run) is the heuristic's main false-positive guard: shorter runs are
common across unrelated function families and would over-narrow.
"""

from .. import _match_array_index, get_func_name_list_alias_list


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
