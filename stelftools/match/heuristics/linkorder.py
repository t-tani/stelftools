"""Link-order identification pass for ident.

When a YARA rule's signature matches multiple aliased function names,
the link order the toolchain assigns to its archives is a strong
disambiguator. :func:`id_func_name_for_linkorder` drives the
:mod:`stelftools.dub_maker` helper to compile a dummy binary against
the same cross-toolchain and capture the order in which the linker
pulls referenced libfuncs; :func:`link_order_base_identificate` then
walks the matched-address table and narrows each multi-candidate slot
to the names that appear between its top and bottom anchor in the
linker's order.

Inputs come from the caller's matched-function dict, the per-toolchain
alias list, and the link-order list returned by
``DubMaker.get_order_list``. Outputs are the updated function dict and
the number of slots the pass narrowed.
"""

from ... import dub_maker as DubMaker
from .. import (
    INIT_CRT_FUNC_LIST,
    STELFTOOLS_PATH,
    TOP_LIBC_FUNC_LIST,
    _match_array_index,
)


def _match_array_index_list(_list, func_name_list):
    index_list= []
    for func_name in func_name_list:
        index_list.extend(_match_array_index(_list, func_name))
    return sorted(set(index_list))


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
                        and len(set(functions[f_addr]['names']) & set(INIT_CRT_FUNC_LIST)) == 0 : # case of HEURISTIC_FIRST_FUNCTION is empty
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
    with open(link_order_list_path, "w") as f:
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
