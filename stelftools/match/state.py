"""Per-binary state computation and mismatch / alias cleanup.

Two responsibilities are bundled here:

* :func:`compute_target_state` reads the ELF once and returns the
  cfg-independent state -- executable-segment table, callsite map,
  instruction bounds, byte buffer, file size, base vaddr. Bruteforce
  drivers compute this once per binary and reuse it across every
  candidate cfg (signature triple) to skip redundant disassembly.
* The cleanup helpers (:func:`del_mismatch`, :func:`get_alias_list`,
  :func:`del_alias`) run between the YARA scan and the heuristics:
  they drop nested / overlapping rule hits and collapse alias
  duplicates so the heuristics see a clean function table.

The small helper :func:`_match_array_index` is exposed at this layer
because both ``heuristics.linkorder`` and ``heuristics.consecutive``
reach back into it.
"""

import os

from elftools.common import exceptions

from ..elf import (
    get_func_addr,
    get_symtab_info_by_capstone,
    get_symtab_info_by_reaelf,
)
from . import (
    FINI_CRT_FUNC_LIST,
    GLIBC_BOT_LIBC_FUNC_LIST,
    INIT_CRT_FUNC_LIST,
    TOP_LIBC_FUNC_LIST,
)
from .yara import get_target_fp


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
