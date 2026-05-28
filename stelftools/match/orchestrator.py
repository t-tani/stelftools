"""Per-target match orchestration: YARA scan, length-bucket merge, heuristics.

:func:`run_one_with_state` is the library entry point that the identify
driver (and any future caller that scores many configs against the same
binary) calls once per ``(target_state, cfg)`` pair, where ``cfg`` is
a toolchain config JSON. It compiles the ``.yara`` rule set once, scans
the cached target bytes, replays the historical multi-pass merge over a
single materialised match list, then runs the convergence loop of the
link-order and dependency heuristics followed by the consecutive-
candidate pass. :func:`run_one` is the single-shot variant that also
recomputes the per-binary state.

:func:`arch_pattern_length` returns the starting bucket size the
multi-pass merge counts down from. Each architecture has its own value
because the minimum useful YARA-rule pattern length differs with
instruction width: a single ARM/thumb / x86 instruction is 2-4 bytes,
PPC64 is 8 bytes, RISC-V relaxes to 2-4 byte instructions but its
default bucket reflects that the worst-case rule body is sparser.
"""

import os
from pathlib import Path

import yara_x

from .heuristics.consecutive import multiple_consecutive_candidate_filt
from .heuristics.depend import id_func_name_for_depend
from .heuristics.linkorder import id_func_name_for_linkorder
from .state import (
    compute_target_state,
    del_alias,
    del_mismatch,
    get_alias_list,
)
from .yara import (
    compile_yara_file,
    format_match_res,
    merge_functions,
    merge_nomatch_functions,
)


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
            functions = merge_nomatch_functions(_functions, call_map)
        else:
            functions = merge_functions(functions, _functions)
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
    # ELF parse + capstone disassembly + call-map extraction; the
    # multi-config identify driver should call those two stages
    # separately so target state is shared across every candidate cfg.
    state = compute_target_state(target_path)
    return run_one_with_state(state, cfg_info, cfg_path=cfg_path)
