"""The matcher package: scan an ELF with toolchain YARA rules and rank matches.

Internally split into four cooperating modules:

* :mod:`.yara` -- yara-x compile / scan and the format helpers that
  turn yara-x match objects into the canonical ``{addr: {names, size,
  detected, category}}`` shape every downstream pass consumes.
* :mod:`.state` -- per-binary state computation
  (:func:`.state.compute_target_state`) and mismatch / alias cleanup.
* :mod:`.heuristics` -- the three named heuristics (link-order,
  dependency, consecutive) that lift detection accuracy after the raw
  scan.
* :mod:`.orchestrator` -- ties the three above together via
  :func:`.orchestrator.run_one_with_state` / :func:`.orchestrator.run_one`.
* :mod:`.coverage` -- libc-region anchors, the bytes / function-count
  coverage metrics, and the toolchain-identified threshold gate. The
  module docstring carries the citation for the methodology.
* :mod:`.output` -- per-style rendering of a matched-function table.

The package root retains the cross-module constants (C runtime symbol
lists, top-of-libc anchor list, MAX_PATTERN_LENGTH, STELFTOOLS_PATH) so
the sub-modules can read them with a plain ``from . import …``. The
legacy names ``run_one`` / ``run_one_with_state`` / ``output`` /
``arch_pattern_length`` and the coverage helpers are re-exported here
so existing callers (the IDA / Ghidra plugins and the identify driver)
keep working unchanged.
"""

from pathlib import Path

# Anchor at the repository root (the parent of the stelftools/ package
# directory). Resolves through any symlinks so plugins set up by the
# host tool (IDA/Ghidra) still find the signatures tree.
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


# Sub-module re-exports. The yara helpers are pulled first because the
# sub-module reads MAX_PATTERN_LENGTH / _CRT_*_LIST / STELFTOOLS_PATH
# off this partially-initialised package on its way up; only the names
# the legacy import path exposed are re-bound here.
from .yara import (  # noqa: E402
    compile_yara_file,
    format_match_res,
    merge_functions,
    merge_nomatch_functions,
)
from .coverage import (  # noqa: E402
    calc_libc_to_data_ratio,
    first_libc_anchor,
    get_bot_addr,
    get_top_addr,
    is_toolchain_identified,
    last_libc_anchor,
    libc_func_in_crt_area,
    libc_funcs_in_crt_area,
    library_coverage_by_bytes,
    library_coverage_by_function,
)
from .state import (  # noqa: E402
    compute_target_state,
    del_alias,
    del_mismatch,
    get_alias_list,
)


# Alias-set lookup shared between depend and consecutive heuristics.
# Lives here (rather than in a sibling module) so the heuristics'
# ``from .. import get_func_name_list_alias_list`` resolves to a
# fully-defined attribute by the time the heuristics modules load.
def get_func_name_list_alias_list(multi_func_name_list, alias_list):
    func_name_alias_list = []
    for multi_func_name in multi_func_name_list:
        for alias in alias_list:
            if multi_func_name in alias:
                func_name_alias_list.extend(alias)
    if func_name_alias_list == []:
        func_name_alias_list = multi_func_name_list
    return sorted(set(func_name_alias_list))


# Orchestrator + output re-exports come last because both modules pull
# heuristics, which in turn reach back here for the constants and the
# alias helper defined above.
from .orchestrator import (  # noqa: E402
    arch_pattern_length,
    run_one,
    run_one_with_state,
)
from .output import output  # noqa: E402


# Public surface for ``from stelftools.match import …``. Listed
# explicitly so the re-exports above are not flagged as unused.
__all__ = [
    # constants
    "FINI_CRT_FUNC_LIST",
    "GLIBC_BOT_LIBC_FUNC_LIST",
    "INIT_CRT_FUNC_LIST",
    "MAX_PATTERN_LENGTH",
    "STELFTOOLS_PATH",
    "TOP_LIBC_FUNC_LIST",
    "skip_libc_func",
    # yara helpers
    "compile_yara_file",
    "format_match_res",
    "merge_functions",
    "merge_nomatch_functions",
    # coverage (libc-region anchors + identified-threshold gate)
    "calc_libc_to_data_ratio",
    "first_libc_anchor",
    "get_bot_addr",
    "get_top_addr",
    "is_toolchain_identified",
    "last_libc_anchor",
    "libc_func_in_crt_area",
    "libc_funcs_in_crt_area",
    "library_coverage_by_bytes",
    "library_coverage_by_function",
    # state / cleanup
    "compute_target_state",
    "del_alias",
    "del_mismatch",
    "get_alias_list",
    # orchestrator
    "arch_pattern_length",
    "run_one",
    "run_one_with_state",
    # alias helper (used by heuristics)
    "get_func_name_list_alias_list",
    # output
    "output",
]
