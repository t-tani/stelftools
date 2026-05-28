"""Render the matched-function table in one of five output styles.

The orchestrator (:mod:`.orchestrator`) returns a per-binary
``target_info`` dict; this module turns that dict into stdout text. The
libc-region anchors and the C-runtime-area exclusion come from
:mod:`.coverage`; this module owns nothing but the per-style rendering.

Modes:

* ``default`` -- one line per function ``<addr> <name1,name2,...>``;
  every entry is printed regardless of libc region.
* ``compare`` / ``ida`` / ``ghidra`` -- only libc-region matches with
  a non-empty name. The separator between aliased names is ``,`` for
  ``compare`` and ``_OR_`` for ``ida`` / ``ghidra`` (the latter pair
  is consumed by the plugin overlay paths that cannot keep commas in
  symbol names). Returns the rendered ``{addr: {'names': str}}`` map
  so callers (the IDA plugin) can apply it as symbol metadata.
* ``count`` -- one line ``<path> : <function-count>``.
* ``no`` -- no output. The multi-config identify path uses this when
  only the ranked config list is wanted (e.g. with ``--verdict-only``).
"""

from . import skip_libc_func
from .coverage import get_bot_addr, get_top_addr, libc_func_in_crt_area


def output(target_info, target_path, output_mode):
    libc_area_top = get_top_addr(target_info['functions'], skip_libc_func)
    libc_area_bot = get_bot_addr(target_info['functions'])
    skip_func_addr = libc_func_in_crt_area(target_info['functions'], libc_area_top, skip_libc_func)

    if output_mode in ['no']:
        pass
    elif output_mode in ['compare', 'ida', 'ghidra']:
        match_info = {}
        matched_func_addrs = []
        for addr in sorted(target_info['functions'].keys()):
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
