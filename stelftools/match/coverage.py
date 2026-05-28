"""Library-function coverage and the toolchain-identified gate.

A toolchain is reported as identified for a target when the fraction of
its library functions that stelftools matches reaches a threshold.
Two coverage definitions are available:

* :func:`library_coverage_by_function` -- identified libc functions
  divided by libc functions present in the binary. This is the default
  and the figure stelftools reports.
* :func:`library_coverage_by_bytes` -- matched libc-region bytes
  divided by total libc-region bytes. An older byte-level
  approximation, kept for backward compatibility and selectable via
  the CLI ``--coverage-metric`` flag.

The libc region is bounded by :func:`first_libc_anchor` /
:func:`last_libc_anchor`, which exploit the GNU linker's fixed emission
order: C runtime (CRT) prologue objects (crt1, crti, crtbeginT), then
program-defined functions, then the libc archive, then the CRT epilogue
(crtend, crtn). :func:`libc_funcs_in_crt_area` drops libc rule hits
that landed in the prologue by mistake.

The default threshold is 0.9 (``--strict`` raises it to 1.0). The
research background behind the coverage definition and the threshold
values is mapped in docs/paper_to_code.md.

Legacy spellings ``get_top_addr`` / ``get_bot_addr`` /
``libc_func_in_crt_area`` / ``calc_libc_to_data_ratio`` are retained as
aliases at the bottom of the module so the existing ``match.output``
pipeline and out-of-tree callers keep working unchanged.
"""

from . import (
    FINI_CRT_FUNC_LIST,
    GLIBC_BOT_LIBC_FUNC_LIST,
    INIT_CRT_FUNC_LIST,
    TOP_LIBC_FUNC_LIST,
    skip_libc_func as _DEFAULT_SKIP_LIBC_FUNC,
)


def first_libc_anchor(functions, skip_libc_func=_DEFAULT_SKIP_LIBC_FUNC):
    """Address of the first library function after the C runtime prologue.

    The GNU linker emits C runtime objects (crt1, crti, crtbeginT)
    first, then program-defined functions, then the libc archive, then
    the C runtime epilogue. The first matched function whose names land
    outside ``INIT_CRT_FUNC_LIST`` and outside ``skip_libc_func`` while
    landing inside ``TOP_LIBC_FUNC_LIST`` — and whose body is at least
    10 bytes — is the anchor. Returns 0 when no anchor is found. The
    three name lists are package-level constants defined in
    :mod:`stelftools.match`.
    """
    top_addr = 0
    for _addr in sorted(functions.keys()):
        names_set = set(functions[_addr]['names'])
        if len(names_set & set(INIT_CRT_FUNC_LIST)) == 0 \
                and len(names_set & set(skip_libc_func)) == 0 \
                and len(names_set & set(TOP_LIBC_FUNC_LIST)) >= 1 \
                and functions[_addr]['size'] >= 10:
            top_addr = _addr
            break
    return top_addr


def last_libc_anchor(functions):
    """Address just past the last library function before the C runtime epilogue.

    Prefers a match in ``FINI_CRT_FUNC_LIST``; falls back to
    ``GLIBC_BOT_LIBC_FUNC_LIST`` (the GLIBC ``free_mem`` epilogue) and
    then to the last matched address. Returns 0 only when the function
    table is empty. Both name lists are defined in
    :mod:`stelftools.match`.
    """
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
    return bot_addr


def libc_funcs_in_crt_area(functions, libc_area_top, skip_libc_func=_DEFAULT_SKIP_LIBC_FUNC):
    """Addresses inside the C runtime prologue whose YARA hits look like libc.

    A libc rule occasionally fires on a C runtime symbol (a stub the
    linker emitted in front of the libc region). Those addresses are
    excluded from the libc region's coverage tally so the metric
    reflects real libc matches.
    """
    skip_func_addr = []
    for _addr in sorted(functions.keys()):
        if _addr < libc_area_top:
            if len(set(functions[_addr]['names']) & set(skip_libc_func)) == len(set(functions[_addr]['names'])) \
                    or len(set(functions[_addr]['names']) & set(INIT_CRT_FUNC_LIST + FINI_CRT_FUNC_LIST)) == len(set(functions[_addr]['names'])):
                skip_func_addr.append(_addr)
    return skip_func_addr


def library_coverage_by_bytes(target_info, libc_area_top, libc_area_bot, skip_func_addr):
    """Bytes-based coverage: matched libc bytes / total libc-region bytes.

    Returns ``(ratio, target_area)`` where ``target_area`` is a per-byte
    list whose entries are the matched ``names`` list (or 0 for an
    unmatched byte). The per-byte map is retained for callers that
    render the libc region in compare / ida / ghidra output modes; the
    ratio is the only value used by :func:`is_toolchain_identified` when
    ``--coverage-metric=bytes`` is selected.
    """
    func_num = 0
    target_area = []
    for i in range(target_info['size']):
        target_area.append(0)
    for addr in sorted(target_info['functions'].keys()):
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
    for libc_area_hex in target_area[ \
            libc_area_top - target_info['base_vaddr']:libc_area_bot + 1 - target_info['base_vaddr']\
            ]:
        if libc_area_hex == 0:
            no_match_area += 1
    if (libc_area_bot - libc_area_top) == 0:
        return 0.00, [0x0, 0x0]
    bin_to_libc_ratio = 1 - (no_match_area / (libc_area_bot - libc_area_top + 1))
    return bin_to_libc_ratio, target_area


def library_coverage_by_function(functions, libc_area_top, libc_area_bot, skip_func_addr):
    """Function-count coverage: identified libc functions / functions in the libc region.

    Counts addresses in ``[libc_area_top, libc_area_bot]`` (excluding the
    CRT-area false-positive list) whose ``names`` entry is a non-empty
    library-function tag, divided by every address present in that
    region. Program-defined gaps lower the ratio. This is the metric
    the toolchain-identified gate compares against the threshold.

    Returns ``(ratio, matched, total)`` so callers can both gate on the
    ratio and report the raw counts.
    """
    if libc_area_bot - libc_area_top <= 0:
        return 0.0, 0, 0
    total = 0
    matched = 0
    for addr in sorted(functions.keys()):
        if addr in skip_func_addr:
            continue
        if libc_area_top != 0 and addr < libc_area_top:
            continue
        if libc_area_bot != 0 and addr > libc_area_bot:
            continue
        total += 1
        names = functions[addr].get('names') or []
        if names and names != ['']:
            matched += 1
    if total == 0:
        return 0.0, 0, 0
    return matched / total, matched, total


# A toolchain is reported identified when library-function coverage
# reaches this threshold. 0.9 is the default because real-world
# stripped / packed samples rarely reach 100% even when the top-ranked
# cfg is correct; ``--strict`` (or ``--threshold 1.0``) requires a full
# match. See docs/paper_to_code.md for the rationale behind both values.
TOOLCHAIN_IDENTIFIED_THRESHOLD = 0.9


def is_toolchain_identified(coverage, threshold=TOOLCHAIN_IDENTIFIED_THRESHOLD):
    """Return True when ``coverage`` meets or exceeds the threshold."""
    return coverage >= threshold


# Legacy spellings retained for the internal output() pipeline and
# out-of-tree callers. New code should call the descriptive names above.
get_top_addr = first_libc_anchor
get_bot_addr = last_libc_anchor
libc_func_in_crt_area = libc_funcs_in_crt_area
calc_libc_to_data_ratio = library_coverage_by_bytes
