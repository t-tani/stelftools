"""Drop candidate groups that fire at more than one address.

A static link pulls an archive member in at most once, so one library
function has one address. Position-independent MIPS code masks a whole
instruction at each GOT reference, which leaves a short call wrapper with no
identity of its own: every wrapper of that shape in the binary matches the
rule, application code included. Such a group names no function, so it is
reset to the unmatched shape `merge_nomatch_functions` gives a bare call
target. The price is a real function among the sites losing its name; a name
that is missing is a gap, a name that is wrong is a false lead.

Opt-in per signature (`unique_site_only` in the cfg JSON).
"""

from collections import Counter


def _group(info):
    return frozenset(n for n in info.get('names') or [] if n)


def drop_multi_site_groups(functions):
    sites = Counter(_group(info) for info in functions.values() if _group(info))
    for info in functions.values():
        group = _group(info)
        if group and sites[group] > 1:
            info.update({'names': [''], 'size': 0, 'detected': True, 'category': 'unmatch'})
    return functions
