"""CRT (init / fini) glue handling.

The C startup glue is split across two toolchain objects: crti.o
carries the ``_init`` / ``_fini`` function prologues, crtn.o carries
the matching epilogues, and the link step splices ABI metadata or a
short thunk between them. This module owns the two-phase handling
that turns the pair into a single YARA-rule pattern:

- :func:`collect_funcs` runs per-file inside ``fetch_opecodes``. It
  picks up each crti.o / crtn.o member's ``_init`` / ``_fini``
  opecode list and stashes it under the leaf name (``crti.o`` or
  ``crtn.o``) so the trailing merge knows which half it has.
- :func:`merge_pairs` runs after every input has been walked. It
  knits matching ``(crti.o, crtn.o)`` halves into one
  ``[0-12]``-spanning rule that matches the linked binary
  regardless of how much glue the loader spliced between them.
"""

# Function names emitted by crti.o / crtn.o that the loader calls. The
# leading-dot / leading-underscore variants reflect what toolchains in
# our corpus actually emit; the rule generator drops literal matches on
# these from the regular symbol loop so the merged pattern below is the
# only rule that fires for them.
INIT_FINI_FUNC_LIST = [
    '.init', '_init', '__init',
    '.fini', '_fini', '__fini',
]


def collect_funcs(textsec, fname):
    """Pick up ``_init`` / ``_fini`` entries from a crti.o / crtn.o input.

    Returns ``{leaf: [entry, ...]}`` where ``leaf`` is ``crti.o`` or
    ``crtn.o``; an empty dict for any other input. ``entry`` carries
    the function name, the byte size of its section, and the joined
    opecode hex string so :func:`merge_pairs` can paste the two halves
    together later without re-reading the file.
    """
    out = {}
    leaf = fname.split('/')[-1]
    if leaf not in ['crti.o', 'crtn.o']:
        return out
    for sym_name in textsec.keys():
        if sym_name not in INIT_FINI_FUNC_LIST:
            continue
        opecodes_str = ' '.join(textsec[sym_name])
        entry = {
            'name': sym_name, 'type': 'func',
            'size': len(textsec[sym_name]),
            'exports': [], 'imports': [],
            'opecodes': opecodes_str,
        }
        out.setdefault(leaf, []).append(entry)
    return out


def merge_pairs(tab, crt_tab):
    """Knit each ``(crti.o, crtn.o)`` function pair into one tab entry.

    Only runs when both halves are present. The ``[0-12]`` window
    between the two halves matches whatever code the linker may splice
    between the crti and crtn glue -- typically a ``.note.ABI-tag``
    section or a short init thunk. The merged pattern overrides any
    pre-existing tab entry produced by the per-file pipeline (the
    pre-existing entry stays as the bucket's first member, and the
    merged crti/crtn rule lands second).
    """
    if not (set(crt_tab.keys()) >= {'crti.o', 'crtn.o'}):
        return
    crt_func_name_list = [info['name'] for info in crt_tab['crti.o']]
    half_opecodes = {}
    for slot, leaf in (('i-opecode', 'crti.o'), ('n-opecode', 'crtn.o')):
        for info in crt_tab.get(leaf, []):
            if info['name'] in crt_func_name_list:
                half_opecodes.setdefault(info['name'], {})[slot] = info['opecodes']

    merged = {}
    for func_name, halves in half_opecodes.items():
        joined = ''
        for opecodes_str in halves.values():
            joined = opecodes_str if not joined else joined + ' [0-12] ' + opecodes_str
        merged[func_name] = joined

    for func_name, joined in merged.items():
        entry = {
            'name': func_name, 'type': 'func',
            'size': len(joined.split(' ')),
            'exports': [], 'imports': [],
            'objname': 'crti.o',
        }
        if joined in tab:
            tab[joined] = [tab[joined][0], entry]
        else:
            tab[joined] = [entry]
