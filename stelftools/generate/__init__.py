#!/usr/bin/python3

import io
import json
import multiprocessing
import os
import sys
import hashlib
import logging
import collections
import glob
import argparse
from pathlib import Path

import arpy
import magic

from . import fetch_opecodes as libfunc_mkrule
from . import deparse as libfunc_deparse
from . import crt
from .. import sigstore
from ..families import family_for


# ---------------------------------------------------------------------------
# Signature output paths -- where the yara / dlist / alist / cfg files
# land for one (toolchain name, arch) pair.
# ---------------------------------------------------------------------------


def signature_dir(tc_name: str, arch: str) -> Path:
    """Per-toolchain output directory: <signatures_root>/<family>/<arch>/."""
    return sigstore.signatures_root() / family_for(tc_name) / arch


def create_toolchain_cfg_file(tc_name, arch, tc_compiler_path):
    """Write the cfg JSON next to its yara / dlist / alist siblings.

    Paths used by ident.py are derived from the cfg file's location at
    load time, so the JSON no longer stores yara_path / alias_list_path /
    dependency_list_path. Only name, arch, and compiler_path remain.
    """
    out_dir = signature_dir(tc_name, arch)
    out_dir.mkdir(parents=True, exist_ok=True)
    cfg = {
        "name": tc_name,
        "arch": arch,
        "compiler_path": tc_compiler_path,
    }
    with open(out_dir / (tc_name + ".json"), "w") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")


# ---------------------------------------------------------------------------
# Static-library discovery -- walk the toolchain tree, deduplicate by
# realpath + size + sha256, return the per-archive worklist that drives
# the rest of the pipeline.
# ---------------------------------------------------------------------------


_STATIC_LIB_EXTS = ('.a', '.o', '.os', '.lo')


def _file_sha256(path, chunk=1 << 16):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            buf = f.read(chunk)
            if not buf:
                break
            h.update(buf)
    return h.digest()


def get_static_lib_file_list(tc_path):
    """Static-library files reachable from ``tc_path``, deduplicated to one visit per content.

    The earlier ``path != realpath(path)`` test combined with a
    symmetric-difference set XOR silently dropped every archive when
    ``tc_path`` was relative (every relative path differs from its
    realpath) or when any parent directory was a symlink (Bootlin ships
    ``lib64 -> lib``). The first dedup pass here indexes by
    :func:`os.path.realpath` so file-symlink aliases (``libm.a ->
    libm-2.39.a``) and directory-symlink aliases (``lib64/foo.a`` vs
    ``lib/foo.a``) collapse to a single entry.

    Bootlin additionally publishes byte-identical copies of several
    archives under separate inodes — for the aarch64/glibc tarball the
    overlap covers libgomp, libstdc++, libstdc++fs, libstdc++exp,
    libsupc++ — and processing each twice ate roughly five minutes of
    the prior run. A second pass groups survivors by file size (free)
    and only hashes within size-collision buckets, so the dedup cost is
    dominated by hashing libstdc++.a once instead of twice.
    """
    seen = {}
    for f in glob.glob(tc_path + '/**', recursive=True):
        if not f.endswith(_STATIC_LIB_EXTS):
            continue
        if not os.path.isfile(f):
            continue
        real = os.path.realpath(f)
        if real not in seen:
            seen[real] = f

    by_size = collections.defaultdict(list)
    for path in seen.values():
        by_size[os.path.getsize(path)].append(path)

    final = []
    for paths in by_size.values():
        if len(paths) == 1:
            final.append(paths[0])
            continue
        by_hash = {}
        for path in paths:
            digest = _file_sha256(path)
            if digest not in by_hash:
                by_hash[digest] = path
        final.extend(by_hash.values())
    return sorted(final)


# ---------------------------------------------------------------------------
# Per-file processing -- libmagic-driven dispatch from one toolchain
# file to (tab, crt_tab, depend) deltas. Workers in the multiprocessing
# pool call into this section; it must stay self-contained on
# module-level state so pickling round-trips cleanly.
# ---------------------------------------------------------------------------


# Toolchain object files that the rule generator skips. crtbegin / Scrt1
# / rcrt1 are dynamic-link helpers whose code is not part of any user
# library; they used to be filtered from the rule pass only and still
# need to feed the dependency analyser to record their callers.
_EXCLUDE_OPECODE_TOPLEVEL = {'Scrt1.o', 'rcrt1.o', 'crtbegin.o', 'crtbeginS.o', 'crtendS.o'}

# Top-level archive that the rule generator does not handle (C++ symbol
# names blow past the YARA identifier-length limits the rule writer
# enforces). Excluded from both passes; libfunc_deparse never had a
# C++ branch either.
_EXCLUDE_BOTH_TOPLEVEL = {'libstdc++.a'}

# Per-archive members the rule generator avoids; the dependency walk
# still descends into them to preserve depend_list parity.
_EXCLUDE_OPECODE_IN_ARCHIVE = {'aeabi_sighandlers.os', 'aeabi_sighandlers.o'}

_EXECUTABLE_MIMES = {
    'application/x-executable',
    'application/x-sharedlib',
    'application/x-pie-executable',
}


def _named_bytesio(data, name):
    """BytesIO wrapper whose ``.name`` attribute satisfies libfunc_mkrule.

    libfunc_mkrule.fetch_opecodes picks up the file name from ``f.header.name``
    (for arpy archive members) or ``f.name`` (for plain files). A bare
    BytesIO has neither, so the rule writer would error out; setting
    ``.name`` matches the plain-file path.
    """
    buf = io.BytesIO(data)
    buf.name = name
    return buf


def _process_one_file(filename):
    """Worker: build the (tab, crt_tab, depend) deltas for a single file.

    Returns ``None`` for files the caller skips (libstdc++.a top-level,
    file types neither archive/object/executable, magic failures), or
    ``('error', message, path)`` for files that the matcher could not
    process (unsupported MIME, or libfunc_mkrule / libfunc_deparse
    hitting an architecture branch that abruptly raises). Otherwise
    returns ``(tab, crt_tab, depend)``.

    Must stay picklable for multiprocessing.Pool; relies only on
    module-level state.

    The outer ``try`` is the load-bearing piece: libfunc_mkrule's
    architecture dispatch calls ``exit(-1)`` on unknown relocation
    types, which raises ``SystemExit``. In a Pool worker that kills
    the process; the Pool then either replaces the worker (which
    picks up the next .o and dies on the same reloc) or stalls in
    ``imap`` forever. Catching here surfaces the failure to the main
    process as a normal error tuple instead.
    """
    try:
        return _process_one_file_inner(filename)
    except SystemExit as exc:
        return ('error', f'matcher exited (code={exc.code})', filename)
    except Exception as exc:
        return ('error', f'{type(exc).__name__}: {exc}', filename)


def _process_one_file_inner(filename):
    leaf = filename.split('/')[-1]
    if leaf in _EXCLUDE_BOTH_TOPLEVEL:
        return None
    try:
        ftype = magic.from_file(filename, mime=True)
    except magic.MagicException:
        return None

    skip_opecode_outer = leaf in _EXCLUDE_OPECODE_TOPLEVEL
    tab = {}
    crt_tab = {}
    depend = {}

    if ftype == 'application/x-archive':
        rel_arfile = leaf
        try:
            ar = arpy.Archive(os.path.abspath(filename))
        except Exception:
            return None
        for of in ar:
            inner_fname = of.header.name.decode('utf-8')
            data = of.read()
            if not data:
                continue
            buf = _named_bytesio(data, inner_fname)
            if inner_fname not in _EXCLUDE_OPECODE_IN_ARCHIVE:
                newtab, new_crt_tab = libfunc_mkrule.fetch_opecodes(buf, arfile=rel_arfile)
                tab = libfunc_mkrule.merge_dicts(tab, newtab)
                crt_tab = libfunc_mkrule.merge_dicts(crt_tab, new_crt_tab)
            buf.seek(0)
            depend.update(libfunc_deparse.func_depend_analy(buf, inner_fname))

    elif ftype == 'application/x-object':
        with open(filename, 'rb') as f:
            data = f.read()
        buf = _named_bytesio(data, filename)
        if not skip_opecode_outer:
            newtab, new_crt_tab = libfunc_mkrule.fetch_opecodes(buf)
            tab = libfunc_mkrule.merge_dicts(tab, newtab)
            crt_tab = libfunc_mkrule.merge_dicts(crt_tab, new_crt_tab)
        buf.seek(0)
        depend.update(libfunc_deparse.func_depend_analy(buf, leaf))

    elif ftype in _EXECUTABLE_MIMES:
        if skip_opecode_outer:
            return None
        with open(filename, 'rb') as f:
            newtab, new_crt_tab = libfunc_mkrule.fetch_opecodes(f, exapis=[])
        tab = libfunc_mkrule.merge_dicts(tab, newtab)
        crt_tab = libfunc_mkrule.merge_dicts(crt_tab, new_crt_tab)

    elif ftype in ('text/plain', 'inode/symlink'):
        return None
    else:
        return ('error', ftype, filename)

    return (tab, crt_tab, depend)


# ---------------------------------------------------------------------------
# Combined pipeline -- orchestrate the per-file calls over the worklist,
# optionally via a multiprocessing pool, merge results, drive the YARA
# / dlist / alist render at the end.
# ---------------------------------------------------------------------------


def _default_worker_count():
    """Half the available CPUs, capped at 8, with a floor of 1.

    The merge step in the main process is also CPU-bound (unpickling +
    dict merges), so leaving headroom for it tends to win over saturating
    every core with workers. The cap reflects diminishing returns past
    eight workers — pyelftools' relocation parsing is the per-archive
    bottleneck and there are around sixty archives in a typical glibc
    toolchain, so wall time floors at roughly one-eighth of serial.
    """
    cpu = os.cpu_count() or 1
    return max(1, min(8, cpu // 2))


def _merge_one_result(result, tab, crt_tab, depend_list):
    """Fold one worker / serial result into the running accumulators.

    Returns the new ``(tab, crt_tab)``; ``depend_list`` is updated in
    place because :class:`dict.update` already has the right merge
    shape for it. ``result`` is whatever :func:`_process_one_file`
    returned:

    - ``None``: file was skipped (libstdc++, plain text, libmagic
      failure). No-op; the accumulators come back unchanged.
    - ``('error', message, filename)``: matcher aborted. Logs and
      exits so the CLI surfaces the failure loudly.
    - ``(newtab, new_crt_tab, new_depend)``: merge the deltas in.

    The merge keeps ``libfunc_mkrule.merge_dicts``'s "new contribution's
    per-key list first" ordering so the rendered YARA rule's
    ``syms[0]`` matches the pre-cleanup output byte-for-byte.
    """
    if result is None:
        return tab, crt_tab
    if isinstance(result, tuple) and result and result[0] == 'error':
        _, msg, fname = result
        logging.error('aborting on %s: %s', fname, msg)
        exit(-1)
    newtab, new_crt_tab, new_depend = result
    tab = libfunc_mkrule.merge_dicts(tab, newtab)
    crt_tab = libfunc_mkrule.merge_dicts(crt_tab, new_crt_tab)
    depend_list.update(new_depend)
    return tab, crt_tab


def mkrule_and_other(tc_path, tc_name, arch, workers=None):
    """Build the yara, dlist, and alist outputs in a single (optionally parallel) file walk.

    The earlier pipeline ran mkrule() to discover opcodes and write the
    yara file, then mkother() walked the same static-library set a
    second time so libfunc_deparse could record dependency edges. Each
    pass opened the same archives and reparsed the same ELFs; on
    bl-stable-2024.05-1/glibc/aarch64 that double work accounted for
    roughly forty percent of the total runtime.

    The combined walk reads each object file (standalone or pulled from
    an archive) into a BytesIO once, then feeds the same buffer through
    libfunc_mkrule.fetch_opecodes and libfunc_deparse.func_depend_analy
    back-to-back with a seek(0) in between. Exclusion rules from the
    original two functions are preserved verbatim — the rule pass still
    skips Scrt1.o / crtbegin*.o / aeabi_sighandlers.o while the depend
    pass descends into them, and both passes skip libstdc++.a.

    When ``workers`` is greater than one, archive-level processing is
    dispatched to a ``multiprocessing.Pool`` and results merged back in
    submission order (``imap`` preserves order even when workers
    complete out of order), so the final tab / depend_list orderings —
    and therefore the rendered yara / dlist / alist — match the serial
    output byte-for-byte. ``workers=None`` consults
    :func:`_default_worker_count`.
    """
    out_dir = signature_dir(tc_name, arch)
    out_dir.mkdir(parents=True, exist_ok=True)
    yara_output_path  = str(out_dir / (tc_name + ".yara"))
    dlist_output_path = str(out_dir / (tc_name + ".dlist"))
    alist_output_path = str(out_dir / (tc_name + ".alist"))

    static_lib_file_list = get_static_lib_file_list(tc_path)

    if workers is None:
        workers = _default_worker_count()

    logging.info('Analyzing archive files with %d worker(s)...', workers)
    tab = {}
    crt_tab = {}
    depend_list = {}

    if workers > 1:
        # chunksize=1 keeps load balancing tight: libc.a (~30 s) would
        # otherwise serialise behind any larger chunk it shared.
        with multiprocessing.Pool(processes=workers) as pool:
            results = pool.imap(_process_one_file, static_lib_file_list, chunksize=1)
            for result in results:
                tab, crt_tab = _merge_one_result(result, tab, crt_tab, depend_list)
    else:
        for filename in static_lib_file_list:
            tab, crt_tab = _merge_one_result(_process_one_file(filename), tab, crt_tab, depend_list)

    crt.merge_pairs(tab, crt_tab)

    logging.info('\n\nGenerating a yara file...\n\n')
    rules_list = libfunc_mkrule.get_rules(tab)
    libfunc_mkrule.output_rules(rules_list, yara_output_path)

    formatted_depend_data = libfunc_deparse.fmt_depend_data(depend_list)
    libfunc_deparse.output_dlist(formatted_depend_data, dlist_output_path)
    libfunc_deparse.output_alist(formatted_depend_data, alist_output_path)

    return yara_output_path, dlist_output_path, alist_output_path


# ---------------------------------------------------------------------------
# CLI driver -- argparse, default tc_path derivation, and the success-line
# print helpers. The stelftools-mkrule console script wires here.
# ---------------------------------------------------------------------------


def _announce_output(label, path, verb='created'):
    """Print one ``[successfully <verb>] <label> : <path>`` line, but
    only if ``path`` actually exists on disk -- a guard against a
    silent ``mkrule_and_other`` failure that returned a path without
    writing the file.
    """
    if os.path.exists(path):
        print('[successfully %s] %s : %s' % (verb, label, path))


def main():
    parser = argparse.ArgumentParser(prog = sys.argv[0])
    parser.add_argument('-name', help = 'Toolchain name')
    parser.add_argument('--toolchain_path', '-tp', help = 'Toolchain path')
    parser.add_argument('--compiler_path', '-cp', help = 'Toolchain compiler path')
    parser.add_argument('-arch', help = 'arch')
    parser.add_argument(
        '--workers', '-j', type=int, default=0,
        help='Worker processes for archive-level parallelism. '
             '0 (default) auto-picks ~half the available CPUs, capped at 8; '
             '1 forces the serial path; values >1 dispatch to a process pool.',
    )
    args = parser.parse_args()

    tc_name = args.name
    tc_compiler_path = args.compiler_path
    # Default --toolchain_path is two directory levels above the
    # compiler binary: typical Bootlin layout is
    # <root>/bin/<triplet>-gcc, so the root is dirname(dirname(...)).
    if args.toolchain_path:
        tc_path = args.toolchain_path
    else:
        tc_path = str(Path(args.compiler_path).parent.parent)
    arch = args.arch

    workers = None if args.workers <= 0 else args.workers
    yara_rule_path, depend_list_path, alias_list_path = mkrule_and_other(
        tc_path, tc_name, arch, workers=workers,
    )
    _announce_output('yara rule', yara_rule_path)
    _announce_output('toolchain compiler path', tc_compiler_path, verb='checked')
    _announce_output('dependency list', depend_list_path)
    _announce_output('alias list', alias_list_path)

    create_toolchain_cfg_file(tc_name, arch, tc_compiler_path)


if __name__ == '__main__':
    main()
