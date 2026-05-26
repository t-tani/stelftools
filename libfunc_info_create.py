#!/usr/bin/python3

import io
import multiprocessing
import os
import re
import shutil
import struct
import sys
import hashlib
import logging
import collections
import glob
import argparse
import arpy
import cxxfilt
import magic
from capstone import *
from elftools.elf.constants import *
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

import libfunc_mkrule # make lib func rule script
import libfunc_deparse # parse lib func dependency script
from families import family_for
from pathlib import Path

STELFTOOLS_PATH = str(Path(__file__).resolve().parent) + "/"

MINIMUM_PATTERN_LENGTH = 0
MAXIMUM_PATTERN_LENGTH=15000

def create_toolchain_cfg_file(tc_name, arch, yara_rule_path, tc_compiler_path, alias_list_path, depend_list_path):
    yara_rule_path = yara_rule_path[len(STELFTOOLS_PATH):]
    alias_list_path = alias_list_path[len(STELFTOOLS_PATH):]
    depend_list_path = depend_list_path[len(STELFTOOLS_PATH):]
    cfg_dir = Path(STELFTOOLS_PATH) / "signatures" / "configs" / family_for(tc_name)
    cfg_dir.mkdir(parents=True, exist_ok=True)
    with open(cfg_dir / (tc_name + ".json"), "wt") as f:
        f.write("{\n")
        f.write("  \"name\" : \"" + tc_name + "\",\n")
        f.write("  \"arch\" : \"" + arch + "\",\n")
        f.write("  \"yara_path\" : \"" + yara_rule_path + "\",\n")
        f.write("  \"compiler_path\" : \"" + tc_compiler_path + "\",\n")
        f.write("  \"alias_list_path\" : \"" + alias_list_path + "\",\n")
        f.write("  \"dependency_list_path\" : \"" + depend_list_path + "\"\n")
        f.write("}\n")

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
    ``('error', mime, path)`` for genuinely unsupported types so the
    main process can log and exit. Otherwise returns
    ``(tab, crt_tab, depend)``.

    Must stay picklable for multiprocessing.Pool; relies only on
    module-level state.
    """
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


def mkrule_and_other(tc_path, tc_name, workers=None):
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
    family = family_for(tc_name)
    yara_dir  = Path(STELFTOOLS_PATH) / "signatures" / "yara"           / family
    dlist_dir = Path(STELFTOOLS_PATH) / "signatures" / "deps" / "dlists" / family
    alist_dir = Path(STELFTOOLS_PATH) / "signatures" / "deps" / "aliases" / family
    for d in (yara_dir, dlist_dir, alist_dir):
        d.mkdir(parents=True, exist_ok=True)
    yara_output_path  = str(yara_dir  / (tc_name + ".yara"))
    dlist_output_path = str(dlist_dir / (tc_name + ".dlist"))
    alist_output_path = str(alist_dir / (tc_name + ".alist"))

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
                if result is None:
                    continue
                if isinstance(result, tuple) and result and result[0] == 'error':
                    _, ftype, fname = result
                    logging.error('Not supported file type of %s: %s' % (fname, ftype))
                    exit(-1)
                newtab, new_crt_tab, new_depend = result
                tab = libfunc_mkrule.merge_dicts(tab, newtab)
                crt_tab = libfunc_mkrule.merge_dicts(crt_tab, new_crt_tab)
                depend_list.update(new_depend)
    else:
        for filename in static_lib_file_list:
            result = _process_one_file(filename)
            if result is None:
                continue
            if isinstance(result, tuple) and result and result[0] == 'error':
                _, ftype, fname = result
                logging.error('Not supported file type of %s: %s' % (fname, ftype))
                exit(-1)
            newtab, new_crt_tab, new_depend = result
            tab = libfunc_mkrule.merge_dicts(tab, newtab)
            crt_tab = libfunc_mkrule.merge_dicts(crt_tab, new_crt_tab)
            depend_list.update(new_depend)

    # marge crt opecode
    _tmp_crt_info = {}
    crt_obj_list = ['crti.o', 'crtn.o']
    if len(set(crt_tab.keys()) & set(crt_obj_list)) == len(crt_obj_list):
        crt_func_name_list = []
        # get connect crt function name list
        for info_in_obj in crt_tab['crti.o']:
            crt_func_name_list.append(info_in_obj['name'])
        for crt_obj, crt_info_list in crt_tab.items():
            if crt_obj == 'crti.o':
                for crt_info in crt_info_list:
                    for crt_func_name in crt_func_name_list:
                        if crt_info['name'] == crt_func_name:
                            opecodes_str = crt_info['opecodes']
                            _tmp_crt_info[crt_func_name] = {'i-opecode': opecodes_str}
        for crt_obj, crt_info_list in crt_tab.items():
            if crt_obj == 'crtn.o':
                for crt_info in crt_info_list:
                    for crt_func_name in crt_func_name_list:
                        if crt_info['name'] == crt_func_name:
                            opecodes_str = crt_info['opecodes']
                            _tmp_crt_info[crt_func_name]['n-opecode'] = opecodes_str
        # marge
        marged_crt_func_opecs = {}
        for func_name in _tmp_crt_info.keys():
            for t_opecodes_str in _tmp_crt_info[func_name].values():
                if not func_name in marged_crt_func_opecs.keys():
                    marged_crt_func_opecs[func_name] = t_opecodes_str
                else:
                    marged_crt_func_opecs[func_name] = marged_crt_func_opecs[func_name] + ' [0-12] ' + t_opecodes_str
        for _crt_func_name, _crt_func_opecodes in marged_crt_func_opecs.items():
            if _crt_func_opecodes in tab.keys():
                tab[_crt_func_opecodes] = [
                    tab[_crt_func_opecodes][0],
                    {'name': _crt_func_name, 'type': 'func',
                     'size': len(_crt_func_opecodes.split(' ')), 'exports': [], 'imports': [],
                     'objname': 'crti.o'},
                ]
            else:
                tab[_crt_func_opecodes] = [
                    {'name': _crt_func_name, 'type': 'func',
                     'size': len(_crt_func_opecodes.split(' ')), 'exports': [], 'imports': [],
                     'objname': 'crti.o'},
                ]

    # show shinked functions
    for v in tab.values():
        if v[0]['size'] > MAXIMUM_PATTERN_LENGTH:
            #logging.warning('Shrinked %s: %d -> %d' % (v[0]['name'], v[0]['size'], MAXIMUM_PATTERN_LENGTH))
            continue
    logging.info('\n\nGenerating a yara file...\n\n')
    rules_list = libfunc_mkrule.get_rules(tab)
    libfunc_mkrule.output_rules(rules_list, yara_output_path)

    formatted_depend_data = libfunc_deparse.fmt_depend_data(depend_list)
    libfunc_deparse.output_dlist(formatted_depend_data, dlist_output_path)
    libfunc_deparse.output_alist(formatted_depend_data, alist_output_path)

    return yara_output_path, dlist_output_path, alist_output_path

if __name__ == '__main__':
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
    if args.toolchain_path:
        tc_path = args.toolchain_path
    else:
        tc_path = "/".join(args.compiler_path.split('/')[0:(len(args.compiler_path.split('/'))-2)])
    arch = args.arch

    workers = None if args.workers <= 0 else args.workers
    yara_rule_path, depend_list_path, alias_list_path = mkrule_and_other(tc_path, tc_name, workers=workers)
    if os.path.exists(yara_rule_path):
        print('[successfully created] yara rule : %s' % yara_rule_path)
    if os.path.exists(tc_compiler_path):
        print('[successfully checked] toolchain compiler path : %s' % tc_compiler_path)
    if os.path.exists(depend_list_path):
        print('[successfully created] dependency list : %s' % depend_list_path)
    if os.path.exists(alias_list_path):
        print('[successfully created] alias list : %s' % alias_list_path)

    create_toolchain_cfg_file( \
            tc_name, \
            arch, \
            yara_rule_path, \
            tc_compiler_path, \
            alias_list_path, \
            depend_list_path \
            )
