#!/usr/bin/env python3
# Identify which toolchain a target ELF was built with by running
# func_ident.run_one() against every toolchain config whose declared
# arch matches the target. lief tells us arch/bit/endian; for dynamic
# binaries the .interp section additionally pins the libc family so we
# can drop ~75% of the configs that would never match.
#
# Runs in-process — the original implementation forked
# `python3 func_ident.py` per config and paid the Python startup cost
# (~150 ms × ~100 configs = ~15s) on every invocation.

import argparse
import glob
import json
import logging
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import lief

# Send progress to stderr with a HH:MM:SS timestamp. Logging handlers
# flush after every record, so the per-cfg lines remain visible even
# when stderr is redirected to a file or piped.
log = logging.getLogger('bruteforce')
_handler = logging.StreamHandler(sys.stderr)
_handler.setFormatter(logging.Formatter(
    fmt='%(asctime)s  %(message)s',
    datefmt='%H:%M:%S',
))
log.addHandler(_handler)
log.setLevel(logging.INFO)

# Make `import func_ident` work whether this script is invoked from the
# stelftools directory directly or from elsewhere.
_THIS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_THIS_DIR))
import func_ident  # noqa: E402

TOOLCHAIN_CONFIG_DIR = _THIS_DIR / "signatures" / "configs"


def set_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-arch', help='comma-separated arch shortlist, '
                        'or "AUTO" / omitted to derive from the ELF header')
    parser.add_argument('-target', help='target binary path', required=True)
    parser.add_argument('-libc', help='comma-separated libc family shortlist '
                        '(glibc, musl, uclibc); "AUTO" / omitted to derive '
                        'from .interp (dynamic only)')
    parser.add_argument('-j', '--jobs', type=int,
                        default=min(8, os.cpu_count() or 1),
                        help='worker processes for parallel scoring '
                             '(default: min(8, cpu_count); set 1 to disable)')
    parser.add_argument('-verbose', '-v', action='store_true')
    return parser.parse_args()


# Worker-side global, populated once per worker by _init_worker. Holds
# the cfg-independent target state so each task in the pool only ships
# the cfg_info dict over the pickle boundary.
_WORKER_STATE = None


def _init_worker(target_state):
    global _WORKER_STATE
    _WORKER_STATE = target_state


def _score_cfg(arg):
    idx, cfg_path, cfg_info = arg
    try:
        target_info = func_ident.run_one_with_state(
            _WORKER_STATE, cfg_info, relative_paths=True)
    except Exception as exc:
        return idx, cfg_path, None, repr(exc)
    names = set()
    for addr, info in target_info['functions'].items():
        if info.get('names') and info['names'] != ['']:
            names.add(','.join(sorted(info['names'])))
    return idx, cfg_path, len(names), None


def lief_arch_candidates(target_path):
    # Map a LIEF machine_type to the set of arch labels that appear as
    # `arch` fields in signatures/configs/**/*.json. Keep parity with the
    # original mapping so the candidate set does not shrink silently.
    b = lief.parse(target_path)
    # Strip "ARCH." prefix and normalise to uppercase — LIEF 0.16+
    # uppercased some labels (i386 -> I386, x86_64 -> X86_64,
    # ARCH_68K -> M68K) and uses CLASS.ELF32 instead of the old
    # ELF_CLASS.CLASS32 form. Normalising lets a single branch handle
    # both spellings.
    machine = str(b.header.machine_type).rsplit('.', 1)[-1].upper()
    iclass  = str(b.header.identity_class).rsplit('.', 1)[-1].upper()
    idata   = str(b.header.identity_data).rsplit('.', 1)[-1].upper()
    is_32bit = iclass in ('CLASS32', 'ELF32')
    is_le    = idata == 'LSB'

    if machine == 'AARCH64':
        return ['arm64', 'AARCH64', 'aarch64']
    if machine == 'ARM':
        return ['arm', 'armv4l', 'armv4eb', 'armv4tl', 'armv5l',
                'armv5-eabi', 'armv6l', 'armv6-eabihf',
                'armv7l', 'armv7-eabihf', 'armv7m']
    if machine in ('M68K', 'ARCH_68K'):
        return ['m68k', 'm68k-q800', 'm68k-mcf', 'm68k-mcf5208', 'm68000']
    if machine == 'MIPS':
        if is_32bit:
            return ['mipsel', 'mips32el'] if is_le else ['mips', 'mips32']
        return ['mips64el'] if is_le else ['mips64']
    if machine == 'PPC':
        return ['powerpc', 'powerpc-440fp', 'powerpc-e300c3',
                'powerpc-e500mc', 'ppc']
    if machine == 'PPC64':
        return ['ppc64', 'powerpc64', 'powerpc64-e6500', 'powerpc64-pwoer8']
    if machine == 'SH':
        return ['sh2', 'sh2eb', 'sh2elf', 'sh4']
    if machine == 'SPARC':
        return ['sparc']
    if machine == 'SPARCV9':
        return ['sparc64']
    if machine == 'I386':
        return ['i386', 'i486', 'i586', 'i686', 'x86', 'x86-core2', 'x86-i686']
    if machine == 'X86_64':
        return ['x86_64', 'amd64', 'x86-64', 'x86-64-core-i7']
    if machine == 'RISCV':
        return ['risc-v', 'riscv', 'risc-v-32', 'risc-v-64']
    raise SystemExit(f'[error] Unknown architecture {machine} : {target_path}')


def lief_libc_family(target_path):
    # Read the dynamic loader path from .interp. Returns one of
    # 'glibc' / 'musl' / 'uclibc' / None. Static binaries return None
    # (no .interp, no pruning hint).
    try:
        b = lief.parse(target_path)
    except Exception:
        return None
    if b is None:
        return None
    # LIEF exposes .interp via Binary.interpreter (string) when present.
    interp = getattr(b, 'interpreter', '') or ''
    if not interp:
        # Older LIEF versions expose it differently; fall back to the
        # PT_INTERP segment data.
        for seg in b.segments:
            if str(seg.type).rsplit('.', 1)[-1].upper() == 'INTERP':
                interp = bytes(seg.content).rstrip(b'\x00').decode(
                    'latin1', errors='ignore')
                break
    if not interp:
        return None
    interp_lc = interp.lower()
    if 'uclibc' in interp_lc:
        return 'uclibc'
    if 'musl' in interp_lc:
        return 'musl'
    if 'ld-linux' in interp_lc or interp.endswith('ld.so.1') \
            or interp.endswith('ld.so.2') or 'ld-2.' in interp_lc:
        return 'glibc'
    return None


# Toolchain config name → libc family. al-/fl-/ucli-pub- are all
# uClibc-based by design; bl-/br-/binutils- encode the libc in the name.
def cfg_libc_family(cfg_name):
    if cfg_name.startswith('al-') or cfg_name.startswith('fl-') \
            or cfg_name.startswith('ucli-pub-'):
        return 'uclibc'
    for fam in ('glibc', 'musl', 'uclibc'):
        if f'_{fam}_' in cfg_name or f'_{fam}-' in cfg_name:
            return fam
    return None  # unknown — keep as a candidate


# Sort key for the candidate cfg list — preserves the README's
# "try these toolchain families first" recommendation so the first cfg
# returning the best score is found earlier under -v false (default).
_FAMILY_PRIORITY = {'fl-': 0, 'al-': 1, 'bl-': 2, 'br-': 3, 'ucli-pub-': 4}


def _cfg_sort_key(cfg_path):
    name = os.path.basename(cfg_path)
    for prefix, pri in _FAMILY_PRIORITY.items():
        if name.startswith(prefix):
            return (pri, name)
    return (99, name)


def candidate_cfgs(target_path, arch_filter, libc_filter):
    cfgs = []
    # signatures/configs/ is partitioned per family; recurse so all
    # toolchains contribute candidates regardless of subdirectory.
    for cfg_path in sorted(glob.glob(str(TOOLCHAIN_CONFIG_DIR / "**" / "*.json"), recursive=True),
                           key=_cfg_sort_key):
        with open(cfg_path) as f:
            info = json.load(f)
        if info['arch'] not in arch_filter:
            continue
        if libc_filter is not None:
            fam = cfg_libc_family(os.path.basename(cfg_path))
            # Keep cfgs whose libc family is unknown (None) — better to
            # over-include than to silently drop a viable candidate.
            if fam is not None and fam not in libc_filter:
                continue
        cfgs.append((cfg_path, info))
    return cfgs


def _format_eta(elapsed, idx, total):
    if idx <= 0:
        return '?'
    remaining = elapsed * (total - idx) / idx
    return f'{int(remaining // 60):d}m{int(remaining % 60):02d}s'


def main():
    args = set_args()
    target_path = args.target

    # arch shortlist: explicit -arch wins; otherwise lief derives it
    if args.arch and args.arch != 'AUTO':
        arch_filter = args.arch.split(',')
    else:
        arch_filter = lief_arch_candidates(target_path)
    log.info('target=%s', target_path)
    log.info('arch candidates: %s', arch_filter)

    # libc shortlist: explicit -libc wins; otherwise .interp pins it
    if args.libc and args.libc != 'AUTO':
        libc_filter = set(args.libc.split(','))
    else:
        fam = lief_libc_family(target_path)
        libc_filter = {fam} if fam else None
    log.info('libc family: %s', libc_filter or 'unknown (no pruning)')

    cfgs = candidate_cfgs(target_path, arch_filter, libc_filter)
    log.info('%d cfg(s) after arch+libc filter', len(cfgs))
    if not cfgs:
        log.error('no signatures/configs entry matches the target')
        return 1

    # Compute target-side state (ELF parse + capstone disassembly +
    # call-site map) once and reuse across every candidate cfg.
    log.info('precomputing target state')
    t_state = time.time()
    target_state = func_ident.compute_target_state(target_path)
    log.info('target state ready in %.2fs (text region %d bytes)',
             time.time() - t_state, target_state['target_size'])

    jobs = max(1, args.jobs)
    tasks = [(idx, cfg_path, cfg_info)
             for idx, (cfg_path, cfg_info) in enumerate(cfgs, 1)]
    match_num_list = []
    best_so_far = (0, None)  # (score, cfg_basename)
    t0 = time.time()
    completed = 0

    if jobs == 1:
        # Serial path keeps deterministic ordering and is handy when
        # debugging — set -j 1.
        _init_worker(target_state)
        results = (_score_cfg(t) for t in tasks)
        def stream(): yield from results
    else:
        # yara-x's Python binding does not release the GIL during
        # compile/scan, so threads would not help. Use a process pool
        # and ship the bulky target_state once per worker via initargs
        # rather than per task.
        log.info('scoring %d cfgs across %d worker processes',
                 len(tasks), jobs)
        pool = ProcessPoolExecutor(max_workers=jobs,
                                    initializer=_init_worker,
                                    initargs=(target_state,))
        futures = [pool.submit(_score_cfg, t) for t in tasks]
        def stream():
            try:
                for fut in as_completed(futures):
                    yield fut.result()
            finally:
                pool.shutdown(wait=False, cancel_futures=True)

    for idx, cfg_path, score, err in stream():
        cfg_name = os.path.basename(cfg_path)
        completed += 1
        elapsed = time.time() - t0
        if err is not None:
            log.warning('[%3d/%3d] %-44s FAILED: %s',
                        idx, len(tasks), cfg_name, err)
            continue
        match_num_list.append((cfg_path, score))
        if score > best_so_far[0]:
            best_so_far = (score, cfg_name)
        log.info('[%3d/%3d done=%3d] %-44s matches=%4d  '
                 'elapsed=%6.1fs  eta=%s  best_so_far=%d (%s)',
                 idx, len(tasks), completed, cfg_name, score,
                 elapsed,
                 _format_eta(elapsed, completed, len(tasks)),
                 best_so_far[0], best_so_far[1])

    if not match_num_list:
        log.error('every candidate cfg errored out')
        return 1

    match_num_list.sort(key=lambda x: x[1], reverse=True)
    best = match_num_list[0][1]
    log.info('---- final ranking ----')
    if args.verbose:
        print(f'Number of most matched functions: {best}')
        print('Candidates for toolchain ->')
        for cfg_path, n in match_num_list:
            print(f'{target_path} : {cfg_path} : {n}')
    else:
        for cfg_path, n in match_num_list:
            if n == best:
                print(f'{target_path} : {cfg_path} : {n}')
                return 0
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
