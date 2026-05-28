"""``stelftools identify`` -- match an ELF against toolchain signatures.

Throughout this module, a *cfg* is the JSON file under
``signatures/<family>/<arch>/<name>.json`` that points at one
toolchain's YARA rules, alias list (``.alist``), and dependency list
(``.dlist``).

The verb covers two modes:

* ``--cfg PATH`` -- single-toolchain mode. Runs the matcher with the
  given cfg, then prints the coverage-based verdict and the per-function
  listing in the requested ``-o`` style.
* default -- multi-toolchain mode. Walks every cfg whose declared
  architecture and (when statically determinable) libc family match
  the binary, ranks them by score (unique names matched), re-evaluates
  the top cfg to derive coverage, and reports identified / unidentified.

The identified gate has two settings:

* Default ``--threshold 0.9`` -- report identified when at least 90% of
  the binary's library functions match. Useful on noisy real-world
  samples where a full match is rarely achieved.
* ``--strict`` (= ``--threshold 1.0``) -- require every library function
  to match before reporting identified.

The lief-driven architecture / libc detection prunes the candidate
set: the ELF header gives the architecture, and the ``.interp``
section (the dynamic loader path, present in dynamically-linked
binaries) names the libc family. A binary with a known interpreter
never pays the per-cfg cost of cfgs from a different libc family.
``-j`` controls how many worker processes score cfgs in parallel.
"""

import argparse
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
log = logging.getLogger('identify')
_handler = logging.StreamHandler(sys.stderr)
_handler.setFormatter(logging.Formatter(
    fmt='%(asctime)s  %(message)s',
    datefmt='%H:%M:%S',
))
log.addHandler(_handler)
log.setLevel(logging.INFO)

from .. import match  # noqa: E402
from .. import sigstore  # noqa: E402
from ..match import skip_libc_func  # noqa: E402
from ..match.coverage import (  # noqa: E402
    TOOLCHAIN_IDENTIFIED_THRESHOLD,
    first_libc_anchor,
    is_toolchain_identified,
    last_libc_anchor,
    libc_funcs_in_crt_area,
    library_coverage_by_bytes,
    library_coverage_by_function,
)
from ..match.output import output as render_output  # noqa: E402

# Each toolchain's cfg JSON, YARA rules, dependency list (.dlist), and
# alias list (.alist) all sit together under
# <signatures_root>/<family>/<arch>/. The root itself is resolved
# per-call by sigstore so $STELFTOOLS_SIGNATURES_DIR set in the
# environment takes effect even when this module was imported before
# the variable was exported.


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
        target_info = match.run_one_with_state(
            _WORKER_STATE, cfg_info, cfg_path=cfg_path)
    except Exception as exc:
        return idx, cfg_path, None, repr(exc)
    names = set()
    for addr, info in target_info['functions'].items():
        if info.get('names') and info['names'] != ['']:
            names.add(','.join(sorted(info['names'])))
    return idx, cfg_path, len(names), None


# Inverse map from a signatures/<family>/<arch>/ directory name to the
# set of arch labels that a LIEF-detected ELF should match against. The
# table is the single source of truth shared with the publish helper
# (tools/ci/publish_signatures_release.py) so manifest entries' lief
# match lists stay in lockstep with what the matcher actually selects.
#
# Each row is (machine_type predicate, candidate list). For MIPS the
# bit-width and endianness flow into a four-row expansion below.
_LIEF_ARCH_GROUPS = [
    (lambda m, b32, le: m == 'AARCH64',
        ['arm64', 'AARCH64', 'aarch64']),
    (lambda m, b32, le: m == 'ARM',
        ['arm', 'armv4l', 'armv4eb', 'armv4tl', 'armv5l',
         'armv5-eabi', 'armv6l', 'armv6-eabihf',
         'armv7l', 'armv7-eabihf', 'armv7m']),
    (lambda m, b32, le: m in ('M68K', 'ARCH_68K'),
        ['m68k', 'm68k-q800', 'm68k-mcf', 'm68k-mcf5208', 'm68000']),
    (lambda m, b32, le: m == 'MIPS' and b32 and le,
        ['mipsel', 'mips32el']),
    (lambda m, b32, le: m == 'MIPS' and b32 and not le,
        ['mips', 'mips32']),
    (lambda m, b32, le: m == 'MIPS' and not b32 and le,
        ['mips64el']),
    (lambda m, b32, le: m == 'MIPS' and not b32 and not le,
        ['mips64']),
    (lambda m, b32, le: m == 'PPC',
        ['powerpc', 'powerpc-440fp', 'powerpc-e300c3',
         'powerpc-e500mc', 'ppc']),
    (lambda m, b32, le: m == 'PPC64',
        ['ppc64', 'powerpc64', 'powerpc64-e6500', 'powerpc64-pwoer8']),
    (lambda m, b32, le: m == 'SH',
        ['sh2', 'sh2eb', 'sh2elf', 'sh4']),
    (lambda m, b32, le: m == 'SPARC',
        ['sparc']),
    (lambda m, b32, le: m == 'SPARCV9',
        ['sparc64']),
    (lambda m, b32, le: m == 'I386',
        ['i386', 'i486', 'i586', 'i686', 'x86', 'x86-core2', 'x86-i686']),
    (lambda m, b32, le: m == 'X86_64',
        ['x86_64', 'amd64', 'x86-64', 'x86-64-core-i7']),
    (lambda m, b32, le: m == 'RISCV',
        ['risc-v', 'riscv', 'risc-v-32', 'risc-v-64']),
]


def lief_arch_group_for(on_disk_arch):
    """Return the lief candidate list that contains ``on_disk_arch``.

    Used by the publish helper to fill each manifest asset's
    ``lief_arch_match`` field. Unknown arches return ``[arch]`` so the
    asset still matches itself but doesn't claim siblings.
    """
    for _predicate, candidates in _LIEF_ARCH_GROUPS:
        if on_disk_arch in candidates:
            return list(candidates)
    return [on_disk_arch]


def lief_arch_candidates(target_path):
    # Map a LIEF machine_type to the set of arch labels that appear as
    # signatures/<family>/<arch>/ directory names. See _LIEF_ARCH_GROUPS
    # for the shared table.
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

    for predicate, candidates in _LIEF_ARCH_GROUPS:
        if predicate(machine, is_32bit, is_le):
            return list(candidates)
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


# Sort key for the candidate family directories — preserves the README's
# "try these toolchain families first" recommendation so the first cfg
# returning the best score is found earlier under -v false (default).
_FAMILY_PRIORITY = {
    'firmware-linux':  0,
    'aboriginal-linux': 1,
    'bootlin-stable':  2,
    'buildroot':       3,
    'uclibc-pub':      4,
}


def _family_sort_key(family_name):
    return (_FAMILY_PRIORITY.get(family_name, 99), family_name)


def candidate_cfgs(target_path, arch_filter, libc_filter):
    """Return [(cfg_path, cfg_info), ...] for cfgs matching the filters.

    The arch filter is applied at the filesystem level — only the
    ``signatures/<family>/<arch>/`` directories whose ``<arch>``
    matches are walked, so the cost scales with the survivor set, not
    the full catalog. The libc filter is applied per-file by parsing
    the signature basename.
    """
    arch_set = set(arch_filter)
    cfgs = []
    root = sigstore.signatures_root()
    if not root.is_dir():
        return cfgs
    family_dirs = sorted(
        (p for p in root.iterdir() if p.is_dir()),
        key=lambda p: _family_sort_key(p.name),
    )
    for family_dir in family_dirs:
        for arch_dir in sorted(family_dir.iterdir()):
            if not arch_dir.is_dir() or arch_dir.name not in arch_set:
                continue
            for cfg_path in sorted(arch_dir.glob("*.json")):
                if libc_filter is not None:
                    fam = cfg_libc_family(cfg_path.name)
                    # Keep cfgs whose libc family is unknown (None) —
                    # better to over-include than silently drop a
                    # viable candidate.
                    if fam is not None and fam not in libc_filter:
                        continue
                with open(cfg_path) as f:
                    info = json.load(f)
                cfgs.append((str(cfg_path), info))
    return cfgs


def _format_eta(elapsed, idx, total):
    if idx <= 0:
        return '?'
    remaining = elapsed * (total - idx) / idx
    return f'{int(remaining // 60):d}m{int(remaining % 60):02d}s'


def select_best(target_path, jobs, *, arch=None, libc=None):
    """Score every candidate cfg against ``target_path`` and rank them.

    ``arch`` and ``libc`` may be a comma-separated string or a list /
    set of tokens; the default ``None`` (or the literal string
    ``'AUTO'``) defers to the lief-driven detection. Returns a list of
    ``(cfg_path, score)`` tuples sorted by score descending. Empty when
    no candidate cfg matches or every score lookup errored.

    Logging mirrors the CLI: arch / libc decisions and per-cfg progress
    land on the module logger so callers that wire a handler see the
    same trail the CLI prints.
    """
    if arch is None or arch == 'AUTO':
        arch_filter = lief_arch_candidates(target_path)
    elif isinstance(arch, str):
        arch_filter = arch.split(',')
    else:
        arch_filter = list(arch)
    log.info('target=%s', target_path)
    log.info('arch candidates: %s', arch_filter)

    if libc is None or libc == 'AUTO':
        fam = lief_libc_family(target_path)
        libc_filter = {fam} if fam else None
    elif isinstance(libc, str):
        libc_filter = set(libc.split(','))
    else:
        libc_filter = set(libc)
    log.info('libc family: %s', libc_filter or 'unknown (no pruning)')

    cfgs = candidate_cfgs(target_path, arch_filter, libc_filter)
    log.info('%d cfg(s) after arch+libc filter', len(cfgs))
    if not cfgs:
        log.error('no signatures/<family>/<arch>/ entry matches the target')
        return []

    log.info('precomputing target state')
    t_state = time.time()
    target_state = match.compute_target_state(target_path)
    log.info('target state ready in %.2fs (text region %d bytes)',
             time.time() - t_state, target_state['target_size'])

    jobs = max(1, jobs)
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
        return []

    match_num_list.sort(key=lambda x: x[1], reverse=True)
    log.info('---- final ranking ----')
    return match_num_list


# ---------------------------------------------------------------------------
# Verdict construction -- compute coverage for a (target_info, cfg) pair
# and gate it against the configured threshold. The coverage definitions
# and threshold default live in stelftools.match.coverage.
# ---------------------------------------------------------------------------


def _compute_verdict(target_info, metric, threshold):
    """Coverage + identified/unidentified verdict for one ``target_info``.

    ``metric`` is ``'function'`` (identified libc functions / libc
    functions present in the binary) or ``'bytes'`` (the historical
    bytes-based proxy). Returns a dict the CLI prints and the test
    suite parses.
    """
    functions = target_info['functions']
    top = first_libc_anchor(functions, skip_libc_func)
    bot = last_libc_anchor(functions)
    skip = libc_funcs_in_crt_area(functions, top, skip_libc_func)
    if metric == 'bytes':
        ratio, _ = library_coverage_by_bytes(target_info, top, bot, skip)
        matched = total = None
    else:
        ratio, matched, total = library_coverage_by_function(functions, top, bot, skip)
    return {
        'coverage_metric': metric,
        'coverage': ratio,
        'matched_libc_functions': matched,
        'total_libc_functions_in_region': total,
        'libc_area_top': top,
        'libc_area_bot': bot,
        'threshold': threshold,
        'identified': is_toolchain_identified(ratio, threshold),
    }


def _print_verdict(target_path, cfg_path, verdict, runners_up=None):
    name = os.path.basename(cfg_path) if cfg_path else '(none)'
    state = 'identified' if verdict['identified'] else 'unidentified'
    metric = verdict['coverage_metric']
    pct = verdict['coverage'] * 100
    threshold_pct = verdict['threshold'] * 100
    print(f'target:    {target_path}')
    print(f'toolchain: {name}')
    print(f'cfg_path:  {cfg_path}' if cfg_path else 'cfg_path:  -')
    if metric == 'function' and verdict['total_libc_functions_in_region']:
        print(f'coverage:  {pct:5.1f}%  '
              f'({verdict["matched_libc_functions"]}/'
              f'{verdict["total_libc_functions_in_region"]} libc functions, '
              f'metric=function)')
    else:
        print(f'coverage:  {pct:5.1f}%  (metric={metric})')
    print(f'verdict:   {state}  (threshold {threshold_pct:.1f}%)')
    if runners_up:
        print('runners-up:')
        for cp, score in runners_up:
            print(f'  {score:>4}  {os.path.basename(cp)}')


# ---------------------------------------------------------------------------
# Single-cfg path -- the old ``stelftools-ident`` flow.
# ---------------------------------------------------------------------------


def identify_with_cfg(target_path, cfg_path, output_style, *, threshold, metric,
                      verdict_only=False):
    """Run the matcher with one cfg, render verdict + output."""
    cfg_info = json.loads(Path(cfg_path).read_text())
    target_info = match.run_one(target_path, cfg_info, cfg_path=cfg_path)
    verdict = _compute_verdict(target_info, metric, threshold)
    _print_verdict(target_path, cfg_path, verdict)
    if not verdict_only:
        render_output(target_info, target_path, output_style)
    return verdict


# ---------------------------------------------------------------------------
# Multi-cfg path -- the old ``stelftools-bruteforce`` flow, now with a
# coverage-based verdict on the winner.
# ---------------------------------------------------------------------------


def identify_without_cfg(target_path, jobs, output_style, *, arch, libc,
                          threshold, metric, verbose=False, verdict_only=False):
    """Score every candidate cfg, derive coverage for the top cfg, render."""
    rankings = select_best(target_path, jobs, arch=arch, libc=libc)
    if not rankings:
        return None
    best_cfg, _best_score = rankings[0]
    cfg_info = json.loads(Path(best_cfg).read_text())
    target_info = match.run_one(target_path, cfg_info, cfg_path=best_cfg)
    verdict = _compute_verdict(target_info, metric, threshold)
    runners_up = rankings[1:5] if verbose else rankings[1:3]
    _print_verdict(target_path, best_cfg, verdict, runners_up=runners_up)
    if not verdict_only:
        render_output(target_info, target_path, output_style)
    return verdict


# ---------------------------------------------------------------------------
# CLI surface -- the verb entry that :mod:`.cli` dispatches to, plus a
# legacy ``main()`` kept for ``stelftools-bruteforce`` /
# ``stelftools-ident`` shims under :mod:`.legacy_shims`.
# ---------------------------------------------------------------------------


def _add_arguments(parser):
    parser.add_argument('target', help='path to the target ELF binary')
    parser.add_argument(
        '--cfg',
        help='path to a single toolchain config JSON (under '
             'signatures/<family>/<arch>/<name>.json). When omitted, '
             'every config whose architecture and libc family match '
             'the target is scored and the best-coverage one wins.',
    )
    parser.add_argument(
        '--arch',
        help='comma-separated arch shortlist, or "AUTO" / omitted to '
             'derive from the ELF header',
    )
    parser.add_argument(
        '--libc',
        help='comma-separated libc family shortlist (glibc, musl, '
             'uclibc); "AUTO" / omitted to derive from the ELF '
             '.interp section (the dynamic loader path; only present '
             'in dynamically-linked binaries)',
    )
    parser.add_argument(
        '--threshold', type=float, default=TOOLCHAIN_IDENTIFIED_THRESHOLD,
        help=f'coverage threshold for the identified verdict. Default '
             f'{TOOLCHAIN_IDENTIFIED_THRESHOLD} reports a toolchain as '
             f'identified when at least 90%% of its library functions '
             f'match; --strict (= --threshold 1.0) requires all of them.',
    )
    parser.add_argument(
        '--strict', action='store_true',
        help='shorthand for --threshold 1.0; requires every libc-region '
             'function to match before the verdict line reads "identified".',
    )
    parser.add_argument(
        '--coverage-metric', choices=('function', 'bytes'), default='function',
        help='function (default) = identified libc functions / libc '
             'functions in the binary; bytes = stelftools historical '
             'proxy (matched libc bytes / total libc-region bytes).',
    )
    parser.add_argument(
        '-o', '--output-style',
        choices=('default', 'compare', 'ida', 'ghidra', 'count', 'no'),
        default='default',
        help='per-function output format. "no" suppresses the function '
             'listing; the verdict line is always printed.',
    )
    parser.add_argument(
        '--verdict-only', action='store_true',
        help='alias for "-o no": print the verdict, suppress per-function output.',
    )
    parser.add_argument(
        '-j', '--jobs', type=int, default=min(8, os.cpu_count() or 1),
        help='worker processes for parallel cfg scoring (default: '
             'min(8, cpu_count); ignored when --cfg is given)',
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='print more runner-up cfgs in the verdict footer.',
    )


def register_parser(subparsers):
    """Attach the ``stelftools identify`` sub-command."""
    parser = subparsers.add_parser(
        'identify',
        help='Identify the toolchain of an ELF and list its library functions.',
        description=__doc__.splitlines()[0],
    )
    _add_arguments(parser)
    parser.set_defaults(_run=run)
    return parser


def run(args):
    output_style = 'no' if args.verdict_only else args.output_style
    # --strict is a shorthand: bump the threshold to 1.0 unless the caller
    # has explicitly passed --threshold on top of it (an explicit value
    # always wins so the user is never silently overridden).
    if args.strict and args.threshold == TOOLCHAIN_IDENTIFIED_THRESHOLD:
        args.threshold = 1.0
    if args.cfg:
        verdict = identify_with_cfg(
            args.target, args.cfg, output_style,
            threshold=args.threshold, metric=args.coverage_metric,
            verdict_only=args.verdict_only,
        )
    else:
        verdict = identify_without_cfg(
            args.target, args.jobs, output_style,
            arch=args.arch, libc=args.libc,
            threshold=args.threshold, metric=args.coverage_metric,
            verbose=args.verbose, verdict_only=args.verdict_only,
        )
    if verdict is None:
        return 1
    return 0


def main(argv=None):
    """Legacy entry point retained for ``stelftools-bruteforce`` shim."""
    parser = argparse.ArgumentParser(prog='stelftools-identify')
    _add_arguments(parser)
    return run(parser.parse_args(argv))


if __name__ == '__main__':
    raise SystemExit(main())
