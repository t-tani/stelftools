"""Write stelftools-matched library names back into a stripped ELF.

The matcher fingerprints statically-linked library code on the host and
yields a virtual-address-to-name map; this module writes that map into
a fresh ``.symtab`` on a copy of the ELF and produces a symbolized
binary.

Both Ghidra and IDA read ``.symtab`` of a static ELF at load time, so
the matched names appear as named functions on import with no database
mutation and no per-function rename calls. The symbolized copy is what
downstream analysis imports; the original ELF is left untouched.

``--cfg`` supplies a toolchain config explicitly. When ``--cfg`` is
omitted, :func:`stelftools.drivers.identify.select_best` elects the
best-scoring cfg from the on-disk signatures tree. A JSON summary is
written to ``--out`` (default stdout).

Byte-identical library functions reach the matcher as a candidate group
(``__GI_strcpy`` + ``strcpy``, ``lcong48`` + ``srand48``). The historical
output joined every group as ``a_OR_b`` so no exact-match consumer of a
libc name (sink tables, naming roles, semgrep allow-lists) ever saw
``strcpy``. :func:`resolve_group` collapses a group to one canonical name
when the caller's ``resolver`` proves it an alias set of one public
function; a group of distinct functions keeps the ``_OR_`` join, and the
sidecar notes when exactly one member is in the caller's ``prefer`` set
(``catalog``, e.g. a catalogued sink / source) so such consumers can
treat the join as a lead. Standalone — no ``--resolver`` — only a group
of one name is proven and every other group stays an ``_OR_`` join. The
per-address decision is written beside the ELF as
``<out_elf>.symbols.json``.
"""
from __future__ import annotations

import argparse
import contextlib
import importlib
import io
import json
import logging
import os
import sys
import time
from collections.abc import Callable, Collection
from pathlib import Path

from . import identify as _identify
from .. import match
from ..elf.symtab_write import append_symtab, section_index_for_addr
from ..match import skip_libc_func
from ..match.coverage import first_libc_anchor, last_libc_anchor

log = logging.getLogger("stelftools.drivers.symbolize")


def _setup_default_logging():
    """Wire a stderr handler matching the symbolize_elf legacy format.

    Idempotent: an explicit handler set up by the caller wins, and we
    never add a duplicate.
    """
    if log.handlers:
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(
        fmt="%(asctime)s  %(message)s", datefmt="%H:%M:%S"))
    log.addHandler(handler)
    log.setLevel(logging.INFO)


def pick_toolchain(target_path, jobs):
    """Pick the best-scoring toolchain config for ``target_path``.

    Returns ``(cfg_path, score)``. Raises :class:`RuntimeError` if no
    candidate cfg matches. The selection runs in-process through
    :func:`stelftools.drivers.identify.select_best`; the identify logger
    is left untouched so the CLI of ``stelftools symbolize`` and
    ``stelftools identify`` show the same per-cfg trail.
    """
    rankings = _identify.select_best(target_path, jobs)
    if not rankings:
        raise RuntimeError("identify produced no candidate cfg; "
                           "the signatures tree may be empty or "
                           "every cfg errored out")
    return rankings[0]


def run_match(target_path, cfg_path, output_mode='ghidra', logger=None):
    """Run the stelftools matcher and return ``(match_info, target_info)``.

    ``match_info`` maps a virtual address to ``{'names': '<name>'}``
    where the name is the underscore-OR-joined alias string produced
    by :func:`stelftools.match.output` — the libc-area filter and
    alias collapsing are done inside the matcher. ``output_mode`` is
    ``'ida'`` or ``'ghidra'``; both yield the same ``_OR_``-joined
    format. The matcher prints the match list to stdout; we capture
    it so callers see only their own output.

    If ``logger`` is given, the two slow stages (target-state
    computation and the match itself) are timed onto it.
    """
    with open(cfg_path) as fp:
        cfg_info = json.load(fp)

    t0 = time.time()
    target_state = match.compute_target_state(target_path)
    if logger:
        logger.info("compute_target_state done in %.1fs", time.time() - t0)

    t0 = time.time()
    target_info = match.run_one_with_state(
        target_state, cfg_info, cfg_path=cfg_path)
    if logger:
        logger.info("run_one_with_state done in %.1fs (functions=%d)",
                    time.time() - t0, len(target_info['functions']))

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        match_info = match.output(target_info, target_path, output_mode)
    return match_info, target_info


def _load_spec(spec):
    """``module:attr`` → the attribute (the ``--resolver`` / ``--prefer``
    plug-in flags)."""
    mod, sep, attr = spec.partition(":")
    if not sep or not mod or not attr:
        raise ValueError(f"expected module:attr, got {spec!r}")
    return getattr(importlib.import_module(mod), attr)


def prefer_names(specs):
    """The union of the name sets the ``--prefer`` specs point at: each
    attribute is a collection of names (a dict counts by its keys) or a
    zero-argument callable returning one."""
    out = set()
    for spec in specs:
        obj = _load_spec(spec)
        out.update(obj() if callable(obj) else obj)
    return frozenset(out)


#: ``(candidates, prefer) -> (canonical, resolution)`` with resolution one of
#: ``single`` / ``alias`` / ``catalog`` / ``ambiguous`` (see :func:`resolve_group`).
Resolver = Callable[[list[str], Collection[str]], tuple[str | None, str]]


def default_resolver(cands, prefer):
    """The standalone rule: a group of one name is that name; the bytes
    prove nothing about any larger group, so it stays ambiguous (``prefer``
    is unused — breaking ties needs a caller's notion of public names)."""
    return (cands[0], "single") if len(cands) == 1 else (None, "ambiguous")


def resolve_group(names, prefer=frozenset(), resolver=None):
    """Decide the symtab name for one candidate group.

    Returns ``{"canonical", "candidates", "resolution", "symbol"}``:
    ``symbol`` is what goes into the ELF — the canonical name only when
    the bytes prove it (``single`` / ``alias``); for ``catalog`` and
    ``ambiguous`` the sorted ``_OR_`` join stays, because "the one
    preferred name among six shape-identical wrappers" is a lead for the
    consumer that supplied ``prefer``, not an identity the decompile may
    assert. ``candidates`` keeps the matcher's raw names (deduplicated,
    sorted) so the sidecar is auditable. ``resolver`` (a :data:`Resolver`)
    defaults to :func:`default_resolver`.
    """
    cands = sorted({n for n in names if n})
    canonical, resolution = (resolver or default_resolver)(cands, prefer)
    symbol = canonical if resolution in ("single", "alias") else "_OR_".join(cands)
    return {"canonical": canonical, "candidates": cands,
            "resolution": resolution, "symbol": symbol}


def resolve_symbols(groups, prefer=frozenset(), resolver=None):
    """``{ea: [raw names]}`` → ``{ea: resolve_group(...)}`` for every group
    that has at least one name. Pure; the unit tests drive it directly."""
    out = {}
    for ea, names in groups.items():
        cands = [n for n in names if n]
        if cands:
            out[ea] = resolve_group(cands, prefer, resolver)
    return out


def libc_area(functions):
    """``(top, bot)`` — the statically linked libc's address range the
    matcher anchored on (:func:`stelftools.match.coverage.first_libc_anchor`
    / :func:`last_libc_anchor`): the GNU linker emits the CRT prologue,
    then the program, then the libc archive, then the CRT epilogue, so
    every function inside the range is library code and every function
    before it is the application. ``None`` when no anchor was found (an
    empty match, or a libc the signature set does not know)."""
    top = first_libc_anchor(functions, skip_libc_func)
    bot = last_libc_anchor(functions)
    if not top or not bot or bot <= top:
        return None
    return top, bot


def _write_sidecar(path, cfg, resolved, area=None):
    counts = {}
    for r in resolved.values():
        counts[r["resolution"]] = counts.get(r["resolution"], 0) + 1
    doc = {
        "schema_version": 1,
        "cfg": cfg,
        # the libc area, read by entry_reach's library tagging
        # (docs/entry-reach.md §3); null when no anchor was found
        "libc_area_top": hex(area[0]) if area else None,
        "libc_area_bot": hex(area[1]) if area else None,
        "symbols": {
            hex(ea): {"canonical": r["canonical"],
                      "candidates": r["candidates"],
                      "resolution": r["resolution"]}
            for ea, r in sorted(resolved.items())},
        "counts": counts,
    }
    Path(path).write_text(json.dumps(doc, indent=1) + "\n")
    return counts


def symbolize(binary_path, out_elf_path, cfg_path=None, jobs=None,
              resolver: Resolver | None = None, prefer: Collection[str] = frozenset()):
    """Run match + ELF symtab patch and write the symbolized copy.

    Returns a summary dict with the match counts and the chosen cfg.
    ``cfg_path`` may be ``None``, in which case the identify ranker
    elects one and the chosen score lands in ``identify_score`` on
    the returned dict. ``jobs`` defaults to ``min(8, cpu_count())``.
    ``resolver`` and ``prefer`` are handed to :func:`resolve_symbols`:
    the caller's canonical-name rule and its tie-breaking name set
    (``None`` / empty keep the standalone ``_OR_`` behaviour).

    No file is written until the matcher has produced a result, so an
    identify failure or an unparseable cfg leaves the destination
    untouched. The symtab names come from :func:`resolve_symbols` over
    the matcher's raw candidate lists; the addresses are the ones
    :func:`stelftools.match.output` kept after its libc-area / CRT
    filtering, so the set of symbols is unchanged from the ``_OR_`` era
    and only their spelling differs.
    """
    binary_path = Path(binary_path)
    out_elf_path = Path(out_elf_path)
    if jobs is None:
        jobs = min(8, os.cpu_count() or 1)

    if cfg_path is None:
        cfg_path, identify_score = pick_toolchain(str(binary_path), jobs)
    else:
        cfg_path = str(Path(cfg_path).resolve())
        identify_score = None

    log.info("matching cfg=%s ...", Path(cfg_path).name)
    match_info, target_info = run_match(
        str(binary_path), cfg_path, "ghidra", log)
    functions = target_info.get("functions", {})
    total_funcs = len(functions)
    log.info("matched %d / %d functions", len(match_info), total_funcs)

    resolved = resolve_symbols(
        {ea: functions[ea]["names"] for ea in match_info if ea in functions},
        prefer, resolver)

    data = binary_path.read_bytes()
    symbols = []
    undefined_section = 0
    for ea, info in match_info.items():
        shndx = section_index_for_addr(data, ea)
        if shndx == 0:
            undefined_section += 1
        # An address output() kept but the raw table lacks cannot happen
        # today; fall back to the matcher's own join rather than drop it.
        name = resolved[ea]["symbol"] if ea in resolved else info["names"]
        symbols.append((ea, shndx, name))

    out_data = append_symtab(data, symbols)
    out_elf_path.parent.mkdir(parents=True, exist_ok=True)
    out_elf_path.write_bytes(out_data)
    sidecar = out_elf_path.with_name(out_elf_path.name + ".symbols.json")
    area = None if target_info.get("no_libc_area") else libc_area(functions)
    counts = _write_sidecar(sidecar, cfg_path, resolved, area)
    joined = counts.get("ambiguous", 0) + counts.get("catalog", 0)
    log.info("wrote %d symbols into %s (%d canonical, %d kept as _OR_ joins "
             "of which %d carry a preferred name)",
             len(symbols), out_elf_path, len(resolved) - joined, joined,
             counts.get("catalog", 0))

    return {
        "binary": str(binary_path),
        "out_elf": str(out_elf_path),
        "cfg": cfg_path,
        "identify_score": identify_score,
        "match_count": len(match_info),
        "total_funcs": total_funcs,
        "symbols_added": len(symbols),
        "symbols_undefined_section": undefined_section,
        "canonical_count": len(resolved) - joined,
        "catalog_count": counts.get("catalog", 0),
        "ambiguous_count": counts.get("ambiguous", 0),
        "libc_area_top": hex(area[0]) if area else None,
        "libc_area_bot": hex(area[1]) if area else None,
        "sidecar": str(sidecar),
    }


def _write_summary(path, data):
    text = json.dumps(data, indent=2)
    if path == "-":
        sys.stdout.write(text + "\n")
    else:
        Path(path).write_text(text + "\n")


def _add_arguments(parser):
    parser.add_argument(
        "binary", help="absolute path to the target ELF on the host")
    parser.add_argument(
        "--cfg", default=None,
        help="signatures/<family>/<arch>/<name>.json to apply. "
             "When omitted, the identify ranker elects one from the "
             "on-disk signatures tree.",
    )
    parser.add_argument(
        "--out-elf", "-o", dest="out_elf", required=True,
        help="path to write the symbolized ELF copy",
    )
    parser.add_argument(
        "-j", "--jobs", type=int, default=min(8, os.cpu_count() or 1),
        help="worker count for cfg scoring when --cfg is omitted",
    )
    parser.add_argument(
        "--summary", default="-", dest="summary_path",
        help="output JSON summary path or '-' for stdout",
    )
    parser.add_argument(
        "--resolver", default=None, metavar="MODULE:ATTR",
        help="callable (candidates, prefer) -> (canonical, resolution) that "
             "decides one public name for a group of byte-identical "
             "candidates (resolution: single|alias|catalog|ambiguous). "
             "Default: a group of one name is itself, any other group "
             "stays an _OR_ join.",
    )
    parser.add_argument(
        "--prefer", action="append", default=[], metavar="MODULE:ATTR",
        help="names that break a tie among distinct public functions in a "
             "group (a collection, or a callable returning one); repeatable, "
             "the union is passed to --resolver. Unused by the default resolver.",
    )


def register_parser(subparsers):
    parser = subparsers.add_parser(
        "symbolize",
        help="Write matched library names into a fresh .symtab on a copy of the ELF.",
        description=__doc__.splitlines()[0],
    )
    _add_arguments(parser)
    parser.set_defaults(_run=run)
    return parser


def run(args):
    _setup_default_logging()
    _identify.log.setLevel(logging.INFO)  # propagate to the identify trail

    binary_path = Path(args.binary)
    if not binary_path.is_file():
        _write_summary(args.summary_path,
                       {"error": f"binary not found: {binary_path}"})
        return 2

    try:
        resolver = _load_spec(args.resolver) if args.resolver else None
        prefer = prefer_names(args.prefer)
    except (ImportError, AttributeError, ValueError) as exc:
        _write_summary(args.summary_path,
                       {"error": f"plug-in spec: {exc}", "binary": str(binary_path)})
        return 2

    try:
        summary = symbolize(
            binary_path=binary_path,
            out_elf_path=Path(args.out_elf),
            cfg_path=args.cfg,
            jobs=args.jobs,
            resolver=resolver,
            prefer=prefer,
        )
    except RuntimeError as exc:
        _write_summary(args.summary_path,
                       {"error": str(exc), "binary": str(binary_path)})
        return 4

    _write_summary(args.summary_path, summary)
    return 0


def main(argv=None):
    """Legacy entry point for the ``stelftools-symbolize`` shim."""
    parser = argparse.ArgumentParser(prog="stelftools-symbolize")
    _add_arguments(parser)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
