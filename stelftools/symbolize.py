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
omitted, :func:`stelftools.bruteforce.select_best` elects the
best-scoring cfg from the on-disk signatures tree. A JSON summary is
written to ``--out`` (default stdout).
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import logging
import os
import sys
import time
from pathlib import Path

from . import bruteforce, ident
from .elf.symtab_write import append_symtab, section_index_for_addr

log = logging.getLogger("stelftools.symbolize")


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
    :func:`stelftools.bruteforce.select_best`; the bruteforce logger
    is left untouched so the CLI of stelftools-symbolize and the CLI
    of stelftools-bruteforce show the same per-cfg trail.
    """
    rankings = bruteforce.select_best(target_path, jobs)
    if not rankings:
        raise RuntimeError("bruteforce produced no candidate; "
                           "the signatures tree may be empty or "
                           "every cfg errored out")
    return rankings[0]


def run_match(target_path, cfg_path, output_mode='ghidra', logger=None):
    """Run the stelftools matcher and return ``(match_info, target_info)``.

    ``match_info`` maps a virtual address to ``{'names': '<name>'}``
    where the name is the underscore-OR-joined alias string produced
    by :func:`stelftools.ident.output` — the libc-area filter and
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
    target_state = ident.compute_target_state(target_path)
    if logger:
        logger.info("compute_target_state done in %.1fs", time.time() - t0)

    t0 = time.time()
    target_info = ident.run_one_with_state(
        target_state, cfg_info, cfg_path=cfg_path)
    if logger:
        logger.info("run_one_with_state done in %.1fs (functions=%d)",
                    time.time() - t0, len(target_info['functions']))

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        match_info = ident.output(target_info, target_path, output_mode)
    return match_info, target_info


def symbolize(binary_path, out_elf_path, cfg_path=None, jobs=None):
    """Run match + ELF symtab patch and write the symbolized copy.

    Returns a summary dict with the match counts and the chosen cfg.
    ``cfg_path`` may be ``None``, in which case the bruteforce ranker
    elects one and the chosen score lands in ``bruteforce_score`` on
    the returned dict. ``jobs`` defaults to ``min(8, cpu_count())``.

    No file is written until the matcher has produced a result, so a
    bruteforce failure or an unparseable cfg leaves the destination
    untouched.
    """
    binary_path = Path(binary_path)
    out_elf_path = Path(out_elf_path)
    if jobs is None:
        jobs = min(8, os.cpu_count() or 1)

    if cfg_path is None:
        cfg_path, bruteforce_score = pick_toolchain(str(binary_path), jobs)
    else:
        cfg_path = str(Path(cfg_path).resolve())
        bruteforce_score = None

    log.info("matching cfg=%s ...", Path(cfg_path).name)
    match_info, target_info = run_match(
        str(binary_path), cfg_path, "ghidra", log)
    total_funcs = len(target_info.get("functions", []))
    log.info("matched %d / %d functions", len(match_info), total_funcs)

    data = binary_path.read_bytes()
    symbols = []
    undefined_section = 0
    for ea, info in match_info.items():
        shndx = section_index_for_addr(data, ea)
        if shndx == 0:
            undefined_section += 1
        symbols.append((ea, shndx, info["names"]))

    out_data = append_symtab(data, symbols)
    out_elf_path.parent.mkdir(parents=True, exist_ok=True)
    out_elf_path.write_bytes(out_data)
    log.info("wrote %d symbols into %s", len(symbols), out_elf_path)

    return {
        "binary": str(binary_path),
        "out_elf": str(out_elf_path),
        "cfg": cfg_path,
        "bruteforce_score": bruteforce_score,
        "match_count": len(match_info),
        "total_funcs": total_funcs,
        "symbols_added": len(symbols),
        "symbols_undefined_section": undefined_section,
    }


def _write_summary(path, data):
    text = json.dumps(data, indent=2)
    if path == "-":
        sys.stdout.write(text + "\n")
    else:
        Path(path).write_text(text + "\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("binary", help="absolute path to the target ELF on the host")
    ap.add_argument("--cfg", default=None,
                    help="signatures/configs/<family>/<name>.json to apply. "
                    "Omitted = bruteforce-pick from the ELF.")
    ap.add_argument("--out-elf", required=True,
                    help="path to write the symbolized ELF copy")
    ap.add_argument("-j", "--jobs", type=int,
                    default=min(8, os.cpu_count() or 1),
                    help="bruteforce worker count when --cfg is omitted")
    ap.add_argument("--out", default="-",
                    help="output JSON summary path or '-' for stdout")
    args = ap.parse_args()

    _setup_default_logging()
    bruteforce.log.setLevel(logging.INFO)  # propagate to the bruteforce trail

    binary_path = Path(args.binary)
    if not binary_path.is_file():
        _write_summary(args.out, {"error": f"binary not found: {binary_path}"})
        return 2

    try:
        summary = symbolize(
            binary_path=binary_path,
            out_elf_path=Path(args.out_elf),
            cfg_path=args.cfg,
            jobs=args.jobs,
        )
    except RuntimeError as exc:
        _write_summary(args.out, {"error": str(exc), "binary": str(binary_path)})
        return 4

    _write_summary(args.out, summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
