#!/usr/bin/env python3
"""Score a signature on a MIPS PIC ELF against the binary's own `.pdr`.

`total_funcs` of `stelftools symbolize` counts matches plus bare call targets,
so `match_count / total_funcs` says nothing about how much of the program was
named. A MIPS ELF built with `.pdr` records every procedure's start address,
which gives an independent denominator and a check on each match:

* `named_share`: named `.pdr` procedures / all `.pdr` procedures.
* `off_pdr`: matches at an address no procedure starts at.
* `callees`: for a named function, the callees named in the target (resolved
  through the GOT) against the callees its library object declares (`.dlist`).
  `inconsistent` means a named callee the object never calls: evidence the
  name is wrong. The check needs a named callee, so `no_evidence` is not a pass.

    tools/eval/mips_pdr_eval.py TARGET --cfg CFG.json [--lib-boundary 0x8fd000]
    tools/eval/mips_pdr_eval.py STRIPPED --cfg CFG.json --truth UNSTRIPPED
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from collections import defaultdict
from pathlib import Path

from elftools.elf.elffile import ELFFile

from stelftools.match.experimental import DEFAULT_MIN_SCORE, callee_verdict, infer

PDR_ENTRY = 32
LUI_GP = 0x3C1C
LW_T9_GP = 0x8F99
SHF_EXECINSTR = 0x4


def _s16(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


class Target:
    """The `.pdr` procedures of a little-endian MIPS ELF and their GOT callees."""

    def __init__(self, path: str):
        with open(path, "rb") as f:
            elf = ELFFile(f)
            pdr = elf.get_section_by_name(".pdr")
            if pdr is None:
                raise ValueError(f"{path}: no .pdr section")
            text, got = elf.get_section_by_name(".text"), elf.get_section_by_name(".got")
            self.text, self.text_addr = text.data(), text["sh_addr"]
            self.got = got.data() if got else b""
            self.got_addr = got["sh_addr"] if got else 0
            raw = pdr.data()
        end = self.text_addr + len(self.text)
        self.starts = sorted(
            a
            for a in {struct.unpack_from("<I", raw, i)[0] for i in range(0, len(raw), PDR_ENTRY)}
            if self.text_addr <= a < end
        )
        self.ends = dict(zip(self.starts, [*self.starts[1:], end]))

    def _word(self, addr: int) -> int:
        return struct.unpack_from("<I", self.text, addr - self.text_addr)[0]

    def callees(self, addr: int) -> list[int]:
        """Targets of the `lw t9,slot(gp)` in the procedure at `addr`."""
        if addr not in self.ends or self._word(addr) >> 16 != LUI_GP:
            return []
        gp = ((self._word(addr) & 0xFFFF) << 16) + _s16(self._word(addr + 4) & 0xFFFF) + addr
        found = []
        for pc in range(addr, self.ends[addr] - 3, 4):
            word = self._word(pc)
            if word >> 16 != LW_T9_GP:
                continue
            slot = (gp + _s16(word & 0xFFFF) - self.got_addr) & 0xFFFFFFFF
            if slot + 4 <= len(self.got):
                value = struct.unpack_from("<I", self.got, slot)[0]
                if value in self.ends:
                    found.append(value)
        return found


def read_dlist(path: str) -> dict[str, set[str]]:
    """`caller[,alias...] callee offset` lines as name -> declared callees."""
    declared: dict[str, set[str]] = defaultdict(set)
    with open(path) as f:
        for line in f:
            fields = line.split()
            if len(fields) >= 2:
                for name in fields[0].split(","):
                    declared[name].add(fields[1])
    return declared


def score(target: Target, matches: dict[int, list[str]], declared, lib_boundary: int = 0) -> dict:
    tally = {"consistent": 0, "inconsistent": 0, "no_evidence": 0}
    inconsistent = []
    for addr, names in matches.items():
        verdict = callee_verdict(
            names, [matches.get(c, []) for c in target.callees(addr)], declared
        )
        tally[verdict] += 1
        if verdict == "inconsistent":
            inconsistent.append(f"{addr:#x} {','.join(names)}")
    starts = set(target.starts)
    out = {
        "pdr_procedures": len(target.starts),
        "named": len(matches),
        "named_share": round(len(starts & set(matches)) / max(1, len(starts)), 4),
        "off_pdr": len(set(matches) - starts),
        "callees": tally,
        "inconsistent": sorted(inconsistent),
    }
    if lib_boundary:
        lib = [a for a in target.starts if a >= lib_boundary]
        out["lib_boundary"] = hex(lib_boundary)
        out["lib_procedures"] = len(lib)
        out["lib_named"] = len(set(lib) & set(matches))
        out["lib_named_share"] = round(out["lib_named"] / max(1, len(lib)), 4)
        out["below_boundary"] = sum(a < lib_boundary for a in matches)
    return out


def truth_symbols(path: str) -> dict[int, set[str]]:
    with open(path, "rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        if symtab is None:
            raise SystemExit(f"{path}: no .symtab")
        truth: dict[int, set[str]] = defaultdict(set)
        for sym in symtab.iter_symbols():
            # old assemblers leave a hand-written stub's symbol untyped
            info = sym["st_info"]
            if info["type"] == "STT_NOTYPE" and info["bind"] == "STB_LOCAL":
                continue
            if info["type"] not in ("STT_FUNC", "STT_NOTYPE") or not sym.name:
                continue
            shndx = sym["st_shndx"]
            if isinstance(shndx, int) and elf.get_section(shndx)["sh_flags"] & SHF_EXECINSTR:
                truth[sym["st_value"]].add(sym.name)
    return dict(truth)


def score_truth(matches: dict[int, list[str]], truth: dict[int, set[str]]) -> dict:
    """A match is right when the true symbols at its address meet its candidates."""
    right = [a for a, names in matches.items() if truth.get(a, set()) & set(names)]
    wrong_name = [a for a in matches if a in truth and a not in set(right)]
    no_function = [a for a in matches if a not in truth]
    return {
        "truth_functions": len(truth),
        "matches": len(matches),
        "right": len(right),
        "wrong_name": len(wrong_name),
        "not_a_function": len(no_function),
        "precision": round(len(right) / max(1, len(matches)), 4),
        "recall": round(len(right) / max(1, len(truth)), 4),
        "wrong_samples": [
            f"{a:#x} matched {','.join(matches[a])} is {','.join(sorted(truth[a]))}"
            for a in sorted(wrong_name)[:20]
        ],
    }


def run_matcher(target_path: str, cfg_path: str, state=None) -> dict[int, list[str]]:
    from stelftools import match

    with open(cfg_path) as f:
        cfg = json.load(f)
    state = state or match.compute_target_state(target_path)
    info = match.run_one_with_state(state, cfg, cfg_path=cfg_path)
    return {
        addr: fn["names"]
        for addr, fn in info["functions"].items()
        if fn.get("names") and fn["names"] != [""]
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("target")
    parser.add_argument("--cfg", required=True)
    parser.add_argument("--lib-boundary", type=lambda v: int(v, 0), default=0)
    parser.add_argument("--truth", help="unstripped build of TARGET; adds precision and recall")
    parser.add_argument("--experimental-string-anchor", action="store_true")
    parser.add_argument("--experimental-fuzzy", action="store_true")
    parser.add_argument("--experimental-dispatch", action="store_true")
    parser.add_argument("--fuzzy-min-score", type=float, default=DEFAULT_MIN_SCORE)
    args = parser.parse_args(argv)
    matches = run_matcher(args.target, args.cfg)
    result = {"target": args.target, "cfg": Path(args.cfg).name}
    try:
        target = Target(args.target)
    except ValueError as exc:
        if not args.truth:
            raise SystemExit(str(exc)) from exc
        result["pdr"] = str(exc)
    else:
        declared = read_dlist(str(Path(args.cfg).with_suffix(".dlist")))
        result.update(score(target, matches, declared, args.lib_boundary))
    truth = truth_symbols(args.truth) if args.truth else None
    if truth is not None:
        result["truth"] = score_truth(matches, truth)
    if args.experimental_string_anchor or args.experimental_fuzzy or args.experimental_dispatch:
        found, notes = infer(
            args.target, args.cfg, matches,
            string_anchor=args.experimental_string_anchor,
            fuzzy=args.experimental_fuzzy, dispatch=args.experimental_dispatch,
            min_score=args.fuzzy_min_score,
        )
        result["inferred"] = {
            f"{addr:#x}": {**item, "true": sorted(truth.get(addr, ())) if truth is not None else None}
            for addr, item in sorted(found.items())
        }
        result["inference_notes"] = notes
        if truth is not None:
            result["inferred_score"] = {}
            for method in sorted({i["method"] for i in found.values()}):
                subset = {a: i["names"] for a, i in found.items() if i["method"] == method}
                result["inferred_score"][method] = score_truth(subset, truth)
    json.dump(result, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
