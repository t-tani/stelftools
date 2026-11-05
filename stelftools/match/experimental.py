"""Experimental, opt-in naming of library functions the byte rules missed.

A rule needs the whole function to match, so a vendor's patch to a library
function loses its name even when nearly all of it is the release's code. Two
inferences recover such functions on 32-bit MIPS, both weaker than a byte match,
so `stelftools symbolize` reports them apart from it (`resolution` `inferred_*`
in the sidecar):

* string anchor: the library function is the only one to reference a string
  (recorded by `mkrule --experimental-strings`), and one unnamed target procedure
  is the only one to reference that string.
* fuzzy: nearly all of the library function's instructions occur, in order, in
  an unnamed target procedure, and each is the other's clear best match.

Both reject a candidate with a named callee the library object never calls.
A fuzzy candidate also needs named neighbours: library code links in runs.
"""

from __future__ import annotations

import json
import math
import re
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

from elftools.elf.elffile import ELFFile

GP = 28
LUI_GP = 0x3C1C
ADDIU_GP_GP = 0x279C
ADDU_GP_GP_T9 = 0x0399E021
LW = 0x23
ADDIU = 0x09
#: j, jal, and the words a rule masks whole (GOT and call slots).
SLOT = "slot"
BRANCH_OPS = frozenset({1, 4, 5, 6, 7, 0x14, 0x15, 0x16, 0x17})
PDR_ENTRY = 32

MIN_TOKENS = 24
DEFAULT_MIN_SCORE = 0.95
MIN_MARGIN = 0.03
MAX_GROWTH = 3.0
MIN_SHRINK = 0.7
NEIGHBOUR_WINDOW = 8
MIN_NAMED_NEIGHBOURS = 2
MIN_STRING_LENGTH = 8
CANDIDATES_PER_RULE = 6


# --- instruction tokens ------------------------------------------------------


def token(word: int):
    """A word's form with what linking and patching move erased: immediates,
    branch offsets, GOT slots. A nop has none: delay-slot filling moves them."""
    if word == 0:
        return None
    op = word >> 26
    if op in (2, 3):
        return SLOT
    if op == LW and (word >> 21) & 31 == GP:
        return SLOT
    if op == 0 or 0x10 <= op <= 0x13:
        return word
    if op in BRANCH_OPS:
        return ("b", word >> 16)
    return word >> 16


def lcs_length(a: list, b: list) -> int:
    """Longest common subsequence, bit-parallel (Hyyro 2004)."""
    if not a or not b:
        return 0
    masks: dict = defaultdict(int)
    for i, item in enumerate(a):
        masks[item] |= 1 << i
    full = (1 << len(a)) - 1
    v = full
    for item in b:
        u = v & masks.get(item, 0)
        v = ((v + u) | (v - u)) & full
    return len(a) - bin(v).count("1")


# --- signature side ----------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    names: tuple[str, ...]
    tokens: tuple


_RULE = re.compile(
    r'^rule \S+ \{\n.*?aliases = "([^"]*)".*?\$pattern = \{ ([^}]*) \}', re.M | re.S
)


def rule_tokens(pattern: str, little_endian: bool = True) -> list | None:
    """The tokens of a rule's hex pattern; None for a form this does not read."""
    cells = pattern.split()
    if len(cells) % 4 or any(not re.fullmatch(r"[0-9A-Fa-f]{2}|\?\?", c) for c in cells):
        return None
    tokens = []
    for i in range(0, len(cells), 4):
        word = cells[i : i + 4]
        if little_endian:
            word = word[::-1]
        if word[0] == "??" or word[1] == "??":
            tokens.append(SLOT)
            continue
        high = int(word[0] + word[1], 16)
        low = 0 if "??" in word[2:] else int(word[2] + word[3], 16)
        if "??" in word[2:]:
            low = 1  # keeps an all-zero word with a masked half from reading as a nop
        tok = token(high << 16 | low)
        if tok is not None:
            tokens.append(tok)
    return tokens


def read_rules(yara_path: str, little_endian: bool = True) -> list[Rule]:
    rules = []
    for match in _RULE.finditer(Path(yara_path).read_text()):
        tokens = rule_tokens(match[2], little_endian)
        if tokens:
            names = tuple(n.strip() for n in match[1].split(",") if n.strip())
            rules.append(Rule(names, tuple(tokens)))
    return rules


def read_alist(path) -> dict[str, frozenset[str]]:
    """Name -> the names of its one body, from `.alist`."""
    classes: dict[str, frozenset[str]] = {}
    if Path(path).is_file():
        with open(path) as f:
            for line in f:
                group = frozenset(n for n in line.strip().split(",") if n)
                for name in group:
                    classes[name] = group
    return classes


_ALIASES = re.compile(r'aliases = "([^"]*)"')


def read_rule_index(path) -> dict[str, int]:
    """Name -> the rule carrying it, from the `.yara` beside a `.dlist`."""
    index: dict[str, int] = {}
    if Path(path).is_file():
        for number, match in enumerate(_ALIASES.finditer(Path(path).read_text())):
            for name in match[1].split(","):
                if name.strip():
                    index[name.strip()] = number
    return index


def _twins(name: str, classes, rules) -> set[str]:
    """`name` and what else it is called. `.alist` is one source, but an assembly
    stub's weak alias is untyped and never reaches it, so a `_` or `__` spelling
    also counts, unless each spelling has a rule of its own: `_exit` and `exit`
    are two functions, and the signature shows it."""
    names = set(classes.get(name, {name}))
    bare = name.lstrip("_")
    for spelling in (bare, f"_{bare}", f"__{bare}"):
        own, other = rules.get(name), rules.get(spelling)
        if own is None or other is None or own == other:
            names.add(spelling)
    return names


def read_dlist(path) -> dict[str, set[str]]:
    """Name -> declared callees, each under every name its body goes by."""
    classes = read_alist(Path(path).with_suffix(".alist"))
    rules = read_rule_index(Path(path).with_suffix(".yara"))
    declared: dict[str, set[str]] = defaultdict(set)
    if Path(path).is_file():
        with open(path) as f:
            for line in f:
                fields = line.split()
                if len(fields) >= 2:
                    callees = _twins(fields[1], classes, rules)
                    for caller in fields[0].split(","):
                        for name in _twins(caller, classes, rules):
                            declared[name] |= callees
    return declared


#: One byte-swap body under each of its public names (byte_swap_{2,4}.S).
_SAME_BODY = (
    frozenset({"bswap16", "htons", "ntohs"}),
    frozenset({"bswap32", "htonl", "ntohl"}),
)


def spellings(name: str) -> set[str]:
    """The names of a byte-swap body; any other name is only itself here, since
    `read_dlist` has already expanded the names a declared callee goes by."""
    bare = name.lstrip("_")
    for group in _SAME_BODY:
        if bare in group:
            return {f"{prefix}{n}" for n in group for prefix in ("", "_", "__")}
    return {name}


def callee_verdict(names, callee_names, declared) -> str:
    """`inconsistent` when a callee named in the target is one the library
    object of `names` never calls; `no_evidence` when nothing can be compared."""
    known = [c for c in callee_names if c]
    if not known:
        return "no_evidence"
    allowed = set()
    for name in names:
        for spelling in spellings(name):
            for callee in declared.get(spelling, ()):
                allowed |= spellings(callee)
    if not allowed:
        return "no_evidence"
    for candidates in known:
        if not any(spellings(c) & allowed for c in candidates):
            return "inconsistent"
    return "consistent"


# --- target side -------------------------------------------------------------


class MipsImage:
    """Procedures of a 32-bit MIPS ELF: `.pdr` entries and PIC prologues."""

    def __init__(self, path: str):
        with open(path, "rb") as f:
            elf = ELFFile(f)
            if elf["e_machine"] != "EM_MIPS" or elf.elfclass != 32:
                raise ValueError("not a 32-bit MIPS ELF")
            self.little_endian = elf.little_endian
            self.order = "<" if elf.little_endian else ">"
            text, got = elf.get_section_by_name(".text"), elf.get_section_by_name(".got")
            if text is None:
                raise ValueError("no .text section")
            self.text, self.text_addr = text.data(), text["sh_addr"]
            self.got = got.data() if got else b""
            self.got_addr = got["sh_addr"] if got else 0
            pdr = elf.get_section_by_name(".pdr")
            raw_pdr = pdr.data() if pdr else b""
            self.loads = [
                (s["p_vaddr"], s.data()) for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"
            ]
            self.segments = [
                (s["p_vaddr"], s.data())
                for s in elf.iter_segments()
                if s["p_type"] == "PT_LOAD" and not s["p_flags"] & 2
            ]
        self.words = struct.unpack(
            f"{self.order}{len(self.text) // 4}I", self.text[: len(self.text) // 4 * 4]
        )
        end = self.text_addr + len(self.words) * 4
        starts = {
            a
            for a in (
                struct.unpack_from(f"{self.order}I", raw_pdr, i)[0]
                for i in range(0, len(raw_pdr) - 3, PDR_ENTRY)
            )
            if self.text_addr <= a < end
        }
        for i in range(len(self.words) - 2):
            if (
                self.words[i] >> 16 == LUI_GP
                and self.words[i + 1] >> 16 == ADDIU_GP_GP
                and self.words[i + 2] == ADDU_GP_GP_T9
            ):
                starts.add(self.text_addr + i * 4)
        self.starts = sorted(starts)
        self.ends = dict(zip(self.starts, [*self.starts[1:], end]))
        self.index = {a: i for i, a in enumerate(self.starts)}

    def body(self, addr: int) -> tuple[int, ...]:
        lo = (addr - self.text_addr) // 4
        return self.words[lo : (self.ends[addr] - self.text_addr) // 4]

    def tokens(self, addr: int) -> list:
        return [t for t in map(token, self.body(addr)) if t is not None]

    def _gp(self, addr: int) -> int | None:
        body = self.body(addr)
        if len(body) < 2 or body[0] >> 16 != LUI_GP:
            return None
        low = body[1] & 0xFFFF
        low = low - 0x10000 if low & 0x8000 else low
        return (((body[0] & 0xFFFF) << 16) + low + addr) & 0xFFFFFFFF

    def _got_value(self, gp: int, word: int) -> int | None:
        imm = word & 0xFFFF
        imm = imm - 0x10000 if imm & 0x8000 else imm
        slot = (gp + imm - self.got_addr) & 0xFFFFFFFF
        if slot + 4 > len(self.got):
            return None
        return struct.unpack_from(f"{self.order}I", self.got, slot)[0]

    def callees(self, addr: int) -> list[int]:
        """Procedures loaded into t9 from the GOT."""
        gp = self._gp(addr)
        if gp is None:
            return []
        found = []
        for word in self.body(addr):
            if word >> 16 == 0x8F99:
                value = self._got_value(gp, word)
                if value in self.ends:
                    found.append(value)
        return found

    def read_word(self, address: int) -> int | None:
        for base, data in self.loads:
            if base <= address and address + 4 <= base + len(data):
                return struct.unpack_from(f"{self.order}I", data, address - base)[0]
        return None

    def _string_at(self, address: int) -> str | None:
        for base, data in self.segments:
            if base <= address < base + len(data):
                raw = data[address - base : address - base + 256].split(b"\0", 1)[0]
                return _printable(raw)
        return None

    def strings(self, addr: int) -> set[str]:
        """Strings the procedure addresses by `lw rX,N(gp)` + `addiu rX,rX,lo`."""
        gp = self._gp(addr)
        if gp is None:
            return set()
        body = self.body(addr)
        found = set()
        for i, word in enumerate(body):
            if word >> 26 != LW or (word >> 21) & 31 != GP:
                continue
            reg = (word >> 16) & 31
            value = self._got_value(gp, word)
            if value is None:
                continue
            for follow in body[i + 1 : i + 5]:
                if follow >> 26 == ADDIU and (follow >> 21) & 31 == reg:
                    low = follow & 0xFFFF
                    low = low - 0x10000 if low & 0x8000 else low
                    text = self._string_at((value + low) & 0xFFFFFFFF)
                    if text:
                        found.add(text)
                    break
        return found


def _printable(raw: bytes) -> str | None:
    """Text worth anchoring on: long enough to be unlikely by accident."""
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    if len(text.strip()) < MIN_STRING_LENGTH or not text.isprintable():
        text_no_ws = text.replace("\n", "").replace("\t", "")
        if len(text.strip()) < MIN_STRING_LENGTH or not text_no_ws.isprintable():
            return None
    return text


# --- inference ---------------------------------------------------------------


def _named_callees(image, addr, named):
    return [named.get(c, []) for c in image.callees(addr)]


def string_anchors(image: MipsImage, named: dict, strings: dict, declared) -> dict:
    """`strings`: library function group -> strings only it references."""
    users: dict[str, set[int]] = defaultdict(set)
    for addr in image.starts:
        for text in image.strings(addr):
            users[text].add(addr)
    taken = {n for names in named.values() for n in names}
    found: dict[int, dict] = {}
    for group, texts in sorted(strings.items()):
        names = group.split(",")
        if taken & set(names):
            continue
        sites = {next(iter(users[t])) for t in texts if len(users.get(t, ())) == 1}
        if len(sites) != 1:
            continue
        addr = sites.pop()
        if addr in named or addr in found:
            found.pop(addr, None)
            continue
        if callee_verdict(names, _named_callees(image, addr, named), declared) == "inconsistent":
            continue
        evidence = sorted(t.strip() for t in texts if image.strings(addr) & {t})
        found[addr] = {"names": names, "method": "string_anchor", "evidence": evidence}
    return found


def fuzzy_matches(
    image: MipsImage, named: dict, rules: list[Rule], declared, min_score=DEFAULT_MIN_SCORE
) -> dict:
    taken = {n for names in named.values() for n in names}
    open_rules = [r for r in rules if len(r.tokens) >= MIN_TOKENS and not taken & set(r.names)]
    target = {
        a: image.tokens(a)
        for a in image.starts
        if a not in named and _has_named_neighbours(image, a, named)
    }
    target = {a: t for a, t in target.items() if len(t) >= MIN_TOKENS * MIN_SHRINK}
    frequency = Counter(t for tokens in target.values() for t in set(tokens))
    postings = defaultdict(list)
    for addr, tokens in target.items():
        for t in set(tokens):
            postings[t].append(addr)
    total = max(1, len(target))

    scores: dict[int, dict[int, float]] = defaultdict(dict)
    for index, rule in enumerate(open_rules):
        weight = Counter()
        for t in set(rule.tokens):
            if frequency[t] and frequency[t] <= max(2, total * 0.25):
                idf = math.log(total / frequency[t])
                for addr in postings[t]:
                    weight[addr] += idf
        for addr, _ in weight.most_common(CANDIDATES_PER_RULE * 3):
            size = len(target[addr])
            if not MIN_SHRINK * len(rule.tokens) <= size <= MAX_GROWTH * len(rule.tokens):
                continue
            scores[index][addr] = lcs_length(list(rule.tokens), target[addr]) / len(rule.tokens)

    by_target: dict[int, list[tuple[float, int]]] = defaultdict(list)
    for index, candidates in scores.items():
        for addr, score in candidates.items():
            by_target[addr].append((score, index))
    found: dict[int, dict] = {}
    for index, candidates in scores.items():
        ranked = sorted(candidates.items(), key=lambda item: -item[1])
        if not ranked or ranked[0][1] < min_score:
            continue
        addr, score = ranked[0]
        if len(ranked) > 1 and score - ranked[1][1] < MIN_MARGIN:
            continue
        rivals = sorted(by_target[addr], reverse=True)
        if rivals[0][1] != index or (len(rivals) > 1 and score - rivals[1][0] < MIN_MARGIN):
            continue
        names = list(open_rules[index].names)
        if callee_verdict(names, _named_callees(image, addr, named), declared) == "inconsistent":
            continue
        found[addr] = {"names": names, "method": "fuzzy", "score": round(score, 4)}
    return found


def _has_named_neighbours(image: MipsImage, addr: int, named: dict) -> bool:
    i = image.index[addr]
    window = image.starts[max(0, i - NEIGHBOUR_WINDOW) : i + NEIGHBOUR_WINDOW + 1]
    return sum(a in named for a in window) >= MIN_NAMED_NEIGHBOURS


def infer(binary, cfg_path, named, *, string_anchor=False, fuzzy=False, dispatch=False,
          min_score=DEFAULT_MIN_SCORE) -> tuple[dict, list[str]]:
    """`{addr: {names, method, ...}}` for functions the byte rules left unnamed,
    and why any requested inference could not run."""
    notes: list[str] = []
    try:
        image = MipsImage(str(binary))
    except ValueError as exc:
        return {}, [f"experimental inference skipped: {exc}"]
    cfg = Path(cfg_path)
    declared = read_dlist(cfg.with_suffix(".dlist"))
    named = {a: [n for n in names if n] for a, names in named.items() if any(names)}
    found: dict[int, dict] = {}
    if string_anchor:
        path = cfg.with_suffix(".strs")
        if path.is_file():
            found.update(string_anchors(image, named, json.loads(path.read_text()), declared))
        else:
            notes.append(f"string anchor skipped: {path.name} is absent")
    if fuzzy:
        known = {**named, **{a: f["names"] for a, f in found.items()}}
        rules = read_rules(str(cfg.with_suffix(".yara")), image.little_endian)
        found.update(fuzzy_matches(image, known, rules, declared, min_score))
    if dispatch:
        from .dispatch import dispatch_names

        known = {**named, **{a: f["names"] for a, f in found.items()}}
        rules = read_rules(str(cfg.with_suffix(".yara")), image.little_endian)
        names, dispatch_notes = dispatch_names(image, known, rules, declared)
        found.update(names)
        notes += dispatch_notes
    return found, notes
