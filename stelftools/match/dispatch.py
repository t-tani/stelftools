"""Experimental: name the wrappers a threads library puts in front of libc.

A user-level threads library can wrap libc so the program never calls the body
a byte rule named: `read` holds no call site, while the unnamed wrapper that
loads it from a function table holds them all. A wrapper is recognised by what
it does, `lw r,N(gp); lw r,K(r); move t9,r; jalr t9`, and a table only counts
when many procedures read it that way. This module:

1. settles candidate groups from what the code calls: `recv|send` by whether its
   callee reaches `recvfrom` or `sendto`, `exect|execve` by which name its callers
   were built against;
2. gives each wrapper the name of the table entry it calls;
3. reads a variadic wrapper of a `v*` function as the function it fronts: one
   that saves a1-a3 and calls `vfprintf` is `fprintf`, not a wrapper of `vfprintf`.

Names stay unique, since a consumer looking a name up gets one address: the
entry holding the most calls keeps the public name, the body becomes `__libc_x`
and any further wrapper `x__stub_<addr>`. The sidecar records what was renamed.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass

from .experimental import GP, LW, spellings

SP = 29
T9 = 25
A0, A1, A2, A3 = 4, 5, 6, 7
SW = 0x2B
JALR_T9 = 0x0320F809
MIN_TABLE_WRAPPERS = 16
SIGNATURE_WINDOW = 24
#: A variadic wrapper builds a `va_list` and calls the `v*` form in the table.
VARIADIC_FRONT = {"vfprintf": "fprintf", "vprintf": "printf"}


@dataclass(frozen=True)
class Wrapper:
    table: int
    offset: int
    target: int


def _s16(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def _is_move_to_t9(word: int, reg: int) -> bool:
    return word in (reg << 21 | T9 << 11 | 0x21, reg << 21 | T9 << 11 | 0x25)


def table_calls(image, addr: int) -> set[tuple[int, int]]:
    """`(table, offset)` of each `lw r,N(gp); lw r,K(r); move t9,r; jalr t9`."""
    gp = image._gp(addr)
    if gp is None:
        return set()
    body = image.body(addr)
    found = set()
    for i, word in enumerate(body):
        if word >> 26 != LW or (word >> 21) & 31 != GP:
            continue
        reg = (word >> 16) & 31
        table = image._got_value(gp, word)
        if table is None:
            continue
        for j in range(i + 1, min(i + 3, len(body))):
            load = body[j]
            if load >> 26 == LW and (load >> 21) & 31 == reg and (load >> 16) & 31 == reg:
                tail = body[j + 1 : j + 8]
                moved = [k for k, w in enumerate(tail) if _is_move_to_t9(w, reg)]
                if moved and JALR_T9 in tail[moved[0] :]:
                    found.add((table, _s16(load & 0xFFFF)))
                break
    return found


def find_wrappers(image) -> dict[int, Wrapper]:
    """Procedures making exactly one call through a table that many read."""
    calls = {a: table_calls(image, a) for a in image.starts}
    per_table = Counter(t for found in calls.values() if len(found) == 1 for t, _ in found)
    wrappers = {}
    for addr, found in calls.items():
        if len(found) != 1:
            continue
        table, offset = next(iter(found))
        if per_table[table] < MIN_TABLE_WRAPPERS:
            continue
        target = image.read_word((table + offset) & 0xFFFFFFFF)
        if target in image.ends:
            wrappers[addr] = Wrapper(table, offset, target)
    return wrappers


def _bare(names) -> set[str]:
    return {n.lstrip("_") for n in names}


def _declared_for(name: str, declared) -> set[str]:
    out = set()
    for spelling in spellings(name):
        for callee in declared.get(spelling, ()):
            out |= spellings(callee)
    return out


def _callee_names(image, addr, named, wrappers) -> list[list[str]]:
    """Named callees of `addr`, seeing through a wrapper to its table entry."""
    out = []
    for callee in image.callees(addr):
        if callee in named:
            out.append(named[callee])
        elif callee in wrappers and wrappers[callee].target in named:
            out.append(named[wrappers[callee].target])
    return out


def _narrow_by_callees(names, callee_names, declared) -> list[str] | None:
    """The one candidate whose object calls every named callee, or None."""
    if not callee_names:
        return None
    fits = [
        n for n in names
        if (allowed := _declared_for(n, declared))
        and all(any(spellings(c) & allowed for c in group) for group in callee_names)
    ]
    return fits if fits and len(_bare(fits)) == 1 else None


def _narrow_by_callers(names, caller_groups, declared) -> list[str] | None:
    """The one candidate some caller was built against, when no other is."""
    called = []
    for name in names:
        wanted = spellings(name)
        if any(any(wanted & _declared_for(c, declared) for c in group) for group in caller_groups):
            called.append(name)
    return called if called and len(_bare(called)) == 1 else None


def settle_groups(image, named, wrappers, rules, declared, callers) -> dict[int, dict]:
    """Candidate groups the code around them can settle; see the module docstring."""
    found: dict[int, dict] = {}
    entry_callers = defaultdict(list, {k: list(v) for k, v in callers.items()})
    for addr, wrapper in wrappers.items():
        entry_callers[wrapper.target].extend(callers.get(addr, ()))

    for addr, names in named.items():
        if len(_bare(names)) < 2:
            continue
        by_callees = _narrow_by_callees(names, _callee_names(image, addr, named, wrappers), declared)
        groups = [named[c] for c in entry_callers.get(addr, ()) if c in named]
        by_callers = _narrow_by_callers(names, groups, declared)
        if by_callees and by_callers and _bare(by_callees) != _bare(by_callers):
            continue
        settled = by_callees or by_callers
        if settled:
            how = "callee" if by_callees else "caller"
            found[addr] = {"names": settled, "method": "dispatch",
                           "evidence": [f"settled from {','.join(names)} by {how}"]}

    # a group the unique-site rule dropped: identical bytes at several places
    by_tokens = {r.tokens: r for r in rules}
    proposed: dict[str, list[tuple[int, list[str], tuple]]] = defaultdict(list)
    for addr in image.starts:
        if addr in named or addr in wrappers:
            continue
        rule = by_tokens.get(tuple(image.tokens(addr)))
        if rule is None:
            continue
        settled = _narrow_by_callees(
            list(rule.names), _callee_names(image, addr, named, wrappers), declared
        )
        if settled:
            proposed[",".join(sorted(settled))].append((addr, settled, rule.names))
    taken = {n for names in named.values() for n in names}
    for _, sites in proposed.items():
        if len(sites) == 1 and not taken & set(sites[0][1]):
            addr, settled, origin = sites[0]
            found[addr] = {"names": settled, "method": "dispatch",
                           "evidence": [f"settled from {','.join(origin)} by callee"]}
    return found


def is_variadic(body) -> bool:
    """a1-a3 stored into the caller's frame: the start of a `va_list`."""
    frame = None
    saved = set()
    for word in body[:SIGNATURE_WINDOW]:
        if word >> 16 == 0x27BD and frame is None:
            frame = -_s16(word & 0xFFFF)
        elif frame and word >> 26 == SW and (word >> 21) & 31 == SP:
            reg, off = (word >> 16) & 31, _s16(word & 0xFFFF)
            if reg in (A0, A1, A2, A3) and off == frame + (reg - A0) * 4:
                saved.add(reg)
    return bool(frame) and {A1, A2, A3} <= saved


def _variadic_fronts(image, wrappers, known) -> dict[int, str]:
    """Wrapper -> public name, for a name exactly one variadic wrapper fronts."""
    sites = defaultdict(list)
    for addr, wrapper in wrappers.items():
        names = known.get(wrapper.target, ())
        fronted = next((VARIADIC_FRONT[n] for n in names if n in VARIADIC_FRONT), None)
        if fronted and addr not in known and is_variadic(image.body(addr)):
            sites[fronted].append(addr)
    return {found[0]: name for name, found in sites.items() if len(found) == 1}


def unique_names(image, named, found, wrappers) -> int:
    """Give every symbol one address; returns how many addresses were renamed.

    Rewrites `found` in place. An address the byte rules named gets a `renamed`
    entry, so its proof is not reported as an inference.
    """
    calls = Counter(c for a in image.starts for c in image.callees(a))
    sites: dict[tuple, list[int]] = defaultdict(list)
    for addr in {*named, *found}:
        names = found[addr]["names"] if addr in found else named[addr]
        sites[tuple(sorted(names))].append(addr)
    renamed = 0
    for names, addrs in sites.items():
        if len(addrs) < 2:
            continue
        # most calls first; among equals a wrapper, since the program enters there
        addrs.sort(key=lambda a: (-calls[a], a not in wrappers, a))
        body_named = False
        for addr in addrs[1:]:
            if addr not in wrappers and not body_named:
                role, new = "body", [f"__libc_{n}" for n in names]
                body_named = True
            else:
                role, new = "stub", [f"{n}__stub_{addr:x}" for n in names]
            base = found.get(addr) or {"method": "renamed"}
            found[addr] = {**base, "names": new, "role": role, "renamed_from": list(names)}
            renamed += 1
        first = addrs[0]
        if first in found:
            found[first] = {**found[first], "role": "entry"}
    return renamed


def dispatch_names(image, named, rules, declared) -> tuple[dict[int, dict], list[str]]:
    wrappers = find_wrappers(image)
    callers = defaultdict(list)
    for addr in image.starts:
        for callee in set(image.callees(addr)):
            callers[callee].append(addr)

    found = settle_groups(image, named, wrappers, rules, declared, callers)
    known = {**named, **{a: f["names"] for a, f in found.items()}}
    fronts = _variadic_fronts(image, wrappers, known)

    refused = []
    for addr, wrapper in wrappers.items():
        names = known.get(wrapper.target)
        if addr in known or not names:
            continue
        target = f"{wrapper.target:#x}"
        evidence = [f"table {wrapper.table:#x}+{wrapper.offset} -> {target}"]
        if addr in fronts:
            found[addr] = {"names": [fronts[addr]], "method": "dispatch", "target": target,
                           "evidence": [*evidence, f"variadic front of {names[0]}"]}
            continue
        if any(n in VARIADIC_FRONT for n in names) and is_variadic(image.body(addr)):
            continue
        # a caller with a known object must have been built against this name
        wanted = set().union(*(spellings(n) for n in names))
        object_callers = [
            c for caller in callers.get(addr, ()) if caller in known
            for c in known[caller] if _declared_for(c, declared)
        ]
        if object_callers and not any(wanted & _declared_for(c, declared) for c in object_callers):
            refused.append(f"{addr:#x} {names[0]}")
            continue
        found[addr] = {"names": list(names), "method": "dispatch", "target": target,
                       "evidence": evidence}
    renamed = unique_names(image, known, found, wrappers)
    notes = [f"dispatch: {len(wrappers)} wrappers, {len(refused)} refused on caller evidence"
             + (f" ({', '.join(refused)})" if refused else "")
             + f", {renamed} renamed to keep names unique"]
    return found, notes


__all__ = ["VARIADIC_FRONT", "Wrapper", "dispatch_names", "find_wrappers", "is_variadic",
           "unique_names"]
