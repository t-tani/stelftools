"""`mkrule --experimental-strings`: the `.strs` file behind the string anchor.

For each library function of a 32-bit MIPS PIC object, the strings it addresses
through a `.rodata` GOT16 + LO16 relocation pair. Only a string exactly one
function references is kept: that is what makes it an anchor.
"""

from __future__ import annotations

import io
import json
from collections import defaultdict

import arpy
import magic
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

from ..match.experimental import MIN_STRING_LENGTH, _printable

R_MIPS_GOT16 = 9
R_MIPS_LO16 = 6


def _function_groups(elf):
    """Functions as `(start, end, "a,b")`; a size-0 alias joins its sized twin."""
    symtab = elf.get_section_by_name(".symtab")
    if symtab is None:
        return []
    sized, names = {}, defaultdict(set)
    for sym in symtab.iter_symbols():
        if sym["st_info"]["type"] == "STT_FUNC" and isinstance(sym["st_shndx"], int):
            key = (sym["st_shndx"], sym["st_value"])
            names[key].add(sym.name)
            sized[key] = max(sized.get(key, 0), sym["st_size"])
    return [
        (value, value + sized[(shndx, value)], ",".join(sorted(group)))
        for (shndx, value), group in names.items()
        if sized[(shndx, value)] and elf.get_section(shndx).name == ".text"
    ]


def object_strings(data: bytes) -> dict[str, set[str]]:
    """Function group -> strings, for one little- or big-endian MIPS object."""
    elf = ELFFile(io.BytesIO(data))
    if elf["e_machine"] != "EM_MIPS" or elf.elfclass != 32:
        return {}
    text, rel = elf.get_section_by_name(".text"), elf.get_section_by_name(".rel.text")
    if text is None or not isinstance(rel, RelocationSection):
        return {}
    groups = _function_groups(elf)
    symtab = elf.get_section(rel["sh_link"])
    body = text.data()
    order = "little" if elf.little_endian else "big"
    pending: dict[int, int] = {}
    out: dict[str, set[str]] = defaultdict(set)
    for entry in rel.iter_relocations():
        kind, offset = entry["r_info_type"], entry["r_offset"]
        if offset + 4 > len(body):
            continue
        imm = int.from_bytes(body[offset : offset + 4], order) & 0xFFFF
        sym = symtab.get_symbol(entry["r_info_sym"])
        if kind == R_MIPS_GOT16:
            pending[entry["r_info_sym"]] = imm << 16
        elif kind == R_MIPS_LO16 and entry["r_info_sym"] in pending:
            shndx = sym["st_shndx"]
            if not isinstance(shndx, int) or elf.get_section(shndx).name != ".rodata":
                continue
            low = imm - 0x10000 if imm & 0x8000 else imm
            where = (pending[entry["r_info_sym"]] + low + sym["st_value"]) & 0xFFFFFFFF
            raw = elf.get_section(shndx).data()[where : where + 256].split(b"\0", 1)[0]
            string = _printable(raw)
            if string and len(string.strip()) >= MIN_STRING_LENGTH:
                for start, end, group in groups:
                    if start <= offset < end:
                        out[group].add(string)
    return out


def collect(files: list[str]) -> dict[str, list[str]]:
    """Group -> the strings no other function in `files` references."""
    by_group: dict[str, set[str]] = defaultdict(set)
    for path in files:
        kind = magic.from_file(path, mime=True)
        if kind == "application/x-archive":
            members = [member.read() for member in arpy.Archive(path)]
        elif kind == "application/x-object":
            with open(path, "rb") as f:
                members = [f.read()]
        else:
            continue
        for data in members:
            if data[:4] == b"\x7fELF":
                for group, strings in object_strings(data).items():
                    by_group[group] |= strings
    users: dict[str, set[str]] = defaultdict(set)
    for group, strings in by_group.items():
        for string in strings:
            users[string].add(group)
    unique = {
        group: sorted(s for s in strings if len(users[s]) == 1)
        for group, strings in by_group.items()
    }
    return {group: strings for group, strings in sorted(unique.items()) if strings}


def write(files: list[str], path) -> int:
    table = collect(files)
    with open(path, "w") as f:
        json.dump(table, f, indent=0, sort_keys=True)
        f.write("\n")
    return len(table)
