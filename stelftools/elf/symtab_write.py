"""Append a synthesized `.symtab` / `.strtab` to a stripped ELF.

LIEF 0.17 cannot build a symbol table on an ELF that has none — it
writes the entries but drops every name. This module constructs the
two sections byte-for-byte and appends them, along with a relocated
section header table, past the end of the original file.

Only the section header table, the section name table, and the ELF
header's section fields are rewritten. Program headers and load
segments are untouched, so the binary stays runnable; Ghidra and IDA
read the appended `.symtab` the same way they read a native one.

An ELF with no section header table at all (`e_shnum == 0`, as MIPS
firmware binaries are often shipped) is also handled: a fresh table
holding a SHT_NULL entry plus the synthesized `.strtab`, `.symtab`,
and `.shstrtab` is built from scratch.

ELF32 and ELF64, both endiannesses, are supported. The function
symbols are emitted as STB_GLOBAL / STT_FUNC.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

SHT_NULL = 0
SHT_SYMTAB = 2
SHT_STRTAB = 3
STB_GLOBAL = 1
STT_FUNC = 2


@dataclass
class _Section:
    name_off: int
    sh_type: int
    addr: int
    size: int


def _parse(data: bytes):
    """Read the class, endianness, and section table of an ELF blob.

    `shstrtab` is `None` when the ELF carries no section header table.
    """
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    ei_class = data[4]
    ei_data = data[5]
    if ei_class not in (1, 2):
        raise ValueError(f"unknown ELF class: {ei_class}")
    endian = "<" if ei_data == 1 else ">"
    is64 = ei_class == 2
    if is64:
        e_shoff = struct.unpack_from(endian + "Q", data, 0x28)[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
            endian + "HHH", data, 0x3a)
    else:
        e_shoff = struct.unpack_from(endian + "I", data, 0x20)[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
            endian + "HHH", data, 0x2e)
    sections = []
    shstrtab = None
    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        if is64:
            sh_name, sh_type = struct.unpack_from(endian + "II", data, base)
            sh_addr = struct.unpack_from(endian + "Q", data, base + 0x10)[0]
            sh_offset = struct.unpack_from(endian + "Q", data, base + 0x18)[0]
            sh_size = struct.unpack_from(endian + "Q", data, base + 0x20)[0]
        else:
            sh_name, sh_type = struct.unpack_from(endian + "II", data, base)
            sh_addr = struct.unpack_from(endian + "I", data, base + 0x0c)[0]
            sh_offset = struct.unpack_from(endian + "I", data, base + 0x10)[0]
            sh_size = struct.unpack_from(endian + "I", data, base + 0x14)[0]
        sections.append(_Section(sh_name, sh_type, sh_addr, sh_size))
        if i == e_shstrndx:
            shstrtab = (sh_offset, sh_size)
    return {
        "endian": endian, "is64": is64, "e_shoff": e_shoff,
        "e_shentsize": e_shentsize, "e_shnum": e_shnum,
        "e_shstrndx": e_shstrndx, "sections": sections,
        "shstrtab": shstrtab,
    }


def section_index_for_addr(data: bytes, addr: int) -> int:
    """Return the section index whose address range covers `addr`, or 0.

    A function symbol must name its containing section so the consumer
    treats it as defined code rather than an absolute label. An ELF
    with no section header table has no such index, so every symbol
    falls back to 0; IDA and Ghidra still read the names.
    """
    meta = _parse(data)
    for idx, sec in enumerate(meta["sections"]):
        if sec.addr and sec.addr <= addr < sec.addr + sec.size:
            return idx
    return 0


def _align(value: int, alignment: int) -> int:
    rem = value % alignment
    return value if rem == 0 else value + (alignment - rem)


def append_symtab(data: bytes, symbols: list[tuple[int, int, str]]) -> bytes:
    """Return `data` with a `.symtab` / `.strtab` appended.

    `symbols` is a list of (virtual_address, section_index, name). A
    leading STN_UNDEF entry is prepended to the symbol table as the ELF
    spec requires.

    An ELF that already carries a section header table keeps it; the
    new sections are appended and the section name table is relocated.
    An ELF with no section header table gets a fresh one built from
    scratch.
    """
    meta = _parse(data)
    if meta["e_shnum"] == 0 or meta["shstrtab"] is None:
        return _append_symtab_no_sht(data, meta, symbols)
    return _append_symtab_with_sht(data, meta, symbols)


def _build_symtab_blob(endian, is64, symbols):
    """Return the `.strtab` and `.symtab` section bytes for `symbols`."""
    strtab = bytearray(b"\x00")
    name_offsets = []
    for _addr, _shndx, name in symbols:
        name_offsets.append(len(strtab))
        strtab += name.encode("utf-8", "replace") + b"\x00"

    sym_entsize = 24 if is64 else 16
    symtab = bytearray(sym_entsize)  # STN_UNDEF
    for (addr, shndx, _name), name_off in zip(symbols, name_offsets):
        st_info = (STB_GLOBAL << 4) | STT_FUNC
        if is64:
            symtab += struct.pack(
                endian + "IBBHQQ", name_off, st_info, 0, shndx, addr, 0)
        else:
            symtab += struct.pack(
                endian + "IIIBBH", name_off, addr, 0, st_info, 0, shndx)
    return bytes(strtab), bytes(symtab), sym_entsize


def _append_symtab_with_sht(data, meta, symbols):
    """Append `.symtab` / `.strtab` to an ELF that has a section table."""
    endian, is64 = meta["endian"], meta["is64"]
    strtab, symtab, sym_entsize = _build_symtab_blob(endian, is64, symbols)

    old_shstr_off, old_shstr_size = meta["shstrtab"]
    old_shstr = data[old_shstr_off:old_shstr_off + old_shstr_size]
    symtab_name_off = len(old_shstr)
    new_shstr = bytes(old_shstr) + b".symtab\x00.strtab\x00"
    strtab_name_off = symtab_name_off + len(b".symtab\x00")

    out = bytearray(data)
    strtab_off = _align(len(out), 4)
    out += b"\x00" * (strtab_off - len(out))
    out += strtab
    symtab_off = _align(len(out), 4)
    out += b"\x00" * (symtab_off - len(out))
    out += symtab
    shstr_off = _align(len(out), 4)
    out += b"\x00" * (shstr_off - len(out))
    out += new_shstr

    entsize = meta["e_shentsize"]
    new_shoff = _align(len(out), 8)
    out += b"\x00" * (new_shoff - len(out))

    # Copy the original section headers verbatim, then repoint the
    # section name table to the relocated, extended copy.
    old_sht = bytearray(
        data[meta["e_shoff"]:meta["e_shoff"] + meta["e_shnum"] * entsize])
    shstrndx = meta["e_shstrndx"]
    if is64:
        struct.pack_into(endian + "Q", old_sht, shstrndx * entsize + 0x18,
                         shstr_off)
        struct.pack_into(endian + "Q", old_sht, shstrndx * entsize + 0x20,
                         len(new_shstr))
    else:
        struct.pack_into(endian + "I", old_sht, shstrndx * entsize + 0x10,
                         shstr_off)
        struct.pack_into(endian + "I", old_sht, shstrndx * entsize + 0x14,
                         len(new_shstr))
    out += old_sht

    strtab_idx = meta["e_shnum"]
    symtab_idx = meta["e_shnum"] + 1
    out += _section_header(endian, is64, strtab_name_off, SHT_STRTAB,
                           strtab_off, len(strtab), link=0, info=0,
                           addralign=1, entsize=0)
    out += _section_header(endian, is64, symtab_name_off, SHT_SYMTAB,
                           symtab_off, len(symtab), link=strtab_idx, info=1,
                           addralign=4, entsize=sym_entsize)

    new_shnum = meta["e_shnum"] + 2
    if is64:
        struct.pack_into(endian + "Q", out, 0x28, new_shoff)
        struct.pack_into(endian + "H", out, 0x3c, new_shnum)
    else:
        struct.pack_into(endian + "I", out, 0x20, new_shoff)
        struct.pack_into(endian + "H", out, 0x30, new_shnum)
    return bytes(out)


def _append_symtab_no_sht(data, meta, symbols):
    """Append `.symtab` / `.strtab` to an ELF that has no section table.

    A four-entry section header table is synthesized: a mandatory
    SHT_NULL entry at index 0, then `.strtab`, `.symtab`, and the
    `.shstrtab` that names them. The ELF header's `e_shoff`,
    `e_shnum`, `e_shentsize`, and `e_shstrndx` are filled in.
    """
    endian, is64 = meta["endian"], meta["is64"]
    strtab, symtab, sym_entsize = _build_symtab_blob(endian, is64, symbols)

    # Section name table. Index 0 is the empty name for SHT_NULL.
    new_shstr = b"\x00.strtab\x00.symtab\x00.shstrtab\x00"
    strtab_name_off = new_shstr.index(b".strtab\x00")
    symtab_name_off = new_shstr.index(b".symtab\x00")
    shstrtab_name_off = new_shstr.index(b".shstrtab\x00")

    out = bytearray(data)
    strtab_off = _align(len(out), 4)
    out += b"\x00" * (strtab_off - len(out))
    out += strtab
    symtab_off = _align(len(out), 4)
    out += b"\x00" * (symtab_off - len(out))
    out += symtab
    shstr_off = _align(len(out), 4)
    out += b"\x00" * (shstr_off - len(out))
    out += new_shstr

    entsize = 64 if is64 else 40
    new_shoff = _align(len(out), 8)
    out += b"\x00" * (new_shoff - len(out))

    # Index 0 SHT_NULL, 1 .strtab, 2 .symtab, 3 .shstrtab.
    out += _section_header(endian, is64, 0, SHT_NULL, 0, 0,
                           link=0, info=0, addralign=0, entsize=0)
    out += _section_header(endian, is64, strtab_name_off, SHT_STRTAB,
                           strtab_off, len(strtab), link=0, info=0,
                           addralign=1, entsize=0)
    out += _section_header(endian, is64, symtab_name_off, SHT_SYMTAB,
                           symtab_off, len(symtab), link=1, info=1,
                           addralign=4, entsize=sym_entsize)
    out += _section_header(endian, is64, shstrtab_name_off, SHT_STRTAB,
                           shstr_off, len(new_shstr), link=0, info=0,
                           addralign=1, entsize=0)

    new_shnum = 4
    new_shstrndx = 3
    if is64:
        struct.pack_into(endian + "Q", out, 0x28, new_shoff)
        struct.pack_into(endian + "H", out, 0x3a, entsize)
        struct.pack_into(endian + "H", out, 0x3c, new_shnum)
        struct.pack_into(endian + "H", out, 0x3e, new_shstrndx)
    else:
        struct.pack_into(endian + "I", out, 0x20, new_shoff)
        struct.pack_into(endian + "H", out, 0x2e, entsize)
        struct.pack_into(endian + "H", out, 0x30, new_shnum)
        struct.pack_into(endian + "H", out, 0x32, new_shstrndx)
    return bytes(out)


def _section_header(endian, is64, name_off, sh_type, offset, size, *,
                    link, info, addralign, entsize) -> bytes:
    if is64:
        return struct.pack(endian + "IIQQQQIIQQ", name_off, sh_type, 0, 0,
                           offset, size, link, info, addralign, entsize)
    return struct.pack(endian + "IIIIIIIIII", name_off, sh_type, 0, 0,
                       offset, size, link, info, addralign, entsize)
