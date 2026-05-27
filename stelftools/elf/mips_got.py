"""Resolve the MIPS Global Offset Table into a (got_addr, gp_offset, callee)
table that mirrors what ``llvm-readelf -A`` reports for the Local entries.

ident's disassembler uses this map to turn ``lw $reg, gp_offset($gp)``
loads into the concrete callee addresses they resolve to at link time,
so MIPS call sites can be parsed without an external toolchain.

Two paths cover stripped and unstripped firmware:

* :func:`_mips_got_map_from_data` is the shared core. Given the raw
  ``.got`` bytes and ``.MIPS.RegInfo`` blob, it walks the table.
* :func:`_mips_got_map` calls it via the section-header path
  (``.got`` + ``.reginfo``).
* :func:`_mips_got_map_from_segments` is the program-header fallback
  for section-header-stripped ELFs; it derives the GOT bounds from
  ``DT_PLTGOT`` + the MIPS ABI counts and GP from the
  ``PT_MIPS_REGINFO`` segment.
"""

import struct

from elftools.elf.elffile import ELFFile


def _mips_got_map(target_path):
    # Reproduce `llvm-readelf -A` Local-entries table directly from .got
    # and .reginfo, so MIPS GOT resolution does not need an external
    # toolchain. Returns the same shape func_ident expects:
    # [(got_addr_hex, abs_gp_offset_decimal_str, callee_addr_hex), ...].
    #
    # The section-header path runs when .got and .reginfo are present.
    # Section-header-stripped firmware ELFs carry the same data in the
    # PT_DYNAMIC and PT_MIPS_REGINFO segments, so a program-header
    # fallback derives the GOT bounds and GP value from there.
    with open(target_path, 'rb') as fp:
        e = ELFFile(fp)
        endian = '<' if e['e_ident']['EI_DATA'] == 'ELFDATA2LSB' else '>'
        word = 4 if e['e_ident']['EI_CLASS'] == 'ELFCLASS32' else 8
        got = e.get_section_by_name('.got')
        reginfo = e.get_section_by_name('.reginfo')
        if got is not None and reginfo is not None:
            return _mips_got_map_from_data(
                endian, word, got['sh_addr'], got.data(), reginfo.data())
    return _mips_got_map_from_segments(target_path, endian, word)


def _mips_got_map_from_data(endian, word, got_base, got_data, reginfo_data):
    # Build the GOT map from the raw GOT bytes and the MIPS_REGINFO
    # blob. Shared by the section-header path and the program-header
    # fallback, which differ only in how they locate these two blobs.
    got_map = []
    word_fmt = endian + ('I' if word == 4 else 'Q')
    # MIPS_REGINFO: ri_gprmask(4) + ri_cprmask[4]*4 + ri_gp_value(4|8)
    if len(reginfo_data) >= 24 and word == 4:
        gp_value = struct.unpack(endian + 'I 4I I', reginfo_data[:24])[5]
    elif len(reginfo_data) >= 40 and word == 8:
        gp_value = struct.unpack(endian + 'I 4I Q', reginfo_data[:32])[5]
    else:
        return got_map
    for i in range(len(got_data) // word):
        got_entry_addr = got_base + i * word
        callee = struct.unpack_from(word_fmt, got_data, i * word)[0]
        gp_offset_abs = abs(gp_value - got_entry_addr)
        got_map.append([
            '%08x' % got_entry_addr,
            str(gp_offset_abs),
            '%08x' % callee,
        ])
    return got_map


def _mips_got_map_from_segments(target_path, endian, word):
    # Program-header fallback for section-header-stripped MIPS ELFs.
    # DT_PLTGOT gives the GOT base; the GOT entry count is the MIPS ABI
    # formula DT_MIPS_LOCAL_GOTNO + (DT_MIPS_SYMTABNO - DT_MIPS_GOTSYM).
    # GP comes from the PT_MIPS_REGINFO segment.
    with open(target_path, 'rb') as fp:
        e = ELFFile(fp)
        # Virtual-address-to-file-offset map over the PT_LOAD segments.
        loads = []
        reginfo_data = b''
        dynamic = None
        for s in e.iter_segments():
            ptype = s.header['p_type']
            if ptype == 'PT_LOAD':
                loads.append((s.header['p_vaddr'],
                              s.header['p_offset'],
                              s.header['p_filesz']))
            elif ptype in ('PT_MIPS_REGINFO', 0x70000000):
                reginfo_data = s.data()
            elif ptype == 'PT_DYNAMIC':
                dynamic = s
        if not reginfo_data or not loads or dynamic is None:
            return []

        def vaddr_to_offset(va):
            for vaddr, off, filesz in loads:
                if vaddr <= va < vaddr + filesz:
                    return off + (va - vaddr)
            return None

        dyn = {}
        for tag in dynamic.iter_tags():
            dyn[tag.entry.d_tag] = tag.entry.d_val
        got_base = dyn.get('DT_PLTGOT')
        local_gotno = dyn.get('DT_MIPS_LOCAL_GOTNO')
        symtabno = dyn.get('DT_MIPS_SYMTABNO')
        gotsym = dyn.get('DT_MIPS_GOTSYM')
        if None in (got_base, local_gotno, symtabno, gotsym):
            return []
        got_entries = local_gotno + (symtabno - gotsym)
        got_off = vaddr_to_offset(got_base)
        if got_off is None:
            return []
        fp.seek(got_off)
        got_data = fp.read(got_entries * word)
    return _mips_got_map_from_data(
        endian, word, got_base, got_data, reginfo_data)
