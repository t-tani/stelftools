"""EM_PPC64 (PowerPC 64-bit) relocation wildcarding.

Each PPC64 relocation is processed against a 4-byte-aligned offset
(``offset // 4 * 4``) because the 64-bit ELF ABI lets relocations sit
on byte boundaries inside an instruction while the instruction itself
is fixed-width 32-bit.

Reloc type values cross-checked against mold's elf.h (commit b7102d2).
Reference: https://github.com/rui314/mold/blob/b7102d26ca42c7d72838f64c82835cb6d7ccdd7b/src/elf.h
"""

import collections
import logging
import re

R_PPC64_NONE                = 0x00
R_PPC64_REL24               = 0x0a
R_PPC64_REL14               = 0x0b
R_PPC64_REL32               = 0x1a
R_PPC64_TOC16_LO            = 0x30
R_PPC64_TOC16_HA            = 0x32
R_PPC64_TOC16_DS            = 0x3f
R_PPC64_TOC16_LO_DS         = 0x40
R_PPC64_TLS                 = 0x43
R_PPC64_TPREL16_LO          = 0x46
R_PPC64_TPREL16_HA          = 0x48
R_PPC64_GOT_TLSGD16         = 0x4f
R_PPC64_GOT_TPREL16_DS      = 0x57
R_PPC64_GOT_TPREL16_LO_DS   = 0x58
R_PPC64_GOT_TPREL16_HA      = 0x5a
R_PPC64_TLSGD               = 0x6b
R_PPC64_REL16_LO            = 0xfa
R_PPC64_REL16_HA            = 0xfc


def apply_relocation(textsec, name, offset, rtype,
                    reloc_info, checked_offsets, ei_data, fname):
    fix_offset = (offset // 4) * 4
    if rtype in [R_PPC64_NONE]:
        return
    elif rtype in [R_PPC64_TOC16_LO, R_PPC64_TOC16_HA, R_PPC64_TOC16_DS, R_PPC64_TOC16_LO_DS,
                   R_PPC64_TPREL16_HA, R_PPC64_TPREL16_LO,
                   R_PPC64_GOT_TPREL16_HA, R_PPC64_GOT_TPREL16_LO_DS, R_PPC64_GOT_TPREL16_DS,
                   R_PPC64_GOT_TLSGD16, R_PPC64_REL16_LO, R_PPC64_REL16_HA]:
        textsec[name][fix_offset:fix_offset + 4] = ['??', '??', '??', '??']
    elif rtype in [R_PPC64_REL14]:
        textsec[name][fix_offset:fix_offset + 4] = ['??', '??', '??', '??']
    elif rtype in [R_PPC64_REL24]:
        _0_7byte = textsec[name][fix_offset:fix_offset+1][0][0]
        # 4? xx xx xx xx : bl instruction
        # 60 00 00 00 00 : nop
        textsec[name][fix_offset:fix_offset + 4] = ['( 60 | ' + _0_7byte+'? )', '??', '??', '??']
        textsec[name][fix_offset+4:fix_offset + 8] = ['??', '??', '??', '??']
    elif rtype in [R_PPC64_REL32, R_PPC64_TLS, R_PPC64_TLSGD]:
        textsec[name][fix_offset:fix_offset + 4] = ['??', '??', '??', '??']
    else:
        logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, fix_offset, fname)
        exit(-1)


def build_opd_dict(e, sections, symtab, textsec):
    """Walk ``.opd`` and produce ``{func_name: {func_opecode, func_size}}``.

    PPC64 stores function descriptors in ``.opd`` and the actual code in
    ``.text``. Each STT_FUNC symbol whose section index lands in
    ``.opd`` corresponds to a function whose bytes live inside
    ``.text``. The dict returned here drives a parallel insert path in
    :mod:`stelftools.mkrule` that bypasses the main symbol loop; an
    empty dict (no ``.opd`` section) means the main loop runs normally.
    """
    opd_present = any(sec.name == '.opd' for sec in sections)
    if not opd_present:
        return {}

    _ndx_list = []
    for sym in symtab.iter_symbols():
        if sym['st_info']['type'] == 'STT_FUNC' and sym['st_info']['bind'] == 'STB_LOCAL' \
                and sym['st_size'] == 0:
            _ndx_list.append(sym['st_shndx'])
        if sym['st_info']['type'] == 'STT_FUNC' and sym['st_info']['bind'] == 'STB_GLOBAL':
            _ndx_list.append(sym['st_shndx'])

    opd_func_info = {}
    for ndx in collections.Counter(_ndx_list).keys():
        _target_sec = e.get_section(ndx)
        if _target_sec.name == '.opd':
            for sym in symtab.iter_symbols():
                if len(sym.name) > 0 and sym['st_info']['type'] == 'STT_FUNC' \
                        and sym['st_other']['visibility'] in ['STV_DEFAULT', 'STV_HIDDEN'] \
                        and sym['st_shndx'] != 'SHN_UNDEF':
                    opd_func_info[sym.name] = sym.entry

    f_order_in_sec = {}
    for v in opd_func_info.values():
        f_order_in_sec.setdefault(v['st_shndx'], []).insert(0, v['st_value'])

    opd_func_dict = {}
    for ndx in f_order_in_sec.keys():
        ndx_func_offset = 0
        for ndx_in_val in sorted(set(f_order_in_sec[ndx])):
            for sym_name, sym_entry in opd_func_info.items():
                if sym_entry['st_shndx'] == ndx and sym_entry['st_value'] == ndx_in_val:
                    if sym_name == 'free_mem':
                        continue
                    if ndx_func_offset == 0:
                        _func_offset = ndx_func_offset
                    else:
                        _mod = (ndx_func_offset % 16)
                        if _mod == 0:
                            _func_offset = ndx_func_offset
                        else:
                            _func_offset = (ndx_func_offset // 16) * 16 + 16
                    func_opecode = textsec['.text'][_func_offset:_func_offset+sym_entry['st_size']]
                    func_size = len(func_opecode)
                    opd_func_dict[sym_name] = {'func_opecode': func_opecode, 'func_size': func_size}
                    ndx_func_offset = _func_offset + sym_entry['st_size']
    return opd_func_dict


def retarget_section(e, sym, target_sec, textsec):
    """When a STT_FUNC's recorded section is ``.opd`` but its code lives
    in ``.text`` / ``.text.unlikely``, redirect ``target_sec`` so the
    opecode slice lands on real instructions. Returns
    ``(target_sec, fix_sec_flag)``; the flag tells the caller to slice
    the alternative section from offset 0 rather than from
    ``st_value - sh_addr``.
    """
    fix_sec_flag = False
    if not target_sec.name in textsec.keys() \
            and target_sec.name in ['.opd']:
        if '.text' in textsec.keys():
            if len(textsec['.text']) != 0 and sym.entry['st_value'] == 0:
                target_sec = e.get_section_by_name('.text')
            elif '.text.unlikely' in textsec.keys() \
                    and len(textsec['.text.unlikely']) != 0 and len(textsec['.text.unlikely']) != 0:
                target_sec = e.get_section_by_name('.text.unlikely')
                fix_sec_flag = True
            else:
                for _sec_name in textsec.keys():
                    if re.match(sym.name, _sec_name):
                        target_sec = e.get_section_by_name(_sec_name)
                if target_sec.name == '.opd' and '.text.unlikely' in textsec.keys():
                    if len(textsec['.text.unlikely']) != 0:
                        target_sec = e.get_section_by_name('.text.unlikely')
            if target_sec.name == '.opd':  # force overwrite
                target_sec = e.get_section_by_name('.text')
    return target_sec, fix_sec_flag
