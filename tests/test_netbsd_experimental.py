"""Experimental inference, the content-keyed rule cache, and weak aliases of size 0."""
from __future__ import annotations

import itertools
from types import SimpleNamespace

import pytest

from stelftools.generate import opcodes
from stelftools.match import experimental as ex
from stelftools.match import yara as match_yara


def _dp_lcs(a, b):
    row = [0] * (len(b) + 1)
    for x in a:
        prev = 0
        for j, y in enumerate(b, 1):
            prev, row[j] = row[j], prev + 1 if x == y else max(row[j], row[j - 1])
    return row[-1]


@pytest.mark.parametrize(
    ("a", "b"),
    [(list(x), list(y)) for x, y in itertools.product(["", "abc", "aabca", "xyz"], repeat=2)]
    + [(list("phkmalloc"), list("ph_k_m_al_loc__")), (list(range(90)), list(range(0, 180, 2)))],
)
def test_lcs_length_agrees_with_the_plain_dp(a, b):
    assert ex.lcs_length(a, b) == _dp_lcs(a, b)


def test_token_erases_what_linking_moves_and_keeps_registers():
    assert ex.token(0) is None
    assert ex.token(0x8F998000) == ex.token(0x8F82FFFC) == ex.SLOT  # lw t9/v0,N(gp)
    assert ex.token(0x24420004) == ex.token(0x24427FFF)  # addiu v0,v0,N
    assert ex.token(0x24420004) != ex.token(0x24630004)  # addiu v1,v1,N
    assert ex.token(0x10400003) == ex.token(0x10400070)  # beqz v0,N
    assert ex.token(0x0320F809) == 0x0320F809  # jalr t9


def test_rule_tokens_read_a_little_endian_pattern_with_masks():
    # lui gp,?; lw t9,?(gp) masked whole; addiu v0,v0,?; nop
    pattern = "?? ?? 1C 3C ?? ?? ?? ?? ?? ?? 42 24 00 00 00 00"
    assert ex.rule_tokens(pattern) == [0x3C1C, ex.SLOT, 0x2442]
    assert ex.rule_tokens("?? ?? 1C") is None
    assert ex.rule_tokens("[1-2] 00 00 00") is None


def test_read_rules_strips_the_space_after_an_alias_comma(tmp_path):
    path = tmp_path / "r.yara"
    path.write_text(
        'rule a_1 {\n\tmeta:\n\t\taliases = "BF_ecb, CAST_ecb"\n\tstrings:\n'
        "\t\t$pattern = { 09 00 E0 03 }\n\tcondition:\n\t\t$pattern\n}\n"
    )
    assert ex.read_rules(str(path))[0].names == ("BF_ecb", "CAST_ecb")


class FakeImage:
    """Enough of MipsImage for the selection rules."""

    def __init__(self, tokens, callees=None, strings=None):
        self._tokens, self._callees, self._strings = tokens, callees or {}, strings or {}
        self.starts = sorted(tokens)
        self.index = {a: i for i, a in enumerate(self.starts)}

    def tokens(self, addr):
        return self._tokens[addr]

    def callees(self, addr):
        return self._callees.get(addr, [])

    def strings(self, addr):
        return self._strings.get(addr, set())


BODY = list(range(100, 140))
NOISE = list(range(500, 540))
NAMED = {10: ["x"], 20: ["y"], 40: ["z"]}


def _image(**kw):
    return FakeImage({10: NOISE, 20: NOISE, 30: BODY + [999, 998], 40: NOISE, 50: NOISE}, **kw)


def test_fuzzy_names_a_patched_copy_and_records_its_score():
    found = ex.fuzzy_matches(_image(), NAMED, [ex.Rule(("malloc",), tuple(BODY))], {})
    assert found == {30: {"names": ["malloc"], "method": "fuzzy", "score": 1.0}}


def test_fuzzy_refuses_two_equally_good_sites():
    image = FakeImage({10: NOISE, 20: NOISE, 30: BODY, 35: BODY, 40: NOISE})
    assert ex.fuzzy_matches(image, NAMED, [ex.Rule(("malloc",), tuple(BODY))], {}) == {}


def test_fuzzy_refuses_a_low_score_and_a_short_rule():
    assert ex.fuzzy_matches(_image(), NAMED, [ex.Rule(("m",), tuple(BODY[:20] + NOISE[:20]))], {}) == {}
    assert ex.fuzzy_matches(_image(), NAMED, [ex.Rule(("m",), tuple(BODY[:10]))], {}) == {}


def test_fuzzy_refuses_a_name_the_byte_rules_already_placed():
    named = {**NAMED, 10: ["malloc"]}
    assert ex.fuzzy_matches(_image(), named, [ex.Rule(("malloc",), tuple(BODY))], {}) == {}


def test_fuzzy_refuses_a_named_callee_the_library_never_calls():
    image = _image(callees={30: [10]})
    assert ex.fuzzy_matches(image, NAMED, [ex.Rule(("malloc",), tuple(BODY))], {"malloc": {"write"}}) == {}


def test_fuzzy_needs_named_neighbours():
    assert ex.fuzzy_matches(_image(), {10: ["x"]}, [ex.Rule(("malloc",), tuple(BODY))], {}) == {}


def test_string_anchor_needs_one_user_on_each_side():
    text = " in malloc():"
    table = {"malloc": [text]}
    one = _image(strings={30: {text}})
    assert ex.string_anchors(one, NAMED, table, {})[30]["names"] == ["malloc"]
    two = _image(strings={30: {text}, 50: {text}})
    assert ex.string_anchors(two, NAMED, table, {}) == {}


def test_string_anchor_refuses_a_named_procedure_and_a_placed_name():
    text = " in malloc():"
    assert ex.string_anchors(_image(strings={10: {text}}), NAMED, {"malloc": [text]}, {}) == {}
    named = {**NAMED, 20: ["malloc"]}
    assert ex.string_anchors(_image(strings={30: {text}}), named, {"malloc": [text]}, {}) == {}


def test_cache_key_is_the_content_not_the_name_or_mtime(tmp_path, monkeypatch):
    monkeypatch.setattr(match_yara, "CACHE_DIR", str(tmp_path / "cache"))
    rule = 'rule %s {\n strings:\n $p = { 01 02 03 04 }\n condition:\n $p\n}\n'
    old, new = tmp_path / "old", tmp_path / "new"
    old.mkdir(), new.mkdir()
    (new / "a.yara").write_text(rule % "fresh")
    (old / "a.yara").write_text(rule % "stale")
    # the older file, same basename: an mtime-keyed cache would serve `fresh`
    __import__("os").utime(old / "a.yara", (1, 1))
    def names(path):
        rules, _ = match_yara.compile_yara_file(str(path))
        scanner = match_yara.yara_x.Scanner(rules)
        return [r.identifier for r in scanner.scan(bytes([1, 2, 3, 4])).matching_rules]
    assert names(new / "a.yara") == ["fresh"]
    assert names(old / "a.yara") == ["stale"]
    assert names(new / "a.yara") == ["fresh"]


def _sym(name, value, size, shndx=1):
    return {"st_info": {"type": "STT_FUNC", "bind": "STB_WEAK"}, "st_value": value,
            "st_size": size, "st_shndx": shndx, "name": name}


class _Sym(dict):
    name = ""


def _symtab(*symbols):
    items = []
    for raw in symbols:
        sym = _Sym(raw)
        sym.name = raw["name"]
        items.append(sym)
    return SimpleNamespace(iter_symbols=lambda: iter(items))


def test_a_size_zero_alias_takes_its_sized_twin():
    symtab = _symtab(_sym("_strdup", 0, 168), _sym("strdup", 0, 0))
    excluded, offsets, twins = opcodes._build_alias_index(symtab)
    assert excluded == ["_strdup"]  # the shorter name carries the rule
    assert offsets == [0]
    assert twins == {(0, 1): 168}
    text = {"t": list(range(200))}
    section = SimpleNamespace(name="t")
    body, size = opcodes._opcodes_for_symbol(
        _symtab(_sym("strdup", 0, 0)).iter_symbols().__next__(), section, text, 0, offsets, [0], False, twins
    )
    assert (len(body), size) == (168, 168)


def test_a_size_zero_symbol_without_a_twin_keeps_the_recovery_path():
    symtab = _symtab(_sym("stub", 8, 0), _sym("next", 32, 16))
    _, offsets, twins = opcodes._build_alias_index(symtab)
    text = {"t": list(range(64))}
    section = SimpleNamespace(name="t")
    body, size = opcodes._opcodes_for_symbol(
        _symtab(_sym("stub", 8, 0)).iter_symbols().__next__(), section, text, 0, offsets, [0], False, twins
    )
    assert (len(body), size) == (24, 24)
