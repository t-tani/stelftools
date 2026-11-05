"""Experimental dispatch naming on hand-assembled MIPS procedures."""
from __future__ import annotations

from stelftools.match import dispatch as dp
from stelftools.match.experimental import Rule

GP_VALUE = 0x1000
TABLE = 0x2000
GOT_TABLE_SLOT = -8
JALR = 0x0320F809
NOP = 0


def lw(rt, base, off):
    return 0x23 << 26 | base << 21 | rt << 16 | (off & 0xFFFF)


def sw(rt, base, off):
    return 0x2B << 26 | base << 21 | rt << 16 | (off & 0xFFFF)


def wrapper_body(offset, variadic=False):
    head = [0x27BDFFE0]  # addiu sp,sp,-32
    if variadic:
        head += [sw(5, 29, 36), sw(6, 29, 40), sw(7, 29, 44)]
    return head + [lw(2, 28, GOT_TABLE_SLOT), NOP, lw(2, 2, offset), NOP,
                   2 << 21 | 25 << 11 | 0x21, JALR, NOP]


class FakeImage:
    def __init__(self, bodies, table=None, callees=None, tokens=None):
        self.bodies = bodies
        self.starts = sorted(bodies)
        self.ends = {a: a + 4 * len(b) for a, b in bodies.items()}
        self.table = table or {}
        self._callees = callees or {}
        self._tokens = tokens or {}

    def body(self, addr):
        return self.bodies[addr]

    def _gp(self, addr):
        return GP_VALUE

    def _got_value(self, gp, word):
        return TABLE

    def read_word(self, address):
        return self.table.get(address)

    def callees(self, addr):
        return self._callees.get(addr, [])

    def tokens(self, addr):
        return self._tokens.get(addr, [])


READ, WRITE, VFPRINTF = 0x100, 0x200, 0x300


def _image(extra=None, callees=None, count=16, tokens=None):
    bodies = {READ: [NOP], WRITE: [NOP], VFPRINTF: [NOP]}
    table = {TABLE: READ, TABLE + 4: WRITE, TABLE + 8: VFPRINTF}
    for i in range(count):
        bodies[0x1000 + i * 0x100] = wrapper_body(0)
    bodies.update(extra or {})
    return FakeImage(bodies, table, callees, tokens)


def test_a_table_read_by_too_few_procedures_is_not_a_dispatch_table():
    assert dp.find_wrappers(_image(count=15)) == {}
    assert len(dp.find_wrappers(_image(count=16))) == 16


def test_a_procedure_calling_two_entries_is_not_a_wrapper():
    both = wrapper_body(0) + wrapper_body(4)
    assert 0x9000 not in dp.find_wrappers(_image({0x9000: both}))


def test_a_wrapper_takes_the_name_of_its_table_entry():
    found, _ = dp.dispatch_names(_image(), {READ: ["read"]}, [], {})
    assert found[0x1000]["target"] == f"{READ:#x}"
    assert found[0x1000]["evidence"]


def test_a_wrapper_of_an_unnamed_entry_stays_unnamed():
    assert dp.dispatch_names(_image(), {}, [], {})[0] == {}


def test_a_wrapper_is_refused_when_its_known_caller_expects_another_name():
    callees = {0x8000: [0x1000]}
    image = _image({0x8000: [NOP]}, callees)
    named = {READ: ["read"], 0x8000: ["caller"]}
    found, notes = dp.dispatch_names(image, named, [], {"caller": {"write"}})
    assert 0x1000 not in found
    assert "1 refused" in notes[0]


def test_a_variadic_wrapper_of_vfprintf_is_fprintf_not_vfprintf():
    image = _image({0x9000: wrapper_body(8, variadic=True)})
    found, _ = dp.dispatch_names(image, {VFPRINTF: ["vfprintf"]}, [], {})
    assert found[0x9000]["names"] == ["fprintf"]


def test_a_plain_wrapper_of_vfprintf_keeps_the_name():
    image = _image({0x9000: wrapper_body(8)})
    found, _ = dp.dispatch_names(image, {VFPRINTF: ["vfprintf"]}, [], {})
    assert found[0x9000]["names"] == ["vfprintf"]


def test_two_variadic_fronts_of_one_function_name_neither():
    image = _image({0x9000: wrapper_body(8, True), 0x9100: wrapper_body(8, True)})
    found, _ = dp.dispatch_names(image, {VFPRINTF: ["vfprintf"]}, [], {})
    assert 0x9000 not in found and 0x9100 not in found


def test_a_named_group_is_settled_by_a_callee_seen_through_a_wrapper():
    # recv|send calling the wrapper of recvfrom
    image = _image({0x9000: [NOP]}, {0x9000: [0x1000]})
    named = {0x9000: ["recv", "send"], READ: ["recvfrom"]}
    found, _ = dp.dispatch_names(image, named, [], {"recv": {"recvfrom"}, "send": {"sendto"}})
    assert found[0x9000]["names"] == ["recv"]


def test_a_named_group_is_settled_by_what_its_callers_expect():
    image = _image({0x9000: [NOP], 0x9100: [NOP]}, {0x9100: [0x9000]})
    named = {0x9000: ["exect", "execve"], 0x9100: ["execl"]}
    found, _ = dp.dispatch_names(image, named, [], {"execl": {"execve"}})
    assert found[0x9000]["names"] == ["execve"]


def test_conflicting_evidence_settles_nothing():
    image = _image({0x9000: [NOP], 0x9100: [NOP], 0x9200: [NOP]},
                   {0x9000: [0x9200], 0x9100: [0x9000]})
    named = {0x9000: ["a", "b"], 0x9100: ["caller"], 0x9200: ["g"]}
    declared = {"a": {"g"}, "caller": {"b"}}
    assert 0x9000 not in dp.dispatch_names(image, named, [], declared)[0]


def test_aliases_of_one_function_are_not_a_group_to_settle():
    image = _image({0x9000: [NOP]})
    assert 0x9000 not in dp.dispatch_names(image, {0x9000: ["_popen", "popen"]}, [], {})[0]


def test_an_unnamed_site_of_a_dropped_rule_needs_callee_evidence_and_one_site():
    tokens = {0x9000: [1, 2], 0x9100: [1, 2]}
    rule = Rule(("recv", "send"), (1, 2))
    declared = {"recv": {"recvfrom"}, "send": {"sendto"}}
    named = {0x100: ["recvfrom"], 0x200: ["sendto"]}
    # one site each way: both settle
    image = _image({0x9000: [NOP], 0x9100: [NOP]}, {0x9000: [0x100], 0x9100: [0x200]}, tokens=tokens)
    found, _ = dp.dispatch_names(image, named, [rule], declared)
    assert found[0x9000]["names"] == ["recv"] and found[0x9100]["names"] == ["send"]
    # two sites resolving to one name: neither
    image = _image({0x9000: [NOP], 0x9100: [NOP]}, {0x9000: [0x100], 0x9100: [0x100]}, tokens=tokens)
    found, _ = dp.dispatch_names(image, named, [rule], declared)
    assert 0x9000 not in found and 0x9100 not in found
    # no named callee: nothing
    image = _image({0x9000: [NOP], 0x9100: [NOP]}, tokens=tokens)
    assert 0x9000 not in dp.dispatch_names(image, named, [rule], declared)[0]


def _symbols(named, found):
    return [tuple(found[a]["names"] if a in found else named[a]) for a in {*named, *found}]


def test_a_wrapper_keeps_the_public_name_over_a_body_nobody_calls():
    image = _image(count=16, callees={0x8000: [0x1000]})
    image.bodies[0x8000] = [NOP]
    image.starts = sorted(image.bodies)
    image.ends[0x8000] = 0x8004
    named = {READ: ["read"]}
    found, notes = dp.dispatch_names(image, named, [], {})
    assert found[0x1000]["names"] == ["read"] and found[0x1000]["role"] == "entry"
    assert found[READ]["names"] == ["__libc_read"]
    assert found[READ]["method"] == "renamed" and found[READ]["renamed_from"] == ["read"]
    others = [found[0x1000 + i * 0x100]["names"][0] for i in range(1, 16)]
    assert others[0] == "read__stub_1100"
    assert len(set(_symbols(named, found))) == len(_symbols(named, found))
    assert "renamed" in notes[0]


def test_a_body_with_more_calls_than_its_wrappers_keeps_the_public_name():
    bodies = {0x8000 + i: [NOP] for i in range(3)}
    callees = {0x8000 + i: [READ] for i in range(3)}
    image = _image(bodies, callees)
    found, _ = dp.dispatch_names(image, {READ: ["read"]}, [], {})
    assert READ not in found or found[READ].get("role") == "entry"
    assert found[0x1000]["names"] == ["read__stub_1000"]


def test_a_name_only_one_address_holds_is_not_renamed():
    image = _image()
    named = {READ: ["read"], WRITE: ["write"]}
    found, _ = dp.dispatch_names(image, named, [], {})
    assert WRITE not in found


def test_a_joined_group_is_renamed_member_by_member():
    named = {READ: ["fgetc", "getc"]}
    found, _ = dp.dispatch_names(_image(count=16), named, [], {})
    assert found[READ]["names"] == ["__libc_fgetc", "__libc_getc"]
    assert found[0x1100]["names"] == ["fgetc__stub_1100", "getc__stub_1100"]


def test_exit_and_underscore_exit_are_two_functions_when_settling():
    tokens = {0x9000: [1, 2]}
    rule = Rule(("exit",), (1, 2))
    image = _image({0x9000: [NOP]}, {0x9000: [0x100]}, tokens=tokens)
    named = {0x100: ["cleanup"], 0x200: ["_exit"]}
    found, _ = dp.dispatch_names(image, named, [rule], {"exit": {"cleanup"}})
    assert found[0x9000]["names"] == ["exit"]
