"""The scoring rules of tools/eval/mips_pdr_eval.py on synthetic data."""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PATH = Path(__file__).resolve().parent.parent / "tools/eval/mips_pdr_eval.py"
_SPEC = importlib.util.spec_from_file_location("mips_pdr_eval", _PATH)
ev = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ev)


def test_callee_verdict_needs_a_named_callee():
    assert ev.callee_verdict(["f"], [[], []], {"f": {"g"}}) == "no_evidence"


def test_callee_verdict_takes_only_the_names_it_was_given():
    assert ev.callee_verdict(["f"], [["g"]], {"f": {"g", "_g"}}) == "consistent"
    assert ev.callee_verdict(["f"], [["_g"]], {"f": {"g", "_g"}}) == "consistent"
    # `_exit` and `exit` are two functions unless `.alist` joins them
    assert ev.callee_verdict(["f"], [["_exit"]], {"f": {"exit"}}) == "inconsistent"


def test_read_dlist_expands_callers_and_callees_through_the_alist(tmp_path):
    (tmp_path / "x.dlist").write_text("_strdup,strdup _strlen 44\nabort raise 8\n")
    (tmp_path / "x.alist").write_text("_strdup,strdup\n_strlen,strlen\n")
    declared = ev.read_dlist(str(tmp_path / "x.dlist"))
    assert {"_strlen", "strlen"} <= declared["strdup"]
    assert declared["strdup"] == declared["_strdup"]
    assert "raise" in declared["abort"]


def _rule(aliases):
    return f'rule r {{\n\tmeta:\n\t\taliases = "{aliases}"\n}}\n'


def test_read_dlist_joins_an_untyped_alias_the_alist_never_saw(tmp_path):
    # the stub's rule is `close`; its `_close` alias is only a declared callee
    (tmp_path / "x.dlist").write_text("fclose _close 8\n")
    (tmp_path / "x.yara").write_text(_rule("close"))
    assert "close" in ev.read_dlist(str(tmp_path / "x.dlist"))["fclose"]


def test_read_dlist_keeps_two_functions_that_each_have_a_rule_apart(tmp_path):
    (tmp_path / "x.dlist").write_text("abort _exit 8\n")
    (tmp_path / "x.yara").write_text(_rule("_exit") + _rule("exit"))
    declared = ev.read_dlist(str(tmp_path / "x.dlist"))["abort"]
    assert "_exit" in declared and "exit" not in declared


def test_callee_verdict_treats_the_byte_swap_names_as_one_body():
    assert ev.callee_verdict(["inet_lnaof"], [["__bswap32"]], {"inet_lnaof": {"ntohl"}}) == "consistent"


def test_callee_verdict_without_a_dlist_row_is_no_evidence():
    assert ev.callee_verdict(["crypt"], [["__md5crypt"]], {}) == "no_evidence"


def test_callee_verdict_flags_a_callee_the_object_never_calls():
    assert ev.callee_verdict(["f"], [["g"], ["h"]], {"f": {"g"}}) == "inconsistent"


def test_score_truth_counts_a_candidate_group_right_when_one_name_is_true():
    truth = {0x10: {"popen", "_popen"}, 0x20: {"read"}, 0x30: {"never_matched"}}
    matches = {0x10: ["popen", "x"], 0x20: ["write"], 0x40: ["ghost"]}
    out = ev.score_truth(matches, truth)
    assert (out["right"], out["wrong_name"], out["not_a_function"]) == (1, 1, 1)
    assert out["precision"] == round(1 / 3, 4)
    assert out["recall"] == round(1 / 3, 4)
