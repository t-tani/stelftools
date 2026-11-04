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


def test_callee_verdict_accepts_a_declared_callee_under_either_spelling():
    assert ev.callee_verdict(["f"], [["_g"]], {"f": {"g"}}) == "consistent"
    assert ev.callee_verdict(["_f", "f"], [["g"]], {"f": {"__g"}}) == "consistent"


def test_callee_verdict_finds_the_sized_twin_of_a_weak_alias():
    assert ev.callee_verdict(["strdup"], [["strlen"]], {"_strdup": {"strlen"}}) == "consistent"


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
