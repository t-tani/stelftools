"""The NetBSD signature family: routed by name, kept apart from the Linux
families in both directions, and its multi-site candidate groups dropped."""
from __future__ import annotations

import json
import struct

import pytest

from stelftools.drivers import identify
from stelftools.families import family_for
from stelftools.match.heuristics.unique_site import drop_multi_site_groups


def _note(owner: bytes, desc: bytes = b"\x00" * 4, order: str = "<") -> bytes:
    name = owner + b"\x00"
    pad = (4 - len(name) % 4) % 4
    return struct.pack(order + "III", len(name), len(desc), 1) + name + b"\x00" * pad + desc


def test_name_routes_to_the_netbsd_family():
    assert family_for("netbsd-1.6.2-pmax_mipsel") == "netbsd"


@pytest.mark.parametrize("order", ["<", ">"])
def test_note_owners_reads_either_byte_order(order):
    body = _note(b"GNU", order=order) + _note(b"NetBSD", order=order)
    assert identify._note_owners(body) == [b"GNU", b"NetBSD"]


def test_note_owners_stops_on_a_truncated_note():
    assert identify._note_owners(b"\xff" * 16) == []


@pytest.mark.parametrize(
    ("family", "target_os", "applies"),
    [
        ("netbsd", "netbsd", True),
        ("netbsd", None, False),
        ("bootlin-stable", "netbsd", False),
        ("bootlin-stable", None, True),
    ],
)
def test_family_applies_only_to_its_own_os(family, target_os, applies):
    assert identify._family_applies(family, target_os) is applies


@pytest.mark.parametrize(("target_os", "kept"), [("netbsd", "n"), (None, "l")])
def test_candidate_cfgs_walks_only_the_families_of_the_target_os(
    tmp_path, monkeypatch, target_os, kept
):
    for family, name in (("netbsd", "n"), ("buildroot", "l")):
        arch = tmp_path / family / "mipsel"
        arch.mkdir(parents=True)
        (arch / f"{name}.json").write_text(json.dumps({"name": name}))
    monkeypatch.setenv("STELFTOOLS_SIGNATURES_DIR", str(tmp_path))
    monkeypatch.setattr(identify, "lief_target_os", lambda _: target_os)
    got = identify.candidate_cfgs("target", ["mipsel"], None)
    assert [info["name"] for _, info in got] == [kept]


def test_multi_site_group_is_reset_and_a_unique_one_kept():
    wrapper = {"names": ["strcoll", "seekdir"], "size": 72, "detected": True, "category": "match"}
    functions = {
        0x100: dict(wrapper),
        0x200: {**wrapper, "names": ["seekdir", "strcoll"]},
        0x300: {"names": ["system"], "size": 592, "detected": True, "category": "match"},
        0x400: {"names": [""], "size": 0, "detected": True, "category": "unmatch"},
    }
    out = drop_multi_site_groups(functions)
    assert out[0x100]["names"] == out[0x200]["names"] == [""]
    assert out[0x100]["category"] == "unmatch"
    assert out[0x300]["names"] == ["system"]


def test_output_keeps_names_below_the_anchor_only_without_a_libc_area():
    from stelftools.match.output import output

    functions = {
        0x100: {"names": ["ttymsg"], "size": 64},
        0x200: {"names": ["open"], "size": 64},
    }
    info = {"functions": functions, "size": 0x400, "base_vaddr": 0}
    assert set(output(dict(info), "t", "ghidra")) == {0x200}
    assert set(output({**info, "no_libc_area": True}, "t", "ghidra")) == {0x100, 0x200}
