"""``stelftools symbolize`` names one candidate group through the caller's
``resolver`` / ``prefer`` plug-ins; standalone it keeps the ``_OR_`` join.
These drive the driver's pure helpers on synthetic groups, so they need
neither the matcher nor a binary."""
from __future__ import annotations

import argparse
import json

from stelftools.drivers import symbolize as sym

#: A caller's canonical-name rule: ``__GI_x`` / ``_IO_x`` beside ``x`` is an
#: alias set of ``x``; among distinct names exactly one in ``prefer`` wins.
PREFIXES = ("__GI_", "_IO_")


def fake_resolver(cands, prefer):
    public = []
    for c in cands:
        for p in PREFIXES:
            if c.startswith(p):
                c = c[len(p):]
        if c not in public:
            public.append(c)
    if len(public) == 1:
        return public[0], "single" if len(cands) == 1 else "alias"
    hits = [c for c in public if c in prefer]
    if len(hits) == 1:
        return hits[0], "catalog"
    return None, "ambiguous"


FAKE_SINKS = {"memcpy": {"family": "copy"}, "system": {"family": "exec"}}


def fake_sources():
    return frozenset({"recv", "getenv"})


def test_standalone_keeps_every_group_but_a_singleton_as_or_join():
    assert sym.resolve_group(["strlen"]) == {
        "canonical": "strlen", "candidates": ["strlen"],
        "resolution": "single", "symbol": "strlen"}
    r = sym.resolve_group(["__GI_strcpy", "strcpy"])
    assert (r["canonical"], r["resolution"], r["symbol"]) == (None, "ambiguous", "__GI_strcpy_OR_strcpy")
    # prefer alone proves nothing: tie-breaking needs a resolver
    r = sym.resolve_group(["memcpy", "memmove"], prefer={"memcpy"})
    assert (r["canonical"], r["resolution"], r["symbol"]) == (None, "ambiguous", "memcpy_OR_memmove")


def test_resolver_decides_alias_and_catalog_groups():
    r = sym.resolve_group(["__GI_strcpy", "strcpy"], resolver=fake_resolver)
    assert (r["canonical"], r["resolution"], r["symbol"]) == ("strcpy", "alias", "strcpy")
    r = sym.resolve_group(["_IO_sprintf", "sprintf"], resolver=fake_resolver)
    assert (r["canonical"], r["resolution"], r["symbol"]) == ("sprintf", "alias", "sprintf")
    # the one preferred member is a sidecar lead, never the symtab name
    r = sym.resolve_group(["memcpy", "memmove"], prefer={"memcpy"}, resolver=fake_resolver)
    assert (r["canonical"], r["resolution"], r["symbol"]) == ("memcpy", "catalog", "memcpy_OR_memmove")
    r = sym.resolve_group(["lcong48", "srand48"], prefer={"memcpy"}, resolver=fake_resolver)
    assert (r["canonical"], r["resolution"], r["symbol"]) == (None, "ambiguous", "lcong48_OR_srand48")
    assert r["candidates"] == ["lcong48", "srand48"]


def test_resolve_symbols_threads_the_plugins_and_drops_empty_groups():
    resolved = sym.resolve_symbols(
        {0x10: ["", "strlen"], 0x20: [""], 0x30: ["strcpy", "__GI_strcpy"],
         0x40: ["memmove", "memcpy"]},
        prefer={"memcpy"}, resolver=fake_resolver)
    assert list(resolved) == [0x10, 0x30, 0x40]
    assert resolved[0x10]["symbol"] == "strlen"
    assert resolved[0x30]["symbol"] == "strcpy"
    assert (resolved[0x40]["resolution"], resolved[0x40]["symbol"]) == ("catalog", "memcpy_OR_memmove")


def test_sidecar_counts_and_shape(tmp_path):
    resolved = sym.resolve_symbols({
        0x400100: ["__GI_strcpy", "strcpy"],
        0x400200: ["lcong48", "srand48"],
        0x400300: ["strlen"],
        0x400400: ["memcpy", "memmove"],
    }, prefer={"memcpy"}, resolver=fake_resolver)
    path = tmp_path / "bin.symbols.json"
    counts = sym._write_sidecar(path, "/sig/x.json", resolved)
    assert counts == {"alias": 1, "ambiguous": 1, "catalog": 1, "single": 1}
    doc = json.loads(path.read_text())
    assert doc["schema_version"] == 1 and doc["cfg"] == "/sig/x.json"
    assert doc["symbols"]["0x400100"] == {
        "canonical": "strcpy", "candidates": ["__GI_strcpy", "strcpy"],
        "resolution": "alias"}
    assert doc["symbols"]["0x400200"]["canonical"] is None
    assert doc["symbols"]["0x400400"]["canonical"] == "memcpy"
    assert doc["counts"] == counts


def test_plugin_specs_load_callables_and_name_sets():
    assert sym._load_spec(f"{__name__}:fake_resolver") is fake_resolver
    # a dict counts by its keys, a callable by what it returns; the union
    names = sym.prefer_names([f"{__name__}:FAKE_SINKS", f"{__name__}:fake_sources"])
    assert names == frozenset({"memcpy", "system", "recv", "getenv"})
    assert sym.prefer_names([]) == frozenset()
    for bad in ("nocolon", ":attr", "mod:"):
        try:
            sym._load_spec(bad)
        except ValueError as exc:
            assert "module:attr" in str(exc)
        else:
            raise AssertionError(bad)


def test_cli_parses_the_plugin_flags_and_reports_a_bad_spec(tmp_path):
    parser = argparse.ArgumentParser()
    sym._add_arguments(parser)
    args = parser.parse_args(["/bin/x", "--out-elf", "o", "--resolver", "m:r",
                              "--prefer", "a:b", "--prefer", "c:d"])
    assert (args.resolver, args.prefer) == ("m:r", ["a:b", "c:d"])
    assert parser.parse_args(["/bin/x", "--out-elf", "o"]).prefer == []

    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF")
    summary = tmp_path / "summary.json"
    rc = sym.run(parser.parse_args([str(binary), "--out-elf", str(tmp_path / "out"),
                                    "--summary", str(summary),
                                    "--resolver", "stelftools.no_such_module:resolve"]))
    assert rc == 2
    doc = json.loads(summary.read_text())
    assert doc["error"].startswith("plug-in spec:") and doc["binary"] == str(binary)
    assert not (tmp_path / "out").exists()
