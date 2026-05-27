"""Regression: ident.run_one + ident.output('default') must match the
committed text goldens.

Each spec entry points at a pre-built fixture under
``.cache/_bootlin_work/ident_fixtures/<id>/`` containing
``target.elf`` + the ``sig.{yara,alist,dlist}`` triple, plus a full
toolchain extract under ``.cache/_bootlin_work/toolchains/<stem>/``.
:mod:`tests.build_ident_goldens` populates both; the test here only
verifies that ident produces the same output the golden recorded.

Missing fixtures or missing toolchains skip rather than fail.
"""

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tests.build_ident_goldens import (  # noqa: E402
    FIXTURE_DIR,
    GOLDEN_DIR,
    SPEC_PATH,
    TOOLCHAIN_DIR,
    ensure_runtime_dirs,
    run_ident_capture,
)


def _load_spec_entries():
    return json.loads(SPEC_PATH.read_text())["entries"]


def _toolchain_stem(entry):
    return f"{entry['arch']}--{entry['libc']}--{entry['stability']}-{entry['release']}"


@pytest.mark.linkorder
@pytest.mark.parametrize("entry", _load_spec_entries(), ids=lambda e: e["id"])
def test_ident_default_output_matches_golden(entry):
    fixture = FIXTURE_DIR / entry["id"]
    target = fixture / "target.elf"
    yara = fixture / f"{entry['id']}.yara"
    alist = fixture / f"{entry['id']}.alist"
    dlist = fixture / f"{entry['id']}.dlist"

    toolchain = TOOLCHAIN_DIR / _toolchain_stem(entry)
    gcc = toolchain / entry["gcc_relpath"]

    if not all(p.exists() for p in (target, yara, alist, dlist)):
        pytest.skip(f"fixture missing under {fixture}; run tests/build_ident_goldens.py")
    if not gcc.exists():
        pytest.skip(
            f"toolchain extract missing at {toolchain}; "
            "run tests/build_ident_goldens.py to populate it"
        )

    golden = GOLDEN_DIR / f"{entry['id']}.txt"
    if not golden.exists():
        pytest.skip("ident golden missing; run tests/build_ident_goldens.py")

    ensure_runtime_dirs()
    observed = run_ident_capture(
        str(target), entry["cfg_arch"], fixture, toolchain, entry["gcc_relpath"],
        entry["id"],
    )
    expected = golden.read_text()
    assert observed == expected, f"ident output diverged from golden for {entry['id']}"
