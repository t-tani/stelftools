"""Regression: extract_opcodes output must equal the committed golden.

Fixture set is described in ``tests/test_objects_spec.json``; the inputs
live under ``.cache/_bootlin_work/test_objects/<id>/`` (populated by
``tests/fetch_test_objects.py``) and the goldens under
``tests/golden/<id>.json.gz`` (populated by ``tests/build_goldens.py``).

Per entry, missing inputs or missing goldens skip rather than fail so a
partial cache (e.g. only a subset of arches fetched) still runs the
tests for the arches that are present.
"""

import gzip
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Re-use the canonicalisation + driver from the golden builder so any
# normalisation tweak lands in one place.
from tests.build_goldens import (  # noqa: E402
    canonicalize,
    run_fetch_on_dir,
)

CACHE = REPO_ROOT / ".cache" / "_bootlin_work"
OBJECTS = CACHE / "test_objects"
SPEC_PATH = REPO_ROOT / "tests" / "test_objects_spec.json"
GOLDEN_DIR = REPO_ROOT / "tests" / "golden"


def _load_spec_entries():
    spec = json.loads(SPEC_PATH.read_text())
    return spec["entries"]


def _entry_id(e):
    return f"{e['arch']}--{e['libc']}--{e['release']}"


@pytest.mark.parametrize("entry", _load_spec_entries(), ids=_entry_id)
def test_extract_opcodes_matches_golden(entry):
    obj_dir = OBJECTS / _entry_id(entry)
    golden = GOLDEN_DIR / f"{_entry_id(entry)}.json.gz"
    if not obj_dir.exists() or not any(obj_dir.iterdir()):
        pytest.skip(f"extract missing at {obj_dir}; run tests/fetch_test_objects.py")
    if not golden.exists():
        pytest.skip(f"golden missing at {golden}; run tests/build_goldens.py")

    tab, crt = run_fetch_on_dir(obj_dir)
    observed = {"tab": canonicalize(tab), "crt": canonicalize(crt)}
    with gzip.open(golden, "rb") as f:
        expected = json.loads(f.read().decode("utf-8"))

    assert observed == expected, f"extract_opcodes diverged from golden for {_entry_id(entry)}"
