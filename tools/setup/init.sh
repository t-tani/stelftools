#!/bin/bash
# Install stelftools (and its declared dependencies via pyproject.toml)
# into the current Python environment, then create the runtime scratch
# directories under .cache/runtime/ (gitignored).
#
# Run from the stelftools repo root. The editable install means
# subsequent `python -m stelftools.<module>` calls and the
# stelftools-{ident,mkrule,bruteforce} console scripts pick up code
# changes without a re-install.
set -eu

repo_root="$(cd -- "$(dirname -- "$0")/../.." && pwd)"

# Pick uv when available (it is the project's pinned installer) and
# fall back to plain pip otherwise so this script still works on a
# fresh checkout without uv.
if command -v uv >/dev/null 2>&1; then
    uv pip install --editable "$repo_root"
    uv pip install --editable "$repo_root[qiling]"
else
    pip3 install --editable "$repo_root"
    pip3 install --editable "$repo_root[qiling]"
fi

mkdir -p "$repo_root/.cache/runtime/man_datasets"
mkdir -p "$repo_root/.cache/runtime/link_order_list"
mkdir -p "$repo_root/.cache/runtime/dummy_bin"
