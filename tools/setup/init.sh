#!/bin/bash
# Runtime scratch directories live under .cache/runtime/ (gitignored).
# STELFTOOLS_PATH is derived from each script's __file__, so no shell
# patch is needed for the Python entry points to find their own root.
set -eu

pip3 install yara-x
pip3 install capstone
pip3 install pyelftools
pip3 install python-magic
pip3 install arpy
pip3 install cxxfilt
pip3 install lief
pip3 install qiling

mkdir -p .cache/runtime/man_datasets
mkdir -p .cache/runtime/link_order_list
mkdir -p .cache/runtime/dummy_bin
