#!/bin/bash
# STELFTOOLS_PATH is derived from __file__ at import time, no in-place
# patching needed.

# install the python3 package
pip3 install yara-python
pip3 install capstone
pip3 install pyelftools
pip3 install python-magic
pip3 install arpy
pip3 install cxxfilt
pip3 install lief
pip3 install qiling
# add directories to be used by scripts
#mkdir ./_tmpdir
mkdir ./_tmpdir/man_datasets
mkdir ./_tmpdir/link_order_list
mkdir ./_tmpdir/dummy_bin
