#!/bin/bash
# Mirror tools/setup/init.sh: only the runtime scratch directories are
# scrubbed; signatures/ and other tracked outputs are left alone.
set -eu

rm -rf .cache/runtime/man_datasets
rm -rf .cache/runtime/link_order_list
rm -rf .cache/runtime/dummy_bin
