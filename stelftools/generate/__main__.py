"""Entry point for ``python -m stelftools.generate``.

plugins/ghidra.py spawns the generator as a subprocess via the -m
form, and tools/ci/build_bootlin_signature.sh does the same; delegate
to :func:`stelftools.generate.main`.
"""

from . import main

main()
