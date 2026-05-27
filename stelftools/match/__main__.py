"""Entry point for ``python -m stelftools.match``.

plugins/radare2.py / plugins/ghidra.py / plugins/qiling.py spawn the
matcher as a subprocess via the -m form, so the sub-package keeps a
dedicated __main__ that delegates to the public main() in
:mod:`stelftools.match`.
"""

from . import main

main()
