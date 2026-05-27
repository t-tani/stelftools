"""Entry point for ``python -m stelftools.ident``.

plugins/radare2.py spawns ident as a subprocess via the -m form, so the
sub-package promotion keeps a dedicated __main__ here that delegates to
the public main() defined in :mod:`stelftools.ident`.
"""

from . import main

main()
