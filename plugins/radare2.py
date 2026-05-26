import r2pipe
import sys
import subprocess
from pathlib import Path
from termcolor import colored
from pyfzf.pyfzf import FzfPrompt

# Plugin sits one level below the stelftools root. The signature tree
# is resolved via sigstore so $STELFTOOLS_SIGNATURES_DIR and the XDG
# cache fallback work the same as for the CLI entry points. Toolchain
# cfg JSONs live at <signatures_root>/<family>/<arch>/<name>.json.
STELFTOOLS_PATH = str(Path(__file__).resolve().parent.parent) + "/"
sys.path.insert(0, STELFTOOLS_PATH)
from stelftools import sigstore  # noqa: E402
STELFTOOLS_TOOLCHAIN_PATH = str(sigstore.signatures_root())

def createR2Pipe():
    try:
        pipe = r2pipe.open()
        pipe.cmd('a')
        return pipe
    except Exception:
        print(f'Unexpected error: {sys.exc_info()[0]}')
        return None

pipe = createR2Pipe()

if pipe is None:
    print(colored("only callable inside a r2-instance!", "red", attrs=["bold"]))
    exit(0)

fzf = FzfPrompt()

# signatures/ is partitioned signatures/<family>/<arch>/, so recurse
# to gather every cfg JSON regardless of depth.
known_toolchain_list = sorted(
    p.name for p in Path(STELFTOOLS_TOOLCHAIN_PATH).rglob("*.json")
)

arch = str(pipe.cmdj('ij')['bin']['arch'])
target = str(pipe.cmdj('ij')['core']['file'])

print('which toolchain?')
toolchain = fzf.prompt(known_toolchain_list)[0]
print(f'{toolchain} selected!')

if toolchain not in known_toolchain_list and toolchain + '.json' not in known_toolchain_list:
    print(colored("toolchain not found", "red"))
    print('toolchain json path?')
    toolchain = input('> ')
else:
    # signatures/<family>/<arch>/ is partitioned per family then arch;
    # locate the chosen json by walking once instead of guessing both.
    matches = list(Path(STELFTOOLS_TOOLCHAIN_PATH).rglob(toolchain))
    toolchain = str(matches[0]) if matches else str(Path(STELFTOOLS_TOOLCHAIN_PATH) / toolchain)

run_cmd = [ \
            'python3', '-m', 'stelftools.ident', \
            '-cfg', toolchain, \
            '-target', f'./{target}', \
            '-o', 'ghidra']

# cwd anchors -m at the repo root so the package import resolves
# without requiring a pip install on the host environment.
cmd_res = subprocess.check_output(run_cmd, cwd=STELFTOOLS_PATH).split(b'\n')
res_list = [x.decode('utf-8') for x in cmd_res if x != b'']

for res in res_list:
    addr = res.split(':')[0]
    funcname = res.split(':')[1]
    print(f'{addr}:{funcname}')
    pipe.cmd(f'afn {funcname} @{addr}')
