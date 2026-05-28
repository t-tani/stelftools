#!/usr/bin/env python3
"""Generate golden text dumps of ``stelftools.ident``'s default output.

End-to-end pipeline per ``tests/test_ident_spec.json`` entry:

1. Ensure the Bootlin tarball is cached under ``.cache/_bootlin_work/``
   and its SHA256 matches the spec (re-downloads on mismatch).
2. Ensure the tarball is fully extracted under
   ``.cache/_bootlin_work/toolchains/<stem>/`` (each extract is ~400 MB).
3. Compile ``samples/src/main.c`` with the toolchain's cross-gcc to
   ``.cache/_bootlin_work/ident_fixtures/<id>/target.elf``, then strip
   the symbol table -- the target is the same shape as a customer
   binary the matcher would see in the wild.
4. Run :mod:`stelftools.generate` against the toolchain to produce
   the (yara, alist, dlist, cfg) signature quadruple under the per-id
   signature root; copy the four files into the fixture dir alongside
   the target.
5. Drive :func:`stelftools.ident.run_one` against the target with the
   full cfg (compiler_path + alias_list_path + dependency_list_path all
   set) so the link-order and depend identification paths run; capture
   ``ident.output(..., 'default')`` and write it to
   ``tests/golden_ident/<id>.txt``.

The heavy state (toolchain extract, signature triple, target binary)
is regenerated on demand and lives outside the repo. Only the small
text goldens are committed; :mod:`tests.test_ident_golden` verifies
them at every test run.
"""

import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Import order matters: info_create.signature_dir reads ``STELFTOOLS_SIGNATURES_DIR``
# at call time, so the env var can be set per entry below.
from stelftools import generate as info_create  # noqa: E402
from stelftools import match as ident  # noqa: E402

CACHE = REPO_ROOT / ".cache" / "_bootlin_work"
TOOLCHAIN_DIR = CACHE / "toolchains"
FIXTURE_DIR = CACHE / "ident_fixtures"
RUNTIME_DIR = REPO_ROOT / ".cache" / "runtime"

SPEC_PATH = REPO_ROOT / "tests" / "test_ident_spec.json"
GOLDEN_DIR = REPO_ROOT / "tests" / "golden_ident"
SOURCE_C = REPO_ROOT / "samples" / "src" / "main.c"

BOOTLIN_BASE = "https://toolchains.bootlin.com/downloads/releases/toolchains"


def _stem(entry):
    return f"{entry['arch']}--{entry['libc']}--{entry['stability']}-{entry['release']}"


def _sig_name(entry):
    return f"bl-{entry['stability']}-{entry['release']}_{entry['libc']}_{entry['arch']}"


def _tarball_url(entry):
    return f"{BOOTLIN_BASE}/{entry['arch']}/tarballs/{_stem(entry)}.tar.{entry['ext']}"


def _file_sha256(path, chunk=1 << 16):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for buf in iter(lambda: f.read(chunk), b""):
            h.update(buf)
    return h.hexdigest()


def _http_get(url, dest):
    req = urllib.request.Request(url, headers={"User-Agent": "stelftools-tests/1"})
    with urllib.request.urlopen(req, timeout=120) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f, length=1 << 16)


def ensure_tarball(entry):
    """Cache the Bootlin tarball under .cache/_bootlin_work/ with a
    pinned SHA256 check. Returns the path; deletes and re-downloads on
    sha mismatch.
    """
    stem = _stem(entry)
    tar = CACHE / f"{stem}.tar.{entry['ext']}"
    CACHE.mkdir(parents=True, exist_ok=True)
    if tar.exists():
        observed = _file_sha256(tar)
        if observed == entry["tarball_sha256"]:
            return tar
        print(f"[{entry['id']}] tarball sha mismatch, re-downloading", flush=True)
        tar.unlink()
    print(f"[{entry['id']}] downloading {_tarball_url(entry)}", flush=True)
    tmp = tar.with_suffix(tar.suffix + ".part")
    _http_get(_tarball_url(entry), tmp)
    observed = _file_sha256(tmp)
    if observed != entry["tarball_sha256"]:
        tmp.unlink()
        raise RuntimeError(
            f"{stem}: sha256 mismatch (expected {entry['tarball_sha256']}, got {observed})"
        )
    tmp.rename(tar)
    return tar


def ensure_toolchain_extract(entry, tar):
    """Fully extract the tarball under .cache/_bootlin_work/toolchains/<stem>/.

    Re-uses a previous extract if the gcc binary is already present.
    The ~400 MB footprint per arch is intentional -- ident's link-order
    identification calls back into the toolchain at test time, so the
    extract has to survive after the signatures have been built.
    """
    stem = _stem(entry)
    out = TOOLCHAIN_DIR / stem
    TOOLCHAIN_DIR.mkdir(parents=True, exist_ok=True)
    gcc_path = out / entry["gcc_relpath"]
    if gcc_path.exists():
        return out
    if out.exists():
        shutil.rmtree(out)
    print(f"[{entry['id']}] extracting toolchain to {out}", flush=True)
    with tarfile.open(tar, mode=f"r:{entry['ext']}") as tf:
        tf.extractall(TOOLCHAIN_DIR, filter="data")
    if not gcc_path.exists():
        raise RuntimeError(f"{stem}: gcc not at {gcc_path}")
    return out


def build_target(toolchain_dir, gcc_relpath, out_path):
    """Compile samples/src/main.c with the cross-gcc, statically linked,
    then strip the symbol table so ident operates on a realistic target.

    Uses the cross-strip that lives alongside the cross-gcc; the host
    strip refuses to touch a non-host ELF.
    """
    gcc = toolchain_dir / gcc_relpath
    strip = toolchain_dir / gcc_relpath.replace("-gcc", "-strip")
    subprocess.run(
        [str(gcc), "-static", str(SOURCE_C), "-o", str(out_path)],
        check=True,
    )
    subprocess.run([str(strip), str(out_path)], check=True)


def generate_signatures(entry, toolchain_dir, fixture_dir):
    """Run info_create against the toolchain extract; lift the
    resulting quadruple into the fixture dir.

    The signatures land in
    ``<fixture_dir>/_sig_root/bootlin-stable/<arch>/<sig_name>.*``
    under a private STELFTOOLS_SIGNATURES_DIR override so the
    in-repo signatures/ tree is untouched.
    """
    sig_root = fixture_dir / "_sig_root"
    if sig_root.exists():
        shutil.rmtree(sig_root)
    sig_root.mkdir(parents=True, exist_ok=True)

    # info_create.signature_dir resolves through sigstore.signatures_root,
    # which honours STELFTOOLS_SIGNATURES_DIR on every call.
    os.environ["STELFTOOLS_SIGNATURES_DIR"] = str(sig_root)
    try:
        sig_name = _sig_name(entry)
        # The serial path (workers=1) is deterministic and fits well in
        # a one-binary fixture build; the parallel path would gain little.
        info_create.mkrule_and_other(
            str(toolchain_dir.resolve()), sig_name, entry["arch"], workers=1,
        )
        # The cfg file ident reads -- include the compiler_path so the
        # link-order identification step has something to call back to.
        info_create.create_toolchain_cfg_file(
            sig_name, entry["arch"], str(toolchain_dir / entry["gcc_relpath"]),
        )
    finally:
        del os.environ["STELFTOOLS_SIGNATURES_DIR"]

    src_dir = sig_root / "bootlin-stable" / entry["arch"]
    pairs = [
        (src_dir / f"{sig_name}.yara",  fixture_dir / f"{entry['id']}.yara"),
        (src_dir / f"{sig_name}.alist", fixture_dir / f"{entry['id']}.alist"),
        (src_dir / f"{sig_name}.dlist", fixture_dir / f"{entry['id']}.dlist"),
        (src_dir / f"{sig_name}.json",  fixture_dir / f"{entry['id']}.json"),
    ]
    for src, dst in pairs:
        shutil.copy(src, dst)
    shutil.rmtree(sig_root)


def ensure_runtime_dirs():
    """Create the runtime caches dub_maker / ident expect; the ident
    link-order pass writes to them at first call.
    """
    for sub in ("man_datasets", "dummy_bin", "link_order_list"):
        (RUNTIME_DIR / sub).mkdir(parents=True, exist_ok=True)
    (REPO_ROOT / ".cache" / "yara").mkdir(parents=True, exist_ok=True)


def run_ident_capture(target_path, cfg_arch, fixture_dir, toolchain_dir, gcc_relpath, sig_stem):
    """Drive ident.run_one with the full cfg (yara + alist + dlist +
    compiler_path) and return the captured ident.output('default')
    stdout. ``compiler_path`` engages the link-order identification
    pass (id_func_name_for_linkorder -> DubMaker.get_order_list);
    determinism there depends on the ``undefined reference to ...``
    parser in dub_maker that this branch hardened.
    """
    cfg = {
        "arch": cfg_arch,
        "yara_path": str(fixture_dir / f"{sig_stem}.yara"),
        "alias_list_path": str(fixture_dir / f"{sig_stem}.alist"),
        "dependency_list_path": str(fixture_dir / f"{sig_stem}.dlist"),
        "compiler_path": str(toolchain_dir / gcc_relpath),
    }
    target_info = ident.run_one(target_path, cfg)
    buf = io.StringIO()
    saved = sys.stdout
    sys.stdout = buf
    try:
        ident.output(target_info, target_path, "default")
    finally:
        sys.stdout = saved
    return buf.getvalue()


def build_one(entry, force=False):
    fixture_dir = FIXTURE_DIR / entry["id"]
    target = fixture_dir / "target.elf"
    yara = fixture_dir / f"{entry['id']}.yara"
    alist = fixture_dir / f"{entry['id']}.alist"
    dlist = fixture_dir / f"{entry['id']}.dlist"
    golden = GOLDEN_DIR / f"{entry['id']}.txt"

    if (not force
            and target.exists() and yara.exists()
            and alist.exists() and dlist.exists()
            and golden.exists()):
        print(f"[{entry['id']}] cached, skip ({golden.name})", flush=True)
        return

    tar = ensure_tarball(entry)
    toolchain_dir = ensure_toolchain_extract(entry, tar)

    fixture_dir.mkdir(parents=True, exist_ok=True)
    if not target.exists() or force:
        print(f"[{entry['id']}] compiling target", flush=True)
        build_target(toolchain_dir, entry["gcc_relpath"], target)
    if not (yara.exists() and alist.exists() and dlist.exists()) or force:
        print(f"[{entry['id']}] generating signatures", flush=True)
        generate_signatures(entry, toolchain_dir, fixture_dir)

    print(f"[{entry['id']}] running ident.run_one", flush=True)
    text = run_ident_capture(
        str(target), entry["cfg_arch"], fixture_dir, toolchain_dir, entry["gcc_relpath"],
        entry["id"],
    )
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    golden.write_text(text)
    line_count = text.count("\n")
    print(f"[{entry['id']}] wrote {golden.name} ({line_count} lines)", flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", default=SPEC_PATH, type=Path)
    parser.add_argument("--id", nargs="*", help="restrict to these spec ids")
    parser.add_argument("--force", action="store_true",
                        help="rebuild even if cached")
    args = parser.parse_args(argv)

    ensure_runtime_dirs()
    spec = json.loads(args.spec.read_text())
    entries = spec["entries"]
    if args.id:
        wanted = set(args.id)
        entries = [e for e in entries if e["id"] in wanted]

    for e in entries:
        build_one(e, force=args.force)


if __name__ == "__main__":
    sys.exit(main() or 0)
