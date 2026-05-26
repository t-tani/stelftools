"""Download signature tarballs from GitHub Release attachments.

The package ships a manifest at ``stelftools/signatures_manifest.json``
that lists per-(family, arch) tarballs along with their sha256 and an
indirect URL (``release_base_url + name``). ``stelftools-fetch-signatures``
reads the manifest, picks the assets the caller asked for, and lands
them under ``sigstore.signatures_root()``.

Each extracted ``<family>/<arch>/`` directory carries a
``.fetched_sha256`` sentinel containing the asset's sha256, so re-runs
skip arches that are already in sync with the manifest. Re-runs after a
manifest bump pick up only the asset(s) whose sha256 changed.

Extraction is staged through a sibling temp directory so a failed
download or partial extract never leaves the live arch in a torn state.

Default behavior fetches every asset in the manifest. ``--family`` and
``--arch`` (each accepting a comma-separated list) narrow the
selection; ``--status`` prints a per-asset state report without
touching the network.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
from importlib import resources
from pathlib import Path
from typing import Iterable

import zstandard

from . import sigstore


SENTINEL_NAME = ".fetched_sha256"

# Mirror chunk for streaming downloads + sha256. 1 MiB keeps memory
# bounded while still amortising read() / write() calls on big tarballs.
_CHUNK = 1 << 20


def _load_packaged_manifest() -> Path:
    """Return the path of the package-shipped manifest JSON.

    ``importlib.resources.files`` resolves the on-disk path whether the
    package is installed normally or from an editable install.
    """
    return resources.files("stelftools").joinpath("signatures_manifest.json")


def load_manifest(path: Path | str | None) -> dict:
    """Read a manifest JSON. Defaults to the package-shipped file."""
    if path is None:
        target: Path = Path(str(_load_packaged_manifest()))
    else:
        target = Path(path)
    with target.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if data.get("schema_version") != 1:
        raise SystemExit(
            f"unsupported manifest schema_version: "
            f"{data.get('schema_version')!r} (expected 1)"
        )
    return data


def asset_url(manifest: dict, asset: dict) -> str:
    """Resolve an asset URL.

    A per-asset ``url`` wins (used by tests with ``file://`` URLs);
    otherwise the URL is composed from the manifest's
    ``release_base_url`` and the asset's ``name``.
    """
    if "url" in asset:
        return asset["url"]
    base = manifest.get("release_base_url")
    if not base:
        raise SystemExit(
            f"asset {asset.get('name')!r} has no 'url' and the manifest "
            f"carries no 'release_base_url'"
        )
    return base.rstrip("/") + "/" + asset["name"]


def select_assets(
    manifest: dict,
    families: Iterable[str] | None,
    arches: Iterable[str] | None,
) -> list[dict]:
    fam_set = set(families) if families else None
    arch_set = set(arches) if arches else None
    out = []
    for asset in manifest.get("assets", []):
        if fam_set and asset.get("family") not in fam_set:
            continue
        if arch_set and asset.get("arch") not in arch_set:
            continue
        out.append(asset)
    return out


def _arch_dir(dest_root: Path, asset: dict) -> Path:
    return dest_root / asset["family"] / asset["arch"]


def _read_sentinel(arch_dir: Path) -> str | None:
    sentinel = arch_dir / SENTINEL_NAME
    if not sentinel.is_file():
        return None
    return sentinel.read_text(encoding="utf-8").strip()


def _write_sentinel(arch_dir: Path, sha256: str) -> None:
    (arch_dir / SENTINEL_NAME).write_text(sha256 + "\n", encoding="utf-8")


def _stream_to_file(url: str, dest: Path) -> str:
    """Download ``url`` to ``dest`` streaming, return hex sha256.

    ``urllib.request.urlopen`` handles ``file://`` URLs natively, so the
    same path covers production downloads and the local round-trip test
    that writes a ``file://`` manifest under /tmp.
    """
    h = hashlib.sha256()
    req = urllib.request.Request(
        url, headers={"User-Agent": "stelftools-sigfetch/1"}
    )
    with urllib.request.urlopen(req) as resp, dest.open("wb") as out:
        while True:
            chunk = resp.read(_CHUNK)
            if not chunk:
                break
            h.update(chunk)
            out.write(chunk)
    return h.hexdigest()


def _extract_zst_tar(archive: Path, into: Path) -> None:
    into.mkdir(parents=True, exist_ok=True)
    dctx = zstandard.ZstdDecompressor()
    with archive.open("rb") as fh, dctx.stream_reader(fh) as reader:
        # ``mode='r|'`` streams the tar from the decompressor without
        # seeking. ``filter='data'`` is required on Python 3.12+ to opt
        # into the safe extraction policy (PEP 706).
        with tarfile.open(fileobj=reader, mode="r|") as tf:
            tf.extractall(path=into, filter="data")


def _swap_into_place(staging: Path, target: Path) -> None:
    """Replace ``target`` directory with ``staging`` atomically-ish.

    Posix rename is atomic at the filesystem level, but ``Path.rename``
    cannot overwrite a non-empty directory. We rename the live target
    out of the way first, then move staging into its slot, then sweep
    the old one. A crash between steps leaves a ``.old`` sibling that
    the next run cleans up.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    backup = target.with_name(target.name + ".old")
    if backup.exists():
        shutil.rmtree(backup)
    if target.exists():
        target.rename(backup)
    staging.rename(target)
    if backup.exists():
        shutil.rmtree(backup)


def fetch_one(
    manifest: dict,
    asset: dict,
    dest_root: Path,
    *,
    force: bool = False,
    dry_run: bool = False,
) -> str:
    """Fetch a single asset. Return one of ``downloaded`` / ``skipped`` / ``would-download``."""
    arch_dir = _arch_dir(dest_root, asset)
    expected_sha = asset.get("sha256")
    if not expected_sha:
        raise SystemExit(f"asset {asset.get('name')!r} missing sha256")

    current = _read_sentinel(arch_dir)
    if current == expected_sha and not force:
        return "skipped"
    if dry_run:
        return "would-download"

    url = asset_url(manifest, asset)
    # Staging area sits alongside the target so the final rename stays
    # on the same filesystem (cross-device rename would fail).
    parent = arch_dir.parent
    parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f"{asset['arch']}.", dir=parent) as tmp:
        tmp_path = Path(tmp)
        archive = tmp_path / asset["name"]
        actual_sha = _stream_to_file(url, archive)
        if actual_sha != expected_sha:
            raise SystemExit(
                f"sha256 mismatch for {asset['name']}: "
                f"expected {expected_sha}, got {actual_sha}"
            )

        # Extract into a sibling staging directory whose contents
        # mirror what the archive carries. The archive's top-level
        # entry is the family directory (matching publish_signatures
        # _release.sh's `tar -C signatures <family>/<arch>/...`), so
        # the on-disk layout after extract is staging/<family>/<arch>/.
        # We then promote the inner <arch>/ slice into place.
        staging = tmp_path / "extract"
        _extract_zst_tar(archive, staging)
        produced = staging / asset["family"] / asset["arch"]
        if not produced.is_dir():
            raise SystemExit(
                f"archive {asset['name']} did not yield "
                f"{asset['family']}/{asset['arch']}/ (got: "
                f"{list(staging.rglob('*'))[:4]})"
            )
        _write_sentinel(produced, expected_sha)
        _swap_into_place(produced, arch_dir)
    return "downloaded"


def status_report(manifest: dict, dest_root: Path) -> list[tuple[dict, str]]:
    out = []
    for asset in manifest.get("assets", []):
        arch_dir = _arch_dir(dest_root, asset)
        current = _read_sentinel(arch_dir)
        expected = asset.get("sha256")
        if current is None:
            state = "missing"
        elif current == expected:
            state = "in-sync"
        else:
            state = "stale"
        out.append((asset, state))
    return out


def _split_csv(s: str | None) -> list[str] | None:
    if s is None:
        return None
    return [t for t in s.split(",") if t]


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="stelftools-fetch-signatures",
        description="Download signature tarballs declared in the package manifest.",
    )
    p.add_argument("--manifest", help="Path to a manifest JSON (default: packaged).")
    p.add_argument("--family", help="Comma-separated family allowlist (e.g. bootlin-stable,aboriginal-linux).")
    p.add_argument("--arch", help="Comma-separated arch allowlist (e.g. mips32el,aarch64).")
    p.add_argument(
        "--dest",
        help="Override the on-disk root (default: sigstore.signatures_root()). "
             "Useful for staging or testing.",
    )
    p.add_argument("--force", action="store_true", help="Re-download even when the sentinel matches.")
    p.add_argument("--dry-run", action="store_true", help="Report what would be fetched and exit.")
    p.add_argument("--status", action="store_true", help="Print per-asset state and exit.")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    manifest = load_manifest(args.manifest)
    dest_root = Path(args.dest).expanduser() if args.dest else sigstore.signatures_root()

    if args.status:
        report = status_report(manifest, dest_root)
        for asset, state in report:
            print(f"{state:8s}  {asset['family']:20s}  {asset['arch']:20s}  {asset['name']}")
        total = len(report)
        in_sync = sum(1 for _, s in report if s == "in-sync")
        print(f"\n{in_sync}/{total} assets in sync (dest={dest_root})", file=sys.stderr)
        return 0

    selected = select_assets(manifest, _split_csv(args.family), _split_csv(args.arch))
    if not selected:
        print("no assets matched the filters", file=sys.stderr)
        # An empty selection is not necessarily an error — the manifest
        # may legitimately list zero assets (the bootstrapping state).
        return 0

    counts = {"downloaded": 0, "skipped": 0, "would-download": 0}
    for asset in selected:
        url = asset_url(manifest, asset)
        action = fetch_one(
            manifest, asset, dest_root,
            force=args.force, dry_run=args.dry_run,
        )
        counts[action] = counts.get(action, 0) + 1
        size = asset.get("size_bytes", 0)
        size_mb = size / (1024 * 1024) if size else 0
        print(f"{action:14s}  {asset['family']}/{asset['arch']}  "
              f"{size_mb:6.1f} MB  {url}")
    print(
        f"\ndest={dest_root}  "
        f"downloaded={counts['downloaded']}  skipped={counts['skipped']}  "
        f"would-download={counts['would-download']}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
