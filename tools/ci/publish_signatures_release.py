#!/usr/bin/env python3
"""Bundle per-(family, arch) signature tarballs and publish them as a GitHub Release.

Walks ``signatures/<family>/<arch>/`` under the repo (only the
canonical families listed by ``stelftools.families.known_families``),
streams each pair through ``tar | zstd`` into a staging directory,
computes ``sha256`` and ``size_bytes``, and emits a
``signatures_manifest.json`` that points at the resulting Release
assets.

Two run modes:

* ``--dry-run`` stages tarballs under a temp directory, writes a
  manifest whose ``release_base_url`` is ``file://<staging>``, prints
  the manifest, and stops. With ``--keep-staging`` the tarballs and
  manifest remain on disk so a local ``stelftools-fetch-signatures``
  round-trip can verify the artifacts before the real upload.
* Default (``gh`` available, network OK): creates the GitHub Release
  via ``gh release create``, uploads every tarball, and writes the
  manifest to ``stelftools/signatures_manifest.json`` so the next
  ``pip install`` carries the pointer set.

The script never deletes archives on the host — running it twice with
the same ``--tag`` re-stages locally; the ``gh release create`` call
will fail loudly on a duplicate tag, leaving the staging dir for the
caller to recover.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Iterable

import zstandard

# The publish helper sits at tools/ci/; the package root is two levels up.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from stelftools.families import known_families  # noqa: E402
from stelftools.drivers.bruteforce import lief_arch_group_for  # noqa: E402
from stelftools import sigstore  # noqa: E402


# Streaming chunk for sha256 + size accounting. 1 MiB keeps memory
# bounded without forcing a syscall per kilobyte of tar output.
_CHUNK = 1 << 20


def _sha256_size(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as f:
        while True:
            buf = f.read(_CHUNK)
            if not buf:
                break
            h.update(buf)
            size += len(buf)
    return h.hexdigest(), size


def _pair_yields_signatures(arch_dir: Path) -> bool:
    """An arch directory counts only when it contains at least one cfg JSON."""
    return any(arch_dir.glob("*.json"))


def _build_tarball(
    family: str, arch: str, arch_dir: Path, staging: Path, zstd_level: int,
) -> tuple[Path, str, int]:
    """Write ``<family>-<arch>.tar.zst`` into ``staging``. Return (path, sha256, bytes)."""
    out_path = staging / f"{family}-{arch}.tar.zst"
    cctx = zstandard.ZstdCompressor(level=zstd_level)
    with out_path.open("wb") as fout, cctx.stream_writer(fout) as compressor:
        # ``mode="w|"`` streams the tar headers + payload through the
        # zstd writer without seeking. ``arcname`` keeps the on-disk
        # layout: archives carry ``<family>/<arch>/*``, matching what
        # sigfetch.py expects when it promotes
        # ``staging/<family>/<arch>/`` into place.
        with tarfile.open(fileobj=compressor, mode="w|") as tf:
            tf.add(arch_dir, arcname=f"{family}/{arch}")
    sha256, size = _sha256_size(out_path)
    return out_path, sha256, size


def _enumerate_pairs(repo_root: Path) -> list[tuple[str, str, Path]]:
    """Return [(family, arch, arch_dir), ...] for every populated pair.

    The signatures root is resolved via sigstore so the publish step
    honors ``$STELFTOOLS_SIGNATURES_DIR`` — CI runs override the path
    to land the fetch + new builds on the runner's roomy /mnt volume
    instead of competing with the checkout for the 14 GB / partition.
    """
    sig_root = sigstore.signatures_root()
    pairs: list[tuple[str, str, Path]] = []
    if not sig_root.is_dir():
        return pairs
    for family in known_families():
        family_dir = sig_root / family
        if not family_dir.is_dir():
            continue
        for arch_dir in sorted(family_dir.iterdir()):
            if not arch_dir.is_dir():
                continue
            if not _pair_yields_signatures(arch_dir):
                continue
            pairs.append((family, arch_dir.name, arch_dir))
    return pairs


def _covers_for(arch_dir: Path) -> list[str]:
    """List the signature stems carried in this arch directory."""
    return sorted(p.stem for p in arch_dir.glob("*.json"))


def _repo_slug_from_remote(remote_url: str) -> str:
    """``owner/repo`` from either an ssh or https GitHub remote URL."""
    if remote_url.startswith("git@github.com:"):
        slug = remote_url[len("git@github.com:") :]
    elif remote_url.startswith("https://github.com/"):
        slug = remote_url[len("https://github.com/") :]
    else:
        raise SystemExit(f"can't derive release URL from remote: {remote_url!r}")
    return slug.rstrip("/").removesuffix(".git")


def _resolve_default_base_url(remote_url: str, tag: str) -> str:
    """Translate a git remote URL into a Release attachment base URL."""
    return f"https://github.com/{_repo_slug_from_remote(remote_url)}/releases/download/{tag}"


def _git_remote_url(repo_root: Path) -> str:
    out = subprocess.run(
        ["git", "-C", str(repo_root), "remote", "get-url", "origin"],
        capture_output=True, text=True, check=True,
    )
    return out.stdout.strip()


def recover_manifest_from_staging(
    repo_root: Path, staging: Path, *, tag: str, base_url: str,
) -> dict:
    """Reconstruct a manifest from tarballs left in ``staging``.

    The tarballs themselves are not re-read; only their sha256, size,
    and filename are consumed. ``covers`` and ``lief_arch_match`` come
    from the current on-disk state under ``signatures/<family>/<arch>/``
    via the same helpers that ``build_manifest`` uses, so a recovery
    only succeeds when that directory has not been disturbed since the
    original build.
    """
    sig_root = repo_root / "signatures"
    assets: list[dict] = []
    for archive in sorted(staging.glob("*.tar.zst")):
        stem = archive.name[: -len(".tar.zst")]
        # Family names can contain hyphens (firmware-linux, aboriginal-
        # linux, bootlin-stable, synopsys-arc-gnu, uclibc-pub), so the
        # split has to consult the known-family registry rather than
        # rsplit on the first hyphen.
        family = arch = None
        for candidate in known_families():
            if stem.startswith(candidate + "-"):
                family = candidate
                arch = stem[len(candidate) + 1:]
                break
        if family is None:
            print(f"[recover] cannot infer family from {archive.name!r}, "
                  f"skipping", file=sys.stderr)
            continue
        arch_dir = sig_root / family / arch
        if not arch_dir.is_dir():
            print(f"[recover] {family}/{arch} no longer on disk; can't "
                  f"recompute covers — skipping", file=sys.stderr)
            continue
        sha256, size = _sha256_size(archive)
        assets.append({
            "name": archive.name,
            "family": family,
            "arch": arch,
            "lief_arch_match": lief_arch_group_for(arch),
            "sha256": sha256,
            "size_bytes": size,
            "covers": _covers_for(arch_dir),
        })
    return {
        "schema_version": 1,
        "manifest_version": datetime.date.today().isoformat(),
        "release_tag": tag,
        "release_base_url": base_url,
        "assets": assets,
    }


def build_manifest(
    repo_root: Path,
    staging: Path,
    *,
    tag: str,
    base_url: str,
    zstd_level: int,
) -> dict:
    pairs = _enumerate_pairs(repo_root)
    assets: list[dict] = []
    for family, arch, arch_dir in pairs:
        archive, sha256, size = _build_tarball(
            family, arch, arch_dir, staging, zstd_level,
        )
        assets.append({
            "name": archive.name,
            "family": family,
            "arch": arch,
            "lief_arch_match": lief_arch_group_for(arch),
            "sha256": sha256,
            "size_bytes": size,
            "covers": _covers_for(arch_dir),
        })
        print(
            f"  packed {family}/{arch}: {size / (1024 * 1024):6.1f} MB  "
            f"sha256={sha256[:12]}…  ({len(assets[-1]['covers'])} cfgs)",
            file=sys.stderr,
        )
    return {
        "schema_version": 1,
        "manifest_version": datetime.date.today().isoformat(),
        "release_tag": tag,
        "release_base_url": base_url,
        "assets": assets,
    }


def _gh_release_create(
    tag: str, archives: Iterable[Path], notes: str, target_branch: str,
    *, draft: bool = False, repo: str | None = None,
) -> None:
    cmd = [
        "gh", "release", "create", tag,
        "--target", target_branch,
        "--title", tag,
        "--notes", notes,
    ]
    if repo:
        # Pin to the origin remote's owner/repo. Without this gh would
        # pick a remote on its own — when origin is a fork and upstream
        # is the canonical repo, gh resolves to upstream and 404s with
        # the misleading "workflow scope may be required" hint.
        cmd.extend(["--repo", repo])
    if draft:
        cmd.append("--draft")
    cmd.extend(str(p) for p in archives)
    # Capture stderr so failures (auth scope, tag conflict, network) are
    # reported inline instead of swallowed by the parent Bash redirect.
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stdout:
        sys.stdout.write(result.stdout)
    if result.returncode != 0:
        sys.stderr.write(result.stderr or "")
        raise SystemExit(
            f"gh release create failed (exit={result.returncode}); "
            f"see stderr above. Tarballs preserved in the staging dir "
            f"for retry via --skip-build."
        )


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="publish_signatures_release.py",
                                description=__doc__.splitlines()[0])
    p.add_argument(
        "--tag",
        default=f"signatures-{datetime.date.today().isoformat()}",
        help="Release tag (default: signatures-YYYY-MM-DD).",
    )
    p.add_argument(
        "--target-branch", default="main",
        help="Branch to attach the release to (default: main).",
    )
    p.add_argument(
        "--base-url",
        help=("Override release_base_url. Defaults to derive from the "
              "origin git remote in normal mode, or file://<staging> in "
              "--dry-run."),
    )
    p.add_argument("--dry-run", action="store_true",
                   help="Stage tarballs and emit manifest, but do not call gh.")
    p.add_argument(
        "--draft", action="store_true",
        help=("Create the release as a draft (--draft passed to gh). "
              "Recommended for the first release of a manifest version "
              "so the asset list can be reviewed in the GitHub UI before "
              "the release is promoted to public."),
    )
    p.add_argument("--keep-staging", action="store_true",
                   help="Leave the staging directory in place after exit.")
    p.add_argument(
        "--zstd-level", type=int, default=19,
        help=("zstd compression level (default: 19, best ratio). "
              "Drop to ~15 if CPU time matters more than archive size."),
    )
    p.add_argument(
        "--manifest-out",
        help=("Write the final manifest to this path. Defaults to "
              "stelftools/signatures_manifest.json in normal mode and "
              "stdout in --dry-run."),
    )
    p.add_argument(
        "--staging-dir",
        help=("Reuse / write tarballs into this directory instead of a "
              "mktemp. Useful with --dry-run + --keep-staging when the "
              "caller wants a stable path for the file:// URLs."),
    )
    p.add_argument(
        "--skip-build", action="store_true",
        help=("Skip the tar+zstd build phase and reuse the tarballs + "
              "staging manifest already present under --staging-dir. "
              "Recovery path when gh release create failed after a "
              "successful build."),
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    repo_root = _REPO_ROOT
    if args.staging_dir:
        staging = Path(args.staging_dir).resolve()
        staging.mkdir(parents=True, exist_ok=True)
        keep_staging = True
    else:
        staging = Path(tempfile.mkdtemp(prefix="sigpublish."))
        keep_staging = args.keep_staging

    try:
        if args.base_url:
            base_url = args.base_url
        elif args.dry_run:
            base_url = f"file://{staging}"
        else:
            base_url = _resolve_default_base_url(
                _git_remote_url(repo_root), args.tag,
            )
        print(f"[publish] staging={staging}", file=sys.stderr)
        print(f"[publish] tag={args.tag}", file=sys.stderr)
        print(f"[publish] release_base_url={base_url}", file=sys.stderr)

        staging_manifest = staging / "manifest.json"
        if args.skip_build:
            if staging_manifest.is_file():
                manifest = json.loads(
                    staging_manifest.read_text(encoding="utf-8")
                )
                # The cached manifest may have been written when the
                # caller passed a different --base-url or --tag; honor
                # the current invocation's values so a retry can target
                # a different release URL without rebuilding tarballs.
                manifest["release_tag"] = args.tag
                manifest["release_base_url"] = base_url
                print(
                    f"[publish] reusing {len(manifest['assets'])} tarballs "
                    f"from staging via cached manifest",
                    file=sys.stderr,
                )
            else:
                print(
                    f"[publish] no cached manifest at {staging_manifest}; "
                    f"recomputing from staged tarballs (sha256 + size + "
                    f"covers from on-disk signatures/)",
                    file=sys.stderr,
                )
                manifest = recover_manifest_from_staging(
                    repo_root, staging, tag=args.tag, base_url=base_url,
                )
                staging_manifest.write_text(
                    json.dumps(manifest, indent=2) + "\n", encoding="utf-8",
                )
        else:
            manifest = build_manifest(
                repo_root, staging,
                tag=args.tag, base_url=base_url, zstd_level=args.zstd_level,
            )
            # Persist the manifest into the staging dir so a failed gh
            # upload can be retried via --skip-build without rebuilding.
            staging_manifest.write_text(
                json.dumps(manifest, indent=2) + "\n", encoding="utf-8",
            )
        if not manifest["assets"]:
            print("[publish] no (family, arch) pairs to publish", file=sys.stderr)
            return 0

        if args.dry_run:
            out_path = Path(args.manifest_out) if args.manifest_out else None
            if out_path is not None:
                out_path.write_text(json.dumps(manifest, indent=2) + "\n")
                print(f"[publish] manifest written to {out_path}", file=sys.stderr)
            else:
                json.dump(manifest, sys.stdout, indent=2)
                sys.stdout.write("\n")
            return 0

        archives = [staging / a["name"] for a in manifest["assets"]]
        notes = (
            f"Signature attachments generated by "
            f"tools/ci/publish_signatures_release.py on "
            f"{datetime.date.today().isoformat()}.\n\n"
            f"{len(archives)} (family, arch) bundles, "
            f"{sum(a['size_bytes'] for a in manifest['assets']) / (1024 ** 3):.1f} GB total."
        )
        repo_slug = _repo_slug_from_remote(_git_remote_url(repo_root))
        _gh_release_create(
            args.tag, archives, notes, args.target_branch,
            draft=args.draft, repo=repo_slug,
        )

        manifest_out = Path(args.manifest_out) if args.manifest_out \
            else repo_root / "stelftools" / "signatures_manifest.json"
        manifest_out.write_text(json.dumps(manifest, indent=2) + "\n")
        print(f"[publish] manifest written to {manifest_out}", file=sys.stderr)
        return 0
    finally:
        if not keep_staging:
            shutil.rmtree(staging, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
