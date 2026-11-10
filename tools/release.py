"""Build checksum-pinned raw lokr release assets; never start interactive modes.

Run with: uv run --no-project --python 3.12 python tools/release.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        **kwargs,
    )


def verify_native(binary: Path, version: str) -> None:
    """Prove startup and the noninteractive wire contract without reading secrets."""
    environment = os.environ.copy()
    environment.pop("DISPLAY", None)
    environment.pop("WAYLAND_DISPLAY", None)
    environment["LOKR_TEST_MODE"] = "1"
    with tempfile.TemporaryDirectory() as directory:
        environment["LOKR_HOME"] = directory
        for argument, expected in [
            ("--version", f"lokr {version}\n"),
            (
                "--dry-run",
                f'{{"status":"ok","version":"{version}","interactive":false}}\n',
            ),
        ]:
            result = run(
                [str(binary), argument],
                env=environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=15,
            )
            if (
                result.stdout != expected
                or result.stderr
                or any(Path(directory).iterdir())
            ):
                raise RuntimeError(
                    f"noninteractive verification failed for {binary.name}"
                )


def native_verifiable(target: str) -> bool:
    architecture = platform.machine().lower()
    machine = {"amd64": "x86_64", "arm64": "aarch64"}.get(architecture, architecture)
    suffix = {
        "Linux": "unknown-linux-musl",
        "Darwin": "apple-darwin",
        "Windows": "pc-windows-msvc",
    }
    return target == f"{machine}-{suffix.get(platform.system(), 'unsupported')}"


def verify_linux_linkage(binary: Path, target: str) -> None:
    """Keep host-specific Nix loaders out of GNU assets and musl assets static."""
    if "-linux-" not in target:
        return
    reader = shutil.which("llvm-readelf") or shutil.which("readelf")
    if not reader:
        raise RuntimeError(
            "Linux artifact verification requires llvm-readelf or readelf"
        )
    report = run(
        [reader, "-l", "-d", str(binary)], capture_output=True, text=True
    ).stdout
    if target.endswith("musl"):
        if "Requesting program interpreter" in report or "(NEEDED)" in report:
            raise RuntimeError(f"musl artifact is not static: {binary.name}")
    elif (
        "/nix/store/" in report or "Requesting program interpreter: /lib" not in report
    ):
        raise RuntimeError(
            f"GNU artifact has a nonportable loader or library path: {binary.name}"
        )


def build(target: str, output: Path, version: str) -> dict:
    environment = os.environ.copy()
    environment.pop("DISPLAY", None)
    environment.pop("WAYLAND_DISPLAY", None)
    environment["CARGO_TARGET_DIR"] = str(ROOT / "target")
    if target.endswith("windows-msvc"):
        environment["RUSTFLAGS"] = (
            environment.get("RUSTFLAGS", "") + " -C target-feature=+crt-static"
        )
    run(["soldr", "prepare", "--target", target], env=environment)
    run(
        ["soldr", "cargo", "build", "--release", "--locked", "--target", target],
        env=environment,
    )
    extension = ".exe" if target.endswith("windows-msvc") else ""
    asset = output / f"lokr-{target}{extension}"
    shutil.copy2(ROOT / "target" / target / "release" / f"lokr{extension}", asset)
    asset.chmod(0o755)
    verify_linux_linkage(asset, target)
    if native_verifiable(target):
        verify_native(asset, version)
    with asset.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {
        "target": target,
        "asset": asset.name,
        "sha256": digest,
        "size_bytes": asset.stat().st_size,
        "format": "raw",
        "member": None,
    }


def main() -> None:
    manifest = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    version = manifest["package"]["version"]
    targets = manifest["workspace"]["metadata"]["soldr"]["targets"]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", action="append", choices=targets)
    arguments = parser.parse_args()
    if manifest.get("patch"):
        raise RuntimeError(
            "release builds require registry dependencies, without migration path patches"
        )
    if run(["git", "status", "--porcelain"], capture_output=True, text=True).stdout:
        raise RuntimeError("release builds require a clean committed checkout")
    commit = run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True
    ).stdout.strip()
    output = ROOT / "dist" / f"v{version}"
    output.mkdir(parents=True, exist_ok=True)
    artifacts = [
        build(target, output, version) for target in arguments.target or targets
    ]
    release = {
        "schema_version": 1,
        "version": version,
        "source_commit": commit,
        "artifacts": artifacts,
    }
    (output / "lokr-artifacts.json").write_text(
        json.dumps(release, indent=2) + "\n", encoding="utf-8"
    )
    (output / "SHA256SUMS").write_text(
        "".join(f"{entry['sha256']}  {entry['asset']}\n" for entry in artifacts),
        encoding="utf-8",
    )
    print(output)


if __name__ == "__main__":
    main()
