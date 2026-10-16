"""
GhostWire Standalone Binary Builder
------------------------------------
Compiles GhostWire into a standalone, single-file native executable
using PyInstaller for distribution without requiring a Python environment.
"""

from __future__ import annotations

import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys


def build_binary() -> int:
    """Compile GhostWire into a single-file executable."""
    root_dir = Path(__file__).resolve().parent.parent
    dist_dir = root_dir / "dist" / "binaries"
    dist_dir.mkdir(parents=True, exist_ok=True)

    os_name = platform.system().lower()
    arch = platform.machine().lower()
    if arch in ("amd64", "x86_64"):
        arch_tag = "x64"
    elif arch in ("arm64", "aarch64"):
        arch_tag = "arm64"
    else:
        arch_tag = arch

    if os_name == "windows":
        binary_name = f"ghostwire-windows-{arch_tag}.exe"
    elif os_name == "darwin":
        binary_name = f"ghostwire-macos-{arch_tag}"
    else:
        binary_name = f"ghostwire-linux-{arch_tag}"

    print(f"[*] Building GhostWire Standalone Binary for {platform.system()} ({arch_tag})...")

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onefile",
        "--clean",
        "--name",
        binary_name.replace(".exe", ""),
        "--distpath",
        str(dist_dir),
        str(root_dir / "ghostwire.py"),
    ]

    result = subprocess.run(cmd, cwd=root_dir)
    if result.returncode != 0:
        print(f"[!] PyInstaller compilation failed with code {result.returncode}", file=sys.stderr)
        return result.returncode

    # Locate output
    candidate = dist_dir / binary_name
    if not candidate.exists():
        # Check without suffix
        base_name = binary_name.replace(".exe", "")
        for f in dist_dir.glob(f"{base_name}*"):
            candidate = f
            break

    if candidate.exists():
        size_mb = candidate.stat().st_size / (1024 * 1024)
        print(f"\n[+] Build Complete!")
        print(f"    - Binary: {candidate.resolve()}")
        print(f"    - File Size: {size_mb:.2f} MB")
        print(f"    - Test Run: {candidate} --version")
    else:
        print("[!] Executable not found in output directory.", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(build_binary())
