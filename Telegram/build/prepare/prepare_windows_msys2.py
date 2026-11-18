#!/usr/bin/env python3
"""Prepare the isolated MSYS2 distribution used by the Windows build."""

import argparse
from pathlib import Path
import subprocess
import time


PACKAGES = (
    "make",
    "mingw-w64-ucrt-x86_64-diffutils",
    "mingw-w64-ucrt-x86_64-gperf",
    "mingw-w64-ucrt-x86_64-nasm",
    "mingw-w64-ucrt-x86_64-perl",
    "mingw-w64-ucrt-x86_64-pkgconf",
)


def prefer_primary_server(msys_root: Path) -> None:
    for repository in ("msys", "mingw"):
        path = msys_root / "etc" / "pacman.d" / f"mirrorlist.{repository}"
        primary = f"Server = https://repo.msys2.org/{repository}/$arch/"
        lines = path.read_text(encoding="utf-8").splitlines()
        retained = [line for line in lines if line.strip() != primary]
        path.write_text("\n".join([primary, *retained]) + "\n", encoding="utf-8")


def update(msys_root: Path, packages: tuple[str, ...]) -> None:
    pacman = msys_root / "usr" / "bin" / "pacman.exe"
    command = [str(pacman), "-Syu", "--noconfirm", *packages]
    for attempt, delay in enumerate((0, 10, 30), start=1):
        if delay:
            time.sleep(delay)
        prefer_primary_server(msys_root)
        result = subprocess.run(command, check=False)
        if result.returncode == 0:
            return
        print(f"MSYS2 update attempt {attempt} failed with exit code {result.returncode}.", flush=True)
    raise subprocess.CalledProcessError(result.returncode, command)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("msys_root", type=Path)
    args = parser.parse_args()
    root = args.msys_root.resolve(strict=True)
    bash = root / "usr" / "bin" / "bash.exe"
    subprocess.run([str(bash), "-c", "pacman-key --init && pacman-key --populate"], check=True)
    update(root, ())
    update(root, PACKAGES)


if __name__ == "__main__":
    main()
