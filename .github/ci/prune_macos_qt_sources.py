#!/usr/bin/env python3
"""Remove macOS Qt source/build files while preserving prepare.py's cache hit."""

from __future__ import annotations

import argparse
import re
import shutil
import sys
from pathlib import Path


def skip(reason: str) -> bool:
    print(f"::warning::macOS Qt cache pruning skipped: {reason}")
    return False


def prune(libraries: Path, version: str) -> bool:
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        return skip(f"unexpected Qt version {version!r}")
    try:
        libraries = libraries.resolve(strict=True)
    except (OSError, RuntimeError):
        return skip(f"Libraries directory is missing: {libraries}")

    stage = libraries / f"qt_{version}"
    marker = libraries / "cache_keys" / f"qt_{version}"
    installed = libraries / "local" / f"Qt-{version}"
    try:
        resolved_stage = stage.resolve(strict=True)
    except (OSError, RuntimeError):
        return skip(f"Qt prepare stage is missing: {stage}")
    if stage.is_symlink() or resolved_stage != stage:
        return skip(f"Qt prepare stage resolves outside its expected path: {stage} -> {resolved_stage}")
    if not stage.is_dir():
        return skip(f"Qt prepare stage is not a directory: {stage}")

    try:
        marker_value = marker.read_text().strip()
    except OSError:
        return skip(f"Qt prepare cache marker is missing: {marker}")
    if not re.fullmatch(r"[0-9a-f]{40}", marker_value):
        return skip(f"Qt prepare cache marker is invalid: {marker}")

    try:
        resolved_installed = installed.resolve(strict=True)
    except (OSError, RuntimeError):
        return skip(f"installed Qt prefix is missing: {installed}")
    if installed.is_symlink() or resolved_installed != installed:
        return skip(f"installed Qt prefix resolves outside its expected path: {installed} -> {resolved_installed}")

    expected_files = [
        installed / "include" / "QtCore" / "qglobal.h",
        installed / "lib" / "cmake" / "Qt6" / "Qt6Config.cmake",
    ]
    expected_files.extend(
        installed / "lib" / f"libQt6{module}.a"
        for module in ("Core", "Gui", "Widgets")
    )

    def is_installed_file(path: Path) -> bool:
        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError):
            return False
        return path.is_file() and resolved.is_relative_to(resolved_installed)

    missing = [path for path in expected_files if not is_installed_file(path)]
    if missing:
        return skip("expected installed static Qt output is missing: " + ", ".join(map(str, missing)))
    tool_dirs = (installed / "libexec", installed / "bin")
    if not any(
        all(
            is_installed_file(path) and (path.stat().st_mode & 0o111)
            for path in (tool_dir / name for name in ("moc", "rcc", "uic")))
        for tool_dir in tool_dirs):
        return skip("expected installed Qt tools are missing or not executable in libexec or bin")

    try:
        for child in stage.iterdir():
            if child.is_symlink():
                child.unlink()
            elif child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    except OSError as error:
        return skip(f"could not remove Qt source/build contents: {error}")

    print(f"Removed macOS Qt source/build contents; retained stage and marker: {stage}")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--libraries", required=True, type=Path)
    parser.add_argument("--qt-version", required=True)
    args = parser.parse_args()
    if not prune(args.libraries, args.qt_version):
        sys.exit(1)


if __name__ == "__main__":
    main()
