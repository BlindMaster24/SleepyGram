#!/usr/bin/env python3
"""Remove Qt's completed source build tree while keeping prepare.py's cache marker."""

from __future__ import annotations

import argparse
import os
import re
import stat
import shutil
import sys
from pathlib import Path


def skip(reason: str) -> bool:
    print(f"WARNING: Qt source cleanup skipped: {reason}")
    return False


def retry_readonly(root: Path, function, path, exc_info, *, is_windows=None) -> None:
    error = exc_info[1]
    if is_windows is None:
        is_windows = os.name == "nt"
    if not is_windows or not isinstance(error, PermissionError) or getattr(error, "winerror", None) != 5:
        raise error

    root = os.path.normcase(os.path.abspath(root))
    target = os.path.normcase(os.path.abspath(path))
    try:
        if os.path.commonpath((root, target)) != root or target == root:
            raise error
    except ValueError:
        raise error

    current = Path(root)
    for part in Path(os.path.relpath(target, root)).parts:
        current /= part
        if current.is_symlink() or getattr(current, "is_junction", lambda: False)():
            raise error

    os.chmod(target, stat.S_IWRITE)
    function(path)


def prune(libraries: Path, version: str) -> bool:
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        return skip(f"unexpected Qt version {version!r}")
    try:
        libraries = libraries.resolve(strict=True)
    except (OSError, RuntimeError):
        return skip(f"libraries directory is missing: {libraries}")
    stage = libraries / f"qt_{version}"
    installed = libraries / f"Qt-{version}"
    cache_key = libraries / "cache_keys" / f"qt_{version}"
    try:
        resolved_stage = stage.resolve(strict=True)
    except (OSError, RuntimeError):
        return skip(f"Qt prepare stage is missing: {stage}")
    if stage.is_symlink() or getattr(stage, "is_junction", lambda: False)() or resolved_stage != stage:
        return skip(f"Qt prepare stage resolves outside its expected path: {stage} -> {resolved_stage}")
    if not stage.is_dir():
        return skip(f"Qt prepare stage is not a directory: {stage}")

    expected_files = [
        cache_key,
        installed / "lib" / "cmake" / "Qt6" / "Qt6Config.cmake",
        installed / "lib" / "Qt6Core.lib",
    ]
    expected_files.extend(installed / "bin" / tool for tool in ("moc.exe", "rcc.exe", "uic.exe"))
    missing = [path for path in expected_files if not path.is_file()]
    if missing:
        return skip("expected installed output or cache marker is missing: " + ", ".join(map(str, missing)))

    def onerror(function, path, exc_info):
        retry_readonly(stage, function, path, exc_info)

    for child in stage.iterdir():
        if child.is_symlink():
            try:
                child.unlink()
            except OSError:
                retry_readonly(stage, os.unlink, child, sys.exc_info())
        elif getattr(child, "is_junction", lambda: False)():
            os.rmdir(child)
        elif child.is_dir():
            shutil.rmtree(child, onerror=onerror)
        else:
            try:
                child.unlink()
            except OSError:
                retry_readonly(stage, os.unlink, child, sys.exc_info())
    print(f"Removed completed Qt source/build tree; retained stage marker: {stage}")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--libraries", required=True, type=Path)
    parser.add_argument("--qt-version", required=True)
    args = parser.parse_args()
    prune(args.libraries, args.qt_version)


if __name__ == "__main__":
    main()
