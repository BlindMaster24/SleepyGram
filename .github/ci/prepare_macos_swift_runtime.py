#!/usr/bin/env python3
"""Remove an unusable bundled Swift core runtime from arm64 macOS apps."""

from __future__ import annotations

import argparse
import plistlib
from pathlib import Path
import re
import subprocess
import sys


def output(command: list[str]) -> str:
    return subprocess.check_output(command, text=True, stderr=subprocess.STDOUT)


def version(value: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"(\d+)\.(\d+)(?:\.(\d+))?", value)
    if not match:
        raise RuntimeError("Invalid macOS deployment version: " + value)
    return tuple(int(part or 0) for part in match.groups())


def minimum_version(binary: Path) -> tuple[int, int, int]:
    text = output(["otool", "-l", "-arch", "arm64", str(binary)])
    field = None
    platform = None
    versions = []
    for line in text.splitlines():
        parts = line.split()
        if parts[:2] == ["cmd", "LC_BUILD_VERSION"]:
            field = "minos"
            platform = None
        elif parts[:2] == ["cmd", "LC_VERSION_MIN_MACOSX"]:
            field = "version"
            platform = "1"
        elif parts[:1] == ["Load"]:
            field = None
            platform = None
        elif field == "minos" and parts[:1] == ["platform"]:
            platform = parts[1]
        elif field and len(parts) == 2 and parts[0] == field:
            if platform in ("1", "MACOS"):
                versions.append(version(parts[1]))
    if not versions:
        raise RuntimeError("No macOS deployment target found in " + str(binary))
    return min(versions)


def dependencies(binary: Path) -> set[str]:
    text = output(["otool", "-L", "-arch", "arm64", str(binary)])
    return {line.strip().partition(" (compatibility version ")[0]
            for line in text.splitlines()[1:] if line.strip()}


def rpaths(binary: Path) -> set[str]:
    text = output(["otool", "-l", "-arch", "arm64", str(binary)])
    result = set()
    in_rpath = False
    for line in text.splitlines():
        parts = line.split()
        if parts[:2] == ["cmd", "LC_RPATH"]:
            in_rpath = True
        elif parts[:1] == ["Load"]:
            in_rpath = False
        elif in_rpath and parts[:1] == ["path"]:
            result.add(parts[1])
            in_rpath = False
    return result


def prepare(bundle: Path, minimum: str) -> None:
    bundle = bundle.resolve()
    info = plistlib.loads((bundle / "Contents/Info.plist").read_bytes())
    declared = version(str(info.get("LSMinimumSystemVersion", "")))
    requested = version(minimum)
    if declared < requested:
        raise RuntimeError(
            "The app deployment target must be at least " + minimum
            + "; found " + str(info.get("LSMinimumSystemVersion")))

    executable = info.get("CFBundleExecutable")
    if not isinstance(executable, str) or Path(executable).name != executable:
        raise RuntimeError("Invalid executable name in the macOS bundle.")
    binary = bundle / "Contents/MacOS" / executable
    if set(output(["lipo", "-archs", str(binary)]).split()) != {"arm64"}:
        raise RuntimeError("The macOS arm64 app executable must contain only arm64.")
    if minimum_version(binary) < requested:
        raise RuntimeError("The app executable targets an older macOS than " + minimum + ".")

    frameworks = bundle / "Contents/Frameworks"
    swift_core = frameworks / "libswiftCore.dylib"
    if swift_core.is_file():
        architectures = set(output(["lipo", "-archs", str(swift_core)]).split())
        if "arm64" not in architectures:
            libraries = dependencies(binary)
            system_core = "/usr/lib/swift/libswiftCore.dylib" in libraries
            rpath_core = (
                "@rpath/libswiftCore.dylib" in libraries
                and "/usr/lib/swift" in rpaths(binary))
            if not (system_core or rpath_core):
                raise RuntimeError(
                    "The bundled Swift core runtime has no arm64 slice and the app "
                    "does not resolve libswiftCore from /usr/lib/swift.")
            swift_core.unlink()
            print(
                "Removed x86-only bundled libswiftCore.dylib; the arm64 app "
                "resolves the OS Swift 5 runtime from /usr/lib/swift.",
                flush=True)

    for runtime in sorted(frameworks.glob("libswift*.dylib")):
        architectures = set(output(["lipo", "-archs", str(runtime)]).split())
        if "arm64" not in architectures:
            raise RuntimeError(
                "Bundled Swift runtime has no arm64 slice: " + runtime.name)
        if minimum_version(runtime) > requested:
            raise RuntimeError(
                "Bundled Swift runtime requires newer macOS than " + minimum
                + ": " + runtime.name)

    concurrency = frameworks / "libswift_Concurrency.dylib"
    if concurrency.is_file():
        if "/usr/lib/swift/libswiftCore.dylib" not in dependencies(concurrency):
            raise RuntimeError(
                "The bundled Swift concurrency runtime does not use the OS Swift core runtime.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--minimum", default="11.0")
    args = parser.parse_args()
    try:
        prepare(args.bundle, args.minimum)
    except (OSError, RuntimeError, subprocess.CalledProcessError, KeyError) as error:
        print("::error::" + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
