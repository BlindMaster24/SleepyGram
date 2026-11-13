#!/usr/bin/env python3
"""Write safe build manifests and verify same-run release artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import subprocess
import sys
import tarfile
import zipfile


MANIFEST = "build-manifest.json"
PLATFORMS = {
    "linux-x64": ("SleepyGram-linux-x64.tar.xz", "tar.xz"),
    "macos-arm64": ("SleepyGram-macos-arm64.zip", "zip"),
    "windows-x64": ("SleepyGram-windows-x64.zip", "zip"),
}
MAX_MANIFEST_SIZE = 1024 * 1024


def command_output(command: list[str], cwd: Path | None = None) -> str | None:
    try:
        result = subprocess.run(
            command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, check=False,
        )
    except (FileNotFoundError, OSError):
        return None
    if result.returncode not in (0, 1):
        return None
    return result.stdout.strip() or None


def first_line(command: list[str], cwd: Path | None = None) -> str | None:
    output = command_output(command, cwd)
    return next((line.strip() for line in (output or "").splitlines() if line.strip()), None)


def cmake_values(repo_root: Path, build_dir: Path) -> dict[str, str]:
    for candidate in (build_dir / "CMakeCache.txt", build_dir.parent / "CMakeCache.txt"):
        if not candidate.is_file():
            continue
        result = {}
        for line in candidate.read_text(errors="replace").splitlines():
            if line.startswith(("#", "//")) or ":" not in line or "=" not in line:
                continue
            key, _, value = line.partition("=")
            result[key.partition(":")[0]] = value
        return result
    raise RuntimeError("CMakeCache.txt was not found for the build manifest.")


def qt_version(values: dict[str, str], requested: str | None) -> tuple[str, str]:
    for key in ("QT_VERSION", "Qt6Core_VERSION", "Qt5Core_VERSION", "Qt6_VERSION", "Qt5_VERSION"):
        value = values.get(key, "").strip()
        if re.fullmatch(r"\d+\.\d+(?:\.\d+)?", value):
            if requested and value != requested:
                raise RuntimeError(f"CMake selected Qt {value}, expected {requested}.")
            return value, f"CMakeCache:{key}"
    for key, value in values.items():
        match = re.search(r"(?:^|[/\\])Qt-(\d+\.\d+(?:\.\d+)?)(?:[/\\]|$)", value)
        if match:
            version = match.group(1)
            if requested and version != requested:
                raise RuntimeError(f"CMake selected Qt {version}, expected {requested}.")
            return version, f"CMakeCache:{key}"
    if requested:
        return requested, "CI_QT_VERSION"
    raise RuntimeError("Could not determine the Qt version.")


def submodule_revisions(repo_root: Path) -> list[dict[str, str | bool]]:
    output = command_output(["git", "submodule", "status", "--recursive"], repo_root)
    if not output:
        raise RuntimeError("Could not read recursive submodule status.")
    revisions = []
    for line in output.splitlines():
        match = re.match(r"^([ +\-U])([0-9a-f]{40})\s+(\S+)", line)
        if not match:
            raise RuntimeError("Could not safely parse submodule status.")
        marker, revision, path = match.groups()
        if marker == "-":
            raise RuntimeError(f"Submodule is not initialized: {path}")
        if marker == "U":
            raise RuntimeError(f"Submodule has an unresolved merge: {path}")
        revisions.append({"path": path, "actual_sha": revision, "gitlink_match": marker != "+"})
    return revisions


def submodule_tree_fingerprint(repo_root: Path) -> str:
    status = command_output(["git", "submodule", "status", "--recursive"], repo_root) or ""
    values = []
    for line in status.splitlines():
        match = re.match(r"^([ +\-U])([0-9a-f]{40})\s+(\S+)", line)
        if not match:
            continue
        _marker, revision, path = match.groups()
        tree = command_output(["git", "-C", path, "rev-parse", "HEAD^{tree}"], repo_root)
        values.append(f"{path}:{tree or revision}")
    return "\n".join(values)


def create_manifest(args: argparse.Namespace) -> None:
    repo_root = args.repo_root.resolve()
    build_dir = args.build_dir.resolve()
    actual_sha = command_output(["git", "rev-parse", "HEAD"], repo_root)
    source_sha = os.environ.get("GITHUB_SHA", "").strip() or actual_sha
    if not source_sha or not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise RuntimeError("The source commit SHA is missing or malformed.")
    if actual_sha and actual_sha != source_sha:
        raise RuntimeError("Checked out source does not match GITHUB_SHA.")

    cache = cmake_values(repo_root, build_dir)
    detected_qt, qt_source = qt_version(cache, args.qt_version)
    if args.platform == "windows-x64":
        compiler = command_output(["cl", "/Bv"])
    elif args.platform == "linux-x64":
        compiler = os.environ.get("CI_CONTAINER_CXX")
    else:
        compiler = command_output(["c++", "--version"])
    compiler_lines = [line.strip() for line in (compiler or "").splitlines() if line.strip()]
    toolchain = {
        "runner": {
            "os": os.environ.get("RUNNER_OS", platform.system()),
            "architecture": os.environ.get("RUNNER_ARCH", platform.machine()),
            "image": os.environ.get("ImageOS"),
        },
        "qt": {"version": detected_qt, "source": qt_source},
        "cmake": {
            "version": os.environ.get("CI_CONTAINER_CMAKE") if args.platform == "linux-x64" else first_line(["cmake", "--version"]),
            "generator": cache.get("CMAKE_GENERATOR"),
            "compiler_id": cache.get("CMAKE_CXX_COMPILER_ID"),
            "compiler_version": cache.get("CMAKE_CXX_COMPILER_VERSION"),
            "compiler_runtime": " | ".join(compiler_lines[:3]) or None,
            "osx_architectures": cache.get("CMAKE_OSX_ARCHITECTURES"),
        },
        "container_image": args.container_image or None,
        "windows_sdk": os.environ.get("WINDOWS_SDK_VERSION"),
        "visual_studio": os.environ.get("VisualStudioVersion"),
        "xcode": command_output(["xcodebuild", "-version"]) if args.platform == "macos-arm64" else None,
        "macos_sdk": first_line(["xcrun", "--show-sdk-version"]) if args.platform == "macos-arm64" else None,
    }
    manifest = {
        "schema_version": 1,
        "platform": args.platform,
        "source": {
            "commit": source_sha,
            "workflow_run_id": os.environ.get("GITHUB_RUN_ID", "local"),
            "workflow_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "1"),
        },
        "submodules": submodule_revisions(repo_root),
        "toolchain": toolchain,
        "package": {"archive": PLATFORMS[args.platform][0]},
    }
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(f"Wrote {output.name} for {args.platform} at {source_sha}")


def safe_member(name: str) -> str:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise RuntimeError(f"Unsafe archive path: {name}")
    return path.as_posix()


def archive_members(archive: Path, platform_name: str) -> tuple[set[str], bytes]:
    if PLATFORMS[platform_name][1] == "zip":
        with zipfile.ZipFile(archive) as package:
            names = {safe_member(item.filename) for item in package.infolist() if not item.is_dir()}
            manifest_path = "SleepyGram.app/Contents/Resources/BuildManifest.json" if platform_name == "macos-arm64" else MANIFEST
            info = package.getinfo(manifest_path)
            if info.file_size > MAX_MANIFEST_SIZE:
                raise RuntimeError("Artifact manifest exceeds the 1 MiB safety limit.")
            manifest = package.read(info)
            return names, manifest
    with tarfile.open(archive, "r:xz") as package:
        names = {safe_member(item.name) for item in package.getmembers() if item.isfile()}
        info = package.getmember(MANIFEST)
        if not info.isfile() or info.size > MAX_MANIFEST_SIZE:
            raise RuntimeError("Linux artifact manifest is missing or too large.")
        stream = package.extractfile(info)
        if stream is None:
            raise RuntimeError("Could not read Linux artifact manifest.")
        return names, stream.read()


def verify_package(archive: Path, platform_name: str) -> dict[str, object]:
    if archive.name != PLATFORMS[platform_name][0]:
        raise RuntimeError(f"Expected artifact name {PLATFORMS[platform_name][0]}.")
    names, manifest_bytes = archive_members(archive, platform_name)
    if platform_name == "linux-x64":
        required = {"SleepyGram", MANIFEST}
        allowed = required | {"Updater"}
    elif platform_name == "windows-x64":
        required = {"SleepyGram.exe", MANIFEST}
        allowed = required | {"Updater.exe", "modules/x64/d3d/d3dcompiler_47.dll"}
    else:
        required = {
            "SleepyGram.app/Contents/Info.plist",
            "SleepyGram.app/Contents/Resources/Telegram.rcc",
            "SleepyGram.app/Contents/Resources/BuildManifest.json",
        }
        if not any(name.startswith("SleepyGram.app/Contents/MacOS/") for name in names):
            raise RuntimeError("macOS archive is missing the app executable.")
        allowed = {
            name for name in names
            if name.startswith("SleepyGram.app/") or name.startswith("__MACOSX/")
        }
    missing = required - names
    if missing:
        raise RuntimeError("Artifact is missing required files: " + ", ".join(sorted(missing)))
    if platform_name != "macos-arm64":
        unexpected = names - allowed
        if unexpected:
            raise RuntimeError("Unexpected artifact files: " + ", ".join(sorted(unexpected)[:8]))
    try:
        manifest = json.loads(manifest_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("Artifact manifest is not valid JSON.") from error
    if manifest.get("schema_version") != 1 or manifest.get("platform") != platform_name:
        raise RuntimeError("Artifact manifest does not match its platform.")
    return manifest


def verify_release(args: argparse.Namespace) -> None:
    archives = [path for path in args.directory.resolve().rglob("*") if path.is_file() and path.name in {
        spec[0] for spec in PLATFORMS.values()
    }]
    if len(archives) != len(PLATFORMS):
        raise RuntimeError("Release requires exactly one archive for each of the three platforms.")
    by_name = {path.name: path for path in archives}
    if len(by_name) != len(archives):
        raise RuntimeError("Duplicate platform archive found in downloaded artifacts.")
    expected = {
        "commit": args.source_sha,
        "workflow_run_id": str(args.run_id),
        "workflow_run_attempt": str(args.run_attempt),
    }
    for platform_name, (filename, _kind) in PLATFORMS.items():
        if filename not in by_name:
            raise RuntimeError(f"Release artifact is missing: {filename}")
        manifest = verify_package(by_name[filename], platform_name)
        source = manifest.get("source", {})
        for key, value in expected.items():
            if str(source.get(key, "")) != value:
                raise RuntimeError(f"{filename} does not match this run's {key}.")
    print("Verified all three packages came from this workflow run and source SHA.")


def cache_key(args: argparse.Namespace) -> None:
    repo_root = args.repo_root.resolve()
    digest = hashlib.sha256()
    digest.update(args.platform.encode())
    digest.update(os.environ.get("CI_QT_VERSION", "6.11.2").encode())
    digest.update(os.environ.get("WINDOWS_SDK_VERSION", "").encode())
    digest.update(os.environ.get("ImageOS", "").encode())
    digest.update(os.environ.get("RUNNER_OS", "").encode())
    digest.update(os.environ.get("RUNNER_ARCH", "").encode())
    inputs = [repo_root / ".github/workflows/build.yml", repo_root / ".gitmodules"]
    if args.platform == "linux-x64":
        inputs += [repo_root / "Telegram/build/docker/centos_env", repo_root / "Telegram/build/prepare/patches"]
    else:
        inputs += [repo_root / "Telegram/build/prepare", repo_root / "Telegram/build/qt_version.py"]
        inputs += [repo_root / "Telegram/build/sync_ayu_submodules.py"]
    files = []
    for path in inputs:
        if path.is_dir():
            files.extend(item for item in path.rglob("*") if item.is_file() and ".git" not in item.parts)
        elif path.is_file():
            files.append(path)
    for path in sorted(set(files)):
        digest.update(path.relative_to(repo_root).as_posix().encode())
        digest.update(path.read_bytes())
    if args.platform != "linux-x64":
        digest.update(submodule_tree_fingerprint(repo_root).encode())
    tool_versions = ["cmake --version", "ninja --version"]
    if args.platform == "macos-arm64":
        tool_versions += ["clang++ --version", "xcodebuild -version", "xcrun --show-sdk-version"]
    elif args.platform == "windows-x64":
        tool_versions += ["cl /Bv", "where cmake"]
    else:
        tool_versions += ["docker version --format {{.Server.Version}}"]
    for command in tool_versions:
        digest.update(command.encode())
        digest.update((command_output(command.split(), repo_root) or "missing").encode())
    value = digest.hexdigest()
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with Path(output).open("a") as file:
            file.write(f"key={value}\n")
    print(value)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="write a package build manifest")
    create.add_argument("--platform", choices=sorted(PLATFORMS), required=True)
    create.add_argument("--repo-root", type=Path, required=True)
    create.add_argument("--build-dir", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--qt-version")
    create.add_argument("--container-image")
    create.set_defaults(function=create_manifest)
    package = commands.add_parser("verify-package", help="check archive structure and manifest")
    package.add_argument("--platform", choices=sorted(PLATFORMS), required=True)
    package.add_argument("--archive", type=Path, required=True)
    package.set_defaults(function=lambda args: verify_package(args.archive.resolve(), args.platform))
    release = commands.add_parser("verify-release", help="check complete same-run package set")
    release.add_argument("--directory", type=Path, required=True)
    release.add_argument("--source-sha", required=True)
    release.add_argument("--run-id", required=True)
    release.add_argument("--run-attempt", required=True)
    release.set_defaults(function=verify_release)
    cache = commands.add_parser("cache-key", help="calculate an input-sensitive cache key")
    cache.add_argument("--platform", choices=sorted(PLATFORMS), required=True)
    cache.add_argument("--repo-root", type=Path, required=True)
    cache.set_defaults(function=cache_key)
    return root


def main() -> int:
    try:
        args = parser().parse_args()
        args.function(args)
    except (OSError, RuntimeError, subprocess.CalledProcessError, tarfile.TarError, zipfile.BadZipFile, KeyError) as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
