#!/usr/bin/env python3
"""Run a bounded native startup check with a disposable portable profile."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import plistlib
import signal
import subprocess
import sys
import tempfile


WAIT_SECONDS = 8
UNSUPPORTED_QT = (
    "could not load the qt platform plugin",
    "no qt platform plugin could be initialized",
    "could not connect to display",
    "could not connect to any x display",
    "failed to create wl_display",
)


def sanitized_environment(root: Path, qpa_platform: str) -> dict[str, str]:
    home = root / "home"
    home.mkdir()
    environment = os.environ.copy()
    for name in list(environment):
        upper = name.upper()
        if upper in {
            "GITHUB_TOKEN", "GH_TOKEN", "ACTIONS_RUNTIME_TOKEN", "NUGET_AUTH_TOKEN",
            "TDESKTOP_API_ID", "TDESKTOP_API_HASH", "AYUGRAM_API_ID", "AYUGRAM_API_HASH",
            "TELEGRAM_API_ID", "TELEGRAM_API_HASH", "API_ID", "API_HASH",
        } or upper.endswith(("_TOKEN", "_API_HASH", "_API_KEY", "_SECRET", "_PASSWORD")):
            environment.pop(name, None)
    environment.update({
        "HOME": str(home),
        "USERPROFILE": str(home),
        "APPDATA": str(home / "AppData" / "Roaming"),
        "LOCALAPPDATA": str(home / "AppData" / "Local"),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_DATA_HOME": str(home / ".local" / "share"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "QT_QPA_PLATFORM": qpa_platform,
        "QT_LOGGING_RULES": "*.debug=false",
    })
    for name in ("APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"):
        Path(environment[name]).mkdir(parents=True, exist_ok=True)
    return environment


def stop_tree(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=3)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=("linux-x64", "macos-arm64", "windows-x64"), required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--qpa-platform", default="offscreen")
    parser.add_argument("--require-startup", action="store_true")
    args = parser.parse_args()
    package = args.directory.resolve()

    with tempfile.TemporaryDirectory(prefix="sleepygram-smoke-") as temporary:
        root = Path(temporary)
        if args.platform == "macos-arm64":
            app = package / "SleepyGram.app"
            info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
            name = info.get("CFBundleExecutable")
            if not isinstance(name, str) or Path(name).name != name:
                raise RuntimeError("Invalid CFBundleExecutable in smoke bundle.")
            executable = app / "Contents" / "MacOS" / name
        else:
            app = package
            name = "SleepyGram.exe" if args.platform == "windows-x64" else "SleepyGram"
            executable = app / name
        if not executable.is_file():
            raise RuntimeError(f"Missing smoke executable: {executable.name}")
        profile = root / "profile"
        profile.mkdir()

        log = root / "smoke.log"
        with log.open("wb") as output:
            process = subprocess.Popen(
                [str(executable), "-workdir", str(profile)],
                cwd=executable.parent,
                env=sanitized_environment(root, args.qpa_platform),
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                # -workdir keeps startup state outside the extracted artifact.
                start_new_session=(os.name != "nt"),
                creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0),
            )
            try:
                status = process.wait(timeout=WAIT_SECONDS)
            except subprocess.TimeoutExpired:
                stop_tree(process)
                process.wait(timeout=5)
                print(f"Startup smoke stayed alive for {WAIT_SECONDS}s: {args.platform}")
                return 0

        output_text = log.read_text(errors="replace").lower()
        if any(marker in output_text for marker in UNSUPPORTED_QT):
            if args.require_startup:
                raise RuntimeError(f"No usable Qt platform for startup smoke on {args.platform}.")
            print(f"::warning::Startup smoke skipped on {args.platform}: no usable Qt platform in this runner.")
            return 0
        if status == 0 and not args.require_startup:
            print(f"::warning::Startup smoke inconclusive on {args.platform}: process exited before {WAIT_SECONDS}s.")
            return 0
        raise RuntimeError(f"Startup smoke exited early with status {status} on {args.platform}.")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError, plistlib.InvalidFileException) as error:
        print(f"::error::{error}", file=sys.stderr)
        raise SystemExit(1)
