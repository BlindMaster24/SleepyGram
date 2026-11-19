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
DIAGNOSTIC_BYTES = 16 * 1024
NATIVE_QPA = {
    "linux-x64": "xcb",
    "macos-arm64": "cocoa",
    "windows-x64": "windows",
}
KNOWN_QPA = {
    "cocoa", "directfb", "eglfs", "linuxfb", "minimal", "minimalegl",
    "offscreen", "vnc", "wayland", "wayland-egl", "windows", "xcb",
}
X11_FAILURE = (
    "could not connect to display",
    "could not connect to any x display",
)


def qpa_label(qpa_platform: str) -> str:
    name = qpa_platform.partition(":")[0].lower()
    return f"Qt platform {name}" if name in KNOWN_QPA else "custom Qt platform"


def early_qt_diagnostic(log: Path, qpa_platform: str, has_display: bool) -> str | None:
    with log.open("rb") as output:
        head = output.read(DIAGNOSTIC_BYTES)
        size = output.seek(0, os.SEEK_END)
        output.seek(max(len(head), size - DIAGNOSTIC_BYTES))
        tail = output.read(DIAGNOSTIC_BYTES)
    text = (head + b"\n" + tail).decode("utf-8", errors="replace").lower()
    label = qpa_label(qpa_platform)
    if any(marker in text for marker in X11_FAILURE):
        display = "set" if has_display else "unset"
        return f"Qt could not open the X11 display (DISPLAY is {display}). Check Xvfb and the X11 socket mount."
    if "failed to create wl_display" in text:
        return "Qt could not open a Wayland display. Check the compositor and its socket in the smoke environment."
    if "could not find the qt platform plugin" in text:
        diagnostic = f"The plugin for {label} was not found. Check the packaged plugin or static Qt imports."
    elif "could not load the qt platform plugin" in text:
        diagnostic = f"The plugin for {label} failed to load. Check its runtime library dependencies."
        if "xcb-cursor" in text and qpa_platform == "xcb":
            diagnostic += " Qt reported that the xcb-cursor library is required."
    elif "no qt platform plugin could be initialized" in text:
        diagnostic = f"{label.capitalize()} failed to initialize. Check the packaged plugin and runner display."
    else:
        return None
    plugins = set()
    for line in text.splitlines():
        _, marker, names = line.partition("available platform plugins are:")
        if marker:
            plugins.update(part.strip().rstrip(".") for part in names.split(","))
    available = ", ".join(sorted(plugins & KNOWN_QPA))
    return f"{diagnostic} Available known Qt plugins: {available}." if available else diagnostic


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
            "QT_PLUGIN_PATH", "QT_QPA_PLATFORM_PLUGIN_PATH",
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=NATIVE_QPA, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--qpa-platform", help="Override the platform-native Qt backend.")
    parser.add_argument("--require-startup", action="store_true")
    args = parser.parse_args(argv)
    qpa_platform = args.qpa_platform or NATIVE_QPA[args.platform]
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
        environment = sanitized_environment(root, qpa_platform)
        with log.open("wb") as output:
            process = subprocess.Popen(
                [str(executable), "-workdir", str(profile)],
                cwd=executable.parent,
                env=environment,
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

        if diagnostic := early_qt_diagnostic(log, qpa_platform, bool(environment.get("DISPLAY"))):
            message = f"Startup smoke on {args.platform} exited with status {status}. {diagnostic}"
            if args.require_startup:
                raise RuntimeError(message)
            print(f"::warning::{message}")
            return 0
        if status == 0 and not args.require_startup:
            print(f"::warning::Startup smoke inconclusive on {args.platform}: process exited before {WAIT_SECONDS}s.")
            return 0
        raise RuntimeError(
            f"Startup smoke exited early with status {status} on {args.platform} ({qpa_label(qpa_platform)})."
        )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError, plistlib.InvalidFileException) as error:
        print(f"::error::{error}", file=sys.stderr)
        raise SystemExit(1)
