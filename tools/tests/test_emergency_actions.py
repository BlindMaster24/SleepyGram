#!/usr/bin/env python3
"""Build and run the standalone emergency reset fixtures."""

from pathlib import Path
import os
import shlex
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2] / "Telegram" / "SourceFiles"
MODEL = ROOT / "ayu" / "features" / "emergency_actions"
TESTS = (
    "emergency_action_plan",
    "emergency_action_journal",
    "emergency_rule_dispatch",
    "emergency_action_coordinator",
    "emergency_action_runtime_service",
    "lock_screen_submission",
    "mtproto_session_effect",
    "scoped_account_clear",
)


def main() -> None:
    compiler = shlex.split(os.environ.get("CXX", "c++"))
    flags = ["-std=c++20", "-I", str(ROOT)]
    with tempfile.TemporaryDirectory(prefix="sleepygram-emergency-tests-") as temporary:
        directory = Path(temporary)
        objects = []
        for name in TESTS:
            target = directory / f"{name}.o"
            subprocess.run([
                *compiler, *flags, "-c", str(MODEL / f"{name}.cpp"), "-o", str(target),
            ], check=True)
            objects.append(str(target))
        for name in TESTS:
            executable = directory / f"test_{name}"
            subprocess.run([
                *compiler, *flags, str(ROOT / "tests" / f"test_{name}.cpp"),
                *objects, "-o", str(executable),
            ], check=True)
            subprocess.run([str(executable)], check=True)


if __name__ == "__main__":
    main()
