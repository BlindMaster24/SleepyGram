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
    "emergency_execution_capsule",
    "emergency_recovery_record",
    "lock_screen_submission",
    "mtproto_session_effect",
    "scoped_account_clear",
)
MODEL_SOURCES = (*TESTS, "emergency_rule_vault")


def main() -> None:
    compiler = shlex.split(os.environ.get("CXX", "c++"))
    pkg_config = shlex.split(os.environ.get("PKG_CONFIG", "pkg-config"))
    crypto_flags = shlex.split(subprocess.check_output(
        [*pkg_config, "--cflags", "libcrypto"], text=True,
    ))
    crypto_libs = shlex.split(subprocess.check_output(
        [*pkg_config, "--libs", "libcrypto"], text=True,
    ))
    flags = ["-std=c++20", "-I", str(ROOT), *crypto_flags]
    with tempfile.TemporaryDirectory(prefix="sleepygram-emergency-tests-") as temporary:
        directory = Path(temporary)
        objects = []
        for name in MODEL_SOURCES:
            target = directory / f"{name}.o"
            subprocess.run([
                *compiler, *flags, "-c", str(MODEL / f"{name}.cpp"), "-o", str(target),
            ], check=True)
            objects.append(str(target))
        for name in TESTS:
            executable = directory / f"test_{name}"
            subprocess.run([
                *compiler, *flags, str(ROOT / "tests" / f"test_{name}.cpp"),
                *objects, *crypto_libs, "-o", str(executable),
            ], check=True)
            subprocess.run([str(executable)], check=True)


if __name__ == "__main__":
    main()
