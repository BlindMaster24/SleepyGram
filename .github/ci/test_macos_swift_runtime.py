#!/usr/bin/env python3
"""Test safe removal of an x86-only Swift runtime from arm64 macOS apps."""

from __future__ import annotations

import importlib.util
import plistlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("prepare_macos_swift_runtime.py")
SPEC = importlib.util.spec_from_file_location("prepare_macos_swift_runtime", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SwiftRuntimeTests(unittest.TestCase):
    def make_bundle(self, minimum: str = "11.0") -> tuple[Path, Path, Path, Path]:
        root = Path(self.temp.name)
        bundle = root / "SleepyGram.app"
        frameworks = bundle / "Contents/Frameworks"
        frameworks.mkdir(parents=True)
        binary = bundle / "Contents/MacOS/SleepyGram"
        binary.parent.mkdir()
        binary.write_bytes(b"executable")
        core = frameworks / "libswiftCore.dylib"
        core.write_bytes(b"x86 runtime")
        concurrency = frameworks / "libswift_Concurrency.dylib"
        concurrency.write_bytes(b"universal runtime")
        with (bundle / "Contents/Info.plist").open("wb") as file:
            plistlib.dump({
                "CFBundleExecutable": "SleepyGram",
                "LSMinimumSystemVersion": minimum,
            }, file)
        return bundle, binary, core, concurrency

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def tool_output(self, command: list[str]) -> str:
        if command[0] == "lipo":
            path = command[-1]
            if path.endswith("/SleepyGram"):
                return "arm64"
            if path.endswith("/libswiftCore.dylib"):
                return "x86_64"
            return "x86_64 arm64"
        if command[1:4] == ["-l", "-arch", "arm64"]:
            if command[-1].endswith("/SleepyGram"):
                return """Load command 1
 cmd LC_BUILD_VERSION
 platform 1
 minos 11.0
Load command 2
 cmd LC_RPATH
 path /usr/lib/swift (offset 12)
"""
            return """Load command 1
 cmd LC_BUILD_VERSION
 platform 1
 minos 11.0
"""
        if command[1:4] == ["-L", "-arch", "arm64"]:
            if command[-1].endswith("/SleepyGram"):
                return """SleepyGram:
 /usr/lib/swift/libswiftCore.dylib (compatibility version 0.0.0)
 @rpath/libswift_Concurrency.dylib (compatibility version 1.0.0)
"""
            return """libswift_Concurrency.dylib:
 /usr/lib/swift/libswiftCore.dylib (compatibility version 1.0.0)
"""
        raise AssertionError("Unexpected tool invocation: " + " ".join(command))

    def test_removes_only_x86_core_when_system_runtime_is_linked(self) -> None:
        bundle, _binary, core, concurrency = self.make_bundle()
        with patch.object(MODULE, "output", side_effect=self.tool_output):
            MODULE.prepare(bundle, "11.0")
        self.assertFalse(core.exists())
        self.assertTrue(concurrency.exists())

    def test_rejects_x86_core_without_system_runtime_path(self) -> None:
        bundle, _binary, core, _concurrency = self.make_bundle()

        def no_system_core(command: list[str]) -> str:
            result = self.tool_output(command)
            if command[1:4] == ["-L", "-arch", "arm64"] and command[-1].endswith("/SleepyGram"):
                return result.replace("/usr/lib/swift/libswiftCore.dylib", "@rpath/libswiftCore.dylib")
            if command[1:4] == ["-l", "-arch", "arm64"] and command[-1].endswith("/SleepyGram"):
                return result.replace(" path /usr/lib/swift", " path @executable_path/../Frameworks")
            return result

        with patch.object(MODULE, "output", side_effect=no_system_core):
            with self.assertRaisesRegex(RuntimeError, "does not resolve libswiftCore"):
                MODULE.prepare(bundle, "11.0")
        self.assertTrue(core.exists())

    def test_requires_macos_11_or_newer(self) -> None:
        bundle, _binary, core, _concurrency = self.make_bundle("10.13")
        with patch.object(MODULE, "output", side_effect=self.tool_output):
            with self.assertRaisesRegex(RuntimeError, "at least 11.0"):
                MODULE.prepare(bundle, "11.0")
        self.assertTrue(core.exists())


if __name__ == "__main__":
    unittest.main()
