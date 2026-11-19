from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import smoke


class StartupSmokeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.package = Path(temporary.name)

    def executable(self, platform):
        if platform == "macos-arm64":
            contents = self.package / "SleepyGram.app" / "Contents"
            executable = contents / "MacOS" / "SleepyGram"
            executable.parent.mkdir(parents=True)
            (contents / "Info.plist").write_bytes(plistlib.dumps({"CFBundleExecutable": executable.name}))
        else:
            executable = self.package / ("SleepyGram.exe" if platform == "windows-x64" else "SleepyGram")
        executable.touch()
        return executable

    def smoke(self, platform, *options):
        return smoke.main(["--platform", platform, "--directory", str(self.package), *options])

    def run_with_output(self, platform, output, status, *, options=("--require-startup",)):
        self.executable(platform)
        captured = io.StringIO()
        process = Mock()
        process.wait.return_value = status

        def launch(*args, stdout, **kwargs):
            stdout.write(output)
            return process

        with patch.object(smoke.subprocess, "Popen", side_effect=launch), redirect_stdout(captured):
            result = self.smoke(platform, *options)
        return result, captured.getvalue()

    def test_native_startup_uses_disposable_profile_and_reaps_live_process(self):
        for platform, backend in (
            ("linux-x64", "xcb"),
            ("macos-arm64", "cocoa"),
            ("windows-x64", "windows"),
        ):
            with self.subTest(platform=platform):
                binary = self.executable(platform).resolve()
                process = Mock()
                process.wait.side_effect = [subprocess.TimeoutExpired(binary.name, smoke.WAIT_SECONDS), 0]

                def launch(command, *, cwd, env, **kwargs):
                    self.assertEqual(Path(command[0]), binary)
                    self.assertEqual(cwd, binary.parent)
                    self.assertEqual(command[1], "-workdir")
                    self.assertTrue(Path(command[2]).is_dir())
                    self.assertNotIn(self.package.resolve(), Path(command[2]).parents)
                    self.assertEqual(env["QT_QPA_PLATFORM"], backend)
                    self.assertEqual(env["DISPLAY"], "synthetic-display")
                    for name in ("TEST_API_KEY", "QT_PLUGIN_PATH", "QT_QPA_PLATFORM_PLUGIN_PATH"):
                        self.assertNotIn(name, env)
                    return process

                captured = io.StringIO()
                with (
                    patch.dict(os.environ, {
                        "DISPLAY": "synthetic-display",
                        "QT_QPA_PLATFORM": "inherited-backend",
                        "QT_PLUGIN_PATH": "/host/plugins",
                        "QT_QPA_PLATFORM_PLUGIN_PATH": "/host/platforms",
                        "TEST_API_KEY": "synthetic-secret",
                    }),
                    patch.object(smoke.subprocess, "Popen", side_effect=launch),
                    patch.object(smoke, "stop_tree") as stop,
                    redirect_stdout(captured),
                ):
                    self.assertEqual(self.smoke(platform, "--require-startup"), 0)
                    stop.assert_called_once_with(process)
                self.assertIn(f"stayed alive for {smoke.WAIT_SECONDS}s", captured.getvalue())

    def test_explicit_qpa_override_reports_missing_plugin_without_leaking_output(self):
        with self.assertRaises(RuntimeError) as error:
            self.run_with_output("linux-x64", (
                b"Could not find the Qt platform plugin \"offscreen\" in \"/private/profile\"\n"
                b"Available platform plugins are: xcb, sensitive-plugin, minimal.\n"
                b"::error::test-secret\n"
            ), -6, options=("--qpa-platform", "offscreen", "--require-startup"))
        message = str(error.exception)
        self.assertIn("Qt platform offscreen", message)
        self.assertIn("not found", message)
        self.assertIn("static Qt imports", message)
        self.assertIn("minimal, xcb", message)
        self.assertIn("status -6", message)
        for secret in ("/private/profile", "sensitive-plugin", "test-secret", "::error::"):
            self.assertNotIn(secret, message)

    def test_x11_failure_reports_socket_guidance_without_display_value(self):
        for display, state in (("", "unset"), ("display-secret", "set")):
            with self.subTest(state=state), patch.dict(os.environ, {"DISPLAY": display}):
                with self.assertRaises(RuntimeError) as error:
                    self.run_with_output("linux-x64", (
                        b"qt.qpa.xcb: could not connect to display display-secret\n"
                        b"This application failed to start because no Qt platform plugin could be initialized.\n"
                    ), 1)
                self.assertIn(f"DISPLAY is {state}", str(error.exception))
                self.assertIn("Xvfb and the X11 socket mount", str(error.exception))
                self.assertNotIn("display-secret", str(error.exception))

    def test_xcb_dependency_failure_is_recognized_at_end_of_large_output(self):
        with self.assertRaises(RuntimeError) as error:
            self.run_with_output("linux-x64", (
                b"unrelated application output\n" * smoke.DIAGNOSTIC_BYTES
                + b"From Qt 6.5, xcb-cursor0 or libxcb-cursor0 is needed to load the Qt xcb platform plugin.\n"
                + b"Could not load the Qt platform plugin \"xcb\" even though it was found.\n"
            ), -6)
        self.assertIn("xcb-cursor", str(error.exception))
        self.assertNotIn("unrelated application output", str(error.exception))

    def test_required_startup_rejects_even_a_clean_early_exit(self):
        with self.assertRaisesRegex(RuntimeError, r"status 0.*Qt platform windows"):
            self.run_with_output("windows-x64", b"Do not print this raw log.\n", 0)

    def test_optional_startup_keeps_the_platform_unavailable_warning(self):
        status, message = self.run_with_output(
            "windows-x64", b"No Qt platform plugin could be initialized.\n", -6, options=(),
        )
        self.assertEqual(status, 0)
        self.assertIn("::warning::", message)
        self.assertIn("windows failed to initialize", message)


if __name__ == "__main__":
    unittest.main()
