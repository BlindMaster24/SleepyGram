import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from build_diagnostics import diagnostic_priority, prioritized_diagnostics


class BuildDiagnosticTests(unittest.TestCase):
    def test_numeric_resource_compiler_code(self):
        line = "Telegram/Resources/langs/lang.strings(9246): error 806: plural tag requires an other form"
        self.assertEqual(diagnostic_priority(line), 0)

    def test_gcc_syntax_error(self):
        line = "src/parser.cpp: syntax error, unexpected identifier"
        self.assertEqual(diagnostic_priority(line), 0)

    def test_gcc_error_without_code(self):
        line = "src/parser.cpp:12:8: error: expected ';' before '}' token"
        self.assertEqual(diagnostic_priority(line), 0)

    def test_existing_letter_prefixed_compiler_code(self):
        line = "src/parser.cpp:12:8: error C2039: unknown member"
        self.assertEqual(diagnostic_priority(line), 0)

    def test_harmless_gobject_warnings_do_not_fill_error_slots(self):
        warning_lines = [
            f"gobject warning: deprecated property {index}"
            for index in range(12)
        ]
        self.assertTrue(all(diagnostic_priority(line) is None for line in warning_lines))

    def test_compiler_errors_rank_ahead_of_build_summaries(self):
        compiler = "lang.strings(9246): error 806: plural tag"
        lines = [
            *[f"gobject warning: deprecated property {index}" for index in range(12)],
            "ninja: error: subcommand failed",
            compiler,
        ]
        candidates = [
            (priority, index, line)
            for index, line in enumerate(lines)
            if (priority := diagnostic_priority(line)) is not None
        ]
        selected = prioritized_diagnostics(candidates)
        self.assertEqual(selected, [compiler, "ninja: error: subcommand failed"])

    def test_failed_build_log_is_sanitized_and_exit_code_is_preserved(self):
        script = Path(__file__).with_name("build_diagnostics.py")
        secret = "private-api-hash"
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "diagnostics" / "build.log"
            environment = os.environ.copy()
            environment["TEST_API_HASH"] = secret
            result = subprocess.run(
                [
                    sys.executable,
                    str(script),
                    "--log-file",
                    str(log),
                    "--",
                    sys.executable,
                    "-c",
                    f"print('src/file.cpp:1: error: broken'); print('{secret}'); raise SystemExit(7)",
                ],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 7)
            self.assertIn("::error::src/file.cpp:1: error: broken", result.stdout)
            self.assertIn("***", log.read_text(encoding="utf-8"))
            self.assertNotIn(secret, log.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
