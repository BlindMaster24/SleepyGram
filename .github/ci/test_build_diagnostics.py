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


if __name__ == "__main__":
    unittest.main()
