import unittest

from preflight_lang import plural_key_errors


class PluralPreflightTests(unittest.TestCase):
    def test_accepts_complete_plural_forms(self):
        lines = [
            '"lng_count#one" = "{count} item";',
            '"lng_count#other" = "{count} items";',
        ]
        self.assertEqual(plural_key_errors(lines), [])

    def test_reports_missing_other_with_source_line(self):
        lines = [
            '"lng_title" = "Title";',
            '"lng_count#one" = "{count} item";',
            '"lng_count#few" = "{count} items";',
        ]
        self.assertEqual(plural_key_errors(lines), [(
            2,
            "lng_count",
            "plural variants #few, #one are missing #other",
        )])

    def test_reports_the_unpluralized_count_placeholder_regression(self):
        lines = [
            '"ayu_BulkDownloadAction" = '
            '"Save selected attachments: {count}";'
        ]
        self.assertEqual(plural_key_errors(lines), [(
            1,
            "ayu_BulkDownloadAction",
            "untagged {count} placeholder requires plural forms",
        )])

    def test_ignores_nonplural_hash_suffix(self):
        lines = ['"lng_count#compact" = "Compact";']
        self.assertEqual(plural_key_errors(lines), [])


if __name__ == "__main__":
    unittest.main()
