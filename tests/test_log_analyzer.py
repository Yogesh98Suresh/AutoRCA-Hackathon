import os
import unittest
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from backend import log_analyzer
from backend.log_analyzer import analyze_logs

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_LOG = PROJECT_ROOT / "data" / "sample.log"


class AnalyzeLogsTests(unittest.TestCase):
    def analyze_text(self, text):
        with (
            patch.object(Path, "is_file", return_value=True),
            patch.object(Path, "stat", return_value=SimpleNamespace(st_size=len(text.encode("utf-8")))),
            patch.object(Path, "open", return_value=StringIO(text)),
        ):
            return analyze_logs("in-memory.log")

    def test_sample_log_groups_errors_and_ignores_non_errors(self):
        report = analyze_logs(str(SAMPLE_LOG))
        self.assertEqual(report["total_lines_analyzed"], 10)
        self.assertEqual(report["malformed_line_count"], 1)
        self.assertEqual(report["incident_count"], 3)
        self.assertEqual(report["incidents"][0]["service"], "payment-service")
        self.assertEqual(report["incidents"][0]["error_count"], 3)
        self.assertEqual(report["incidents"][0]["severity"], "HIGH")
        self.assertEqual(report["incidents"][1]["service"], "auth-service")
        self.assertEqual(report["incidents"][1]["errors"][0]["level"], "ERROR")
        self.assertEqual(report["incidents"][1]["severity"], "MEDIUM")

    def test_apache_sample_maps_levels_groups_errors_and_preserves_evidence(self):
        report = analyze_logs(str(PROJECT_ROOT / "data" / "apache_sample.log"))
        self.assertEqual(report["total_lines_analyzed"], 10)
        self.assertEqual(report["malformed_line_count"], 2)
        self.assertEqual(report["parsed_level_counts"], {
            "CRITICAL": 3, "ERROR": 2, "INFO": 2, "WARN": 1,
        })
        self.assertEqual(report["incident_count"], 1)
        apache = report["incidents"][0]
        self.assertEqual(apache["service"], "apache")
        self.assertEqual(apache["severity"], "HIGH")
        self.assertEqual(apache["error_count"], 5)
        self.assertEqual(apache["errors"][0], {
            "timestamp": "Mon Jan 05 12:00:03 2026",
            "level": "ERROR",
            "message": "mod_proxy: database connection timed out",
        })
        self.assertEqual(apache["errors"][-1]["level"], "CRITICAL")
        self.assertIn("hypothesis", apache["possible_causes"][0]["basis"].lower())

    def test_apache_levels_are_mapped_and_invalid_entries_are_malformed(self):
        report = self.analyze_text(
            "[Mon Jan 05 12:00:00 2026] [notice] Started\n"
            "[Mon Jan 05 12:00:01 2026] [info] Ready\n"
            "[Mon Jan 05 12:00:02 2026] [warn] Low disk warning\n"
            "[Mon Jan 05 12:00:03 2026] [crit] Disk full\n"
            "[Mon Jan 05 12:00:04 2026] [alert] Disk full\n"
            "[Mon Jan 05 12:00:05 2026] [emerg] Disk full\n"
            "[Not a date] [error] Invalid date\n"
            "[Mon Jan 05 12:00:06 2026] [unknown] Invalid severity\n"
        )
        self.assertEqual(report["parsed_level_counts"], {
            "CRITICAL": 3, "INFO": 2, "WARN": 1,
        })
        self.assertEqual(report["malformed_line_count"], 2)
        self.assertEqual(report["incidents"][0]["errors"][0]["level"], "CRITICAL")

    def test_one_critical_entry_is_high_severity(self):
        report = self.analyze_text(
            "2026-11-01 10:00:01 CRITICAL billing Payment system unavailable\n"
        )
        self.assertEqual(report["incidents"][0]["severity"], "HIGH")

    def test_two_error_entries_are_medium_severity(self):
        report = self.analyze_text(
            "2026-11-01 10:00:01 ERROR billing First failure\n"
            "2026-11-01 10:00:02 ERROR billing Second failure\n"
        )
        self.assertEqual(report["incidents"][0]["severity"], "MEDIUM")

    def test_three_error_entries_are_high_severity(self):
        report = self.analyze_text(
            "2026-11-01 10:00:01 ERROR billing First failure\n"
            "2026-11-01 10:00:02 ERROR billing Second failure\n"
            "2026-11-01 10:00:03 ERROR billing Third failure\n"
        )
        self.assertEqual(report["incidents"][0]["severity"], "HIGH")

    def test_malformed_and_blank_lines_are_reported_without_breaking_analysis(self):
        report = self.analyze_text(
            "\n"
            "2026-11-01T10:00:01.123Z ERROR api Request timed out\n"
            "not a valid log line\n"
            "2026-11-01 10:00:03 INFO api Request completed\n"
        )
        self.assertEqual(report["total_lines_analyzed"], 3)
        self.assertEqual(report["malformed_line_count"], 1)
        self.assertEqual(report["malformed_lines"][0]["line_number"], 3)
        self.assertEqual(report["incident_count"], 1)
        self.assertEqual(report["incidents"][0]["errors"][0]["timestamp"], "2026-11-01T10:00:01.123Z")

    def test_valid_timezone_timestamp_and_impossible_datetime(self):
        report = self.analyze_text(
            "2026-11-01T10:00:01.125+05:30 ERROR api Database unavailable\n"
            "2026-99-40 25:61:61 ERROR api Authentication failed\n"
        )
        self.assertEqual(report["total_lines_analyzed"], 2)
        self.assertEqual(report["malformed_line_count"], 1)
        self.assertEqual(report["malformed_lines"][0]["line_number"], 2)
        self.assertEqual(report["incidents"][0]["error_count"], 1)
        self.assertEqual(report["incidents"][0]["errors"][0]["timestamp"], "2026-11-01T10:00:01.125+05:30")

    def test_empty_or_only_blank_log_has_no_incidents(self):
        report = self.analyze_text("\n   \n\t\n")
        self.assertEqual(report["total_lines_analyzed"], 0)
        self.assertEqual(report["malformed_line_count"], 0)
        self.assertEqual(report["incidents"], [])

    def test_mixed_signals_return_multiple_causes_with_specific_evidence(self):
        report = self.analyze_text(
            "2026-11-01 10:00:01 ERROR store Database connection refused\n"
            "2026-11-01 10:00:02 ERROR store Dependency request timed out\n"
        )
        causes = report["incidents"][0]["possible_causes"]
        self.assertEqual(len(causes), 3)
        self.assertIn("database", causes[0]["cause"].lower())
        self.assertEqual(causes[0]["evidence"][0]["timestamp"], "2026-11-01 10:00:01")
        self.assertTrue(causes[0]["recommendation"])
        self.assertIn("timeout", causes[1]["cause"].lower())
        self.assertIn("hypothesis", causes[0]["basis"].lower())

    def test_cause_rules_cover_auth_memory_network_and_unknown(self):
        report = self.analyze_text(
            "2026-11-01 10:00:01 ERROR auth Authentication token expired\n"
            "2026-11-01 10:00:02 ERROR memory Worker out of memory\n"
            "2026-11-01 10:00:03 ERROR network Host unreachable\n"
            "2026-11-01 10:00:04 ERROR unknown Operation failed\n"
        )
        by_service = {item["service"]: item["possible_causes"][0] for item in report["incidents"]}
        self.assertIn("authentication", by_service["auth"]["cause"].lower())
        self.assertIn("memory", by_service["memory"]["cause"].lower())
        self.assertIn("network", by_service["network"]["cause"].lower())
        self.assertIn("unknown", by_service["unknown"]["cause"].lower())
        self.assertTrue(all(cause["recommendation"] for cause in by_service.values()))

    def test_negated_causes_and_substrings_do_not_trigger_rules(self):
        report = self.analyze_text(
            "2026-11-01 10:00:01 ERROR api Database is not involved in the issue\n"
            "2026-11-01 10:00:02 ERROR api No database issue was found\n"
            "2026-11-01 10:00:03 ERROR api Blooming logs are unrelated\n"
        )
        causes = report["incidents"][0]["possible_causes"]
        self.assertEqual([cause["cause"] for cause in causes], ["Unknown or ambiguous cause"])

    def test_file_size_limit_raises_a_specific_error(self):
        with patch.object(log_analyzer, "MAX_LOG_FILE_BYTES", 4):
            with self.assertRaises(log_analyzer.LogFileTooLargeError):
                self.analyze_text("this input is too large\n")

    def test_limit_environment_settings_must_be_positive_integers(self):
        with patch.dict(os.environ, {"AUTORCA_TEST_LIMIT": "2048"}):
            self.assertEqual(log_analyzer._positive_setting("AUTORCA_TEST_LIMIT", 10), 2048)
        for invalid in ("not-a-number", "0", "-1"):
            with self.subTest(value=invalid), patch.dict(os.environ, {"AUTORCA_TEST_LIMIT": invalid}):
                with self.assertRaises(RuntimeError):
                    log_analyzer._positive_setting("AUTORCA_TEST_LIMIT", 10)

    def test_overlong_line_is_counted_as_malformed_with_bounded_excerpt(self):
        with patch.object(log_analyzer, "MAX_LOG_LINE_CHARS", 10):
            report = self.analyze_text("x" * 200 + "\n")
        self.assertEqual(report["total_lines_analyzed"], 1)
        self.assertEqual(report["malformed_line_count"], 1)
        self.assertTrue(report["malformed_lines"][0]["truncated"])
        self.assertLessEqual(len(report["malformed_lines"][0]["content"]), 500)

    def test_malformed_example_count_is_bounded_but_total_is_preserved(self):
        text = "bad one\nbad two\nbad three\n"
        with patch.object(log_analyzer, "MAX_MALFORMED_EXAMPLES", 2):
            report = self.analyze_text(text)
        self.assertEqual(report["malformed_line_count"], 3)
        self.assertEqual(len(report["malformed_lines"]), 2)
        self.assertTrue(report["malformed_lines_truncated"])

    def test_same_error_count_sorts_by_service_name(self):
        report = self.analyze_text(
            "2026-11-01 10:00:01 ERROR zeta Request failed\n"
            "2026-11-01 10:00:02 ERROR alpha Request failed\n"
        )
        self.assertEqual([item["service"] for item in report["incidents"]], ["alpha", "zeta"])

    def test_missing_log_raises_file_not_found(self):
        missing = PROJECT_ROOT / "data" / "missing.log"
        with self.assertRaises(FileNotFoundError):
            analyze_logs(str(missing))


if __name__ == "__main__":
    unittest.main()
