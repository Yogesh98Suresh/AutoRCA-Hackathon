import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from backend import main

class ApiRouteTests(unittest.TestCase):
    def setUp(self):
        main.investigations.clear()

    def test_home_route_reports_running_status(self):
        response = main.home()
        self.assertEqual(response["project"], "AutoRCA")
        self.assertEqual(response["status"], "running")

    def test_health_and_file_listing_routes(self):
        self.assertEqual(main.health(), {"status": "ok", "project": "AutoRCA", "switch_mode": "mock"})
        self.assertIn("sample.log", main.list_log_files()["files"])

    def test_analyze_route_returns_report_for_data_file(self):
        response = main.analyze(main.AnalyzeRequest(filename="sample.log"))

        self.assertTrue(response["success"])
        self.assertEqual(response["report"]["incident_count"], 3)

    def test_analyze_route_rejects_paths_and_missing_files(self):
        with self.assertRaises(HTTPException) as path_error:
            main.analyze(main.AnalyzeRequest(filename="../secret.log"))
        self.assertEqual(path_error.exception.status_code, 400)

        with patch.object(main, "DATA_DIR", main.DATA_DIR / "does-not-exist"):
            with self.assertRaises(HTTPException) as missing_error:
                main.analyze(main.AnalyzeRequest(filename="missing.log"))
        self.assertEqual(missing_error.exception.status_code, 404)

    def test_analysis_rejects_non_log_filename(self):
        with self.assertRaises(HTTPException) as error:
            main.analyze(main.AnalyzeRequest(filename="sample.txt"))
        self.assertEqual(error.exception.status_code, 400)

    def test_analysis_reports_unreadable_log_cleanly(self):
        with patch.object(main, "analyze_logs", side_effect=OSError("permission denied")):
            with self.assertRaises(HTTPException) as error:
                main.analyze(main.AnalyzeRequest(filename="sample.log"))
        self.assertEqual(error.exception.status_code, 400)
        self.assertEqual(error.exception.detail, "Could not read the log file as UTF-8 text.")

    def test_human_review_flow_records_context_and_decision(self):
        request = main.InvestigationRequest(filename="sample.log", service="payment-service")
        created = main.create_investigation(request)
        self.assertEqual(created["decision"]["status"], "pending")
        self.assertFalse(created["switch_handoff"]["live_switch_integration"])

        updated = main.add_investigation_message(
            created["id"], main.MessageRequest(message="The database was recently restarted."),
        )
        self.assertIn("recently restarted", updated["proposal"]["context"])
        decision = main.record_investigation_decision(
            created["id"], main.DecisionRequest(decision="approved", note="Reviewed by operator."),
        )
        self.assertEqual(decision["decision"]["status"], "approved")
        self.assertEqual(decision["decision"]["note"], "Reviewed by operator.")

    def test_modified_plan_requires_steps_and_records_changes(self):
        created = main.create_investigation(
            main.InvestigationRequest(filename="sample.log", service="auth-service"),
        )
        with self.assertRaises(HTTPException) as empty_error:
            main.record_investigation_decision(
                created["id"], main.DecisionRequest(decision="modified"),
            )
        self.assertEqual(empty_error.exception.status_code, 400)

        updated = main.record_investigation_decision(
            created["id"], main.DecisionRequest(decision="modified", modified_steps=["Check identity provider"]),
        )
        self.assertEqual(updated["proposal"]["proposed_steps"], ["Check identity provider"])

    def test_unknown_investigation_returns_not_found(self):
        with self.assertRaises(HTTPException) as error:
            main.add_investigation_message("unknown", main.MessageRequest(message="More context"))
        self.assertEqual(error.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
