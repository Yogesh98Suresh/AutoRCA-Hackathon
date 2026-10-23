"""HTTP-contract tests dispatched in-process through the ASGI application."""

import unittest
from unittest.mock import patch

from backend import log_analyzer, main
from asgi_client import request


class FastAPIHttpContractTests(unittest.TestCase):
    def setUp(self):
        main.investigations.clear()

    def test_health_dashboard_files_and_analysis_http_responses(self):
        status, payload = request(main.app, "GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")

        status, payload = request(main.app, "GET", "/files")
        self.assertEqual(status, 200)
        self.assertIn("sample.log", payload["files"])

        status, payload = request(main.app, "GET", "/dashboard")
        self.assertEqual(status, 200)
        self.assertIn(b"AutoRCA", payload)

        status, payload = request(main.app, "POST", "/analyze", {"filename": "sample.log"})
        self.assertEqual(status, 200)
        self.assertTrue(payload["success"])
        self.assertEqual(payload["report"]["malformed_line_count"], 1)
        self.assertIn("incidents", payload["report"])

    def test_analysis_http_validation_and_errors(self):
        status, payload = request(main.app, "POST", "/analyze", {"filename": ""})
        self.assertEqual(status, 422)
        self.assertIn("detail", payload)

        status, payload = request(main.app, "POST", "/analyze", {"filename": 123})
        self.assertEqual(status, 422)

        status, payload = request(main.app, "POST", "/analyze", {"filename": "../outside.log"})
        self.assertEqual(status, 400)
        self.assertEqual(payload["detail"], "Provide a valid .log filename only.")

        status, payload = request(main.app, "POST", "/analyze", {"filename": "missing.log"})
        self.assertEqual(status, 404)
        self.assertIn("not found", payload["detail"].lower())

        with patch.object(log_analyzer, "MAX_LOG_FILE_BYTES", 1):
            status, payload = request(main.app, "POST", "/analyze", {"filename": "sample.log"})
        self.assertEqual(status, 413)
        self.assertIn("byte limit", payload["detail"])

        with patch.object(main, "analyze_logs", side_effect=RuntimeError("unexpected internal error")):
            status, payload = request(main.app, "POST", "/analyze", {"filename": "sample.log"})
        self.assertEqual(status, 500)

    def test_investigation_http_validation_unknown_id_and_decision_history(self):
        status, payload = request(main.app, "POST", "/investigations", {})
        self.assertEqual(status, 422)
        status, payload = request(
            main.app,
            "POST",
            "/investigations",
            {"filename": "sample.log", "service": ["wrong", "type"]},
        )
        self.assertEqual(status, 422)

        status, payload = request(
            main.app,
            "POST",
            "/investigations",
            {"filename": "sample.log", "service": "payment-service"},
        )
        self.assertEqual(status, 201)
        investigation_id = payload["id"]
        self.assertEqual(payload["decision"]["status"], "pending")
        self.assertEqual(len(payload["decision_history"]), 1)
        self.assertFalse(payload["switch_handoff"]["live_switch_integration"])

        status, payload = request(
            main.app,
            "POST",
            f"/investigations/{investigation_id}/messages",
            {"message": "   "},
        )
        self.assertEqual(status, 422)

        status, payload = request(
            main.app,
            "POST",
            f"/investigations/{investigation_id}/messages",
            {"message": "The database was restarted."},
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["messages"][-1]["content"], "The database was restarted.")
        self.assertEqual(len(payload["decision_history"]), 2)

        status, payload = request(
            main.app,
            "POST",
            f"/investigations/{investigation_id}/decision",
            {"decision": "approve-now"},
        )
        self.assertEqual(status, 400)

        status, payload = request(
            main.app,
            "POST",
            f"/investigations/{investigation_id}/decision",
            {"decision": "approved", "note": "Reviewed"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["decision"]["status"], "approved")
        self.assertEqual([event["status"] for event in payload["decision_history"]], ["pending", "pending", "approved"])

        status, payload = request(
            main.app,
            "POST",
            f"/investigations/{investigation_id}/decision",
            {"decision": "rejected"},
        )
        self.assertEqual(status, 409)
        self.assertIn("cannot change", payload["detail"].lower())

        status, payload = request(
            main.app,
            "POST",
            f"/investigations/{investigation_id}/messages",
            {"message": "More context after approval"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["decision"]["status"], "pending")
        self.assertIn("reopened", payload["decision_history"][-1]["note"])

        status, payload = request(main.app, "POST", "/investigations/unknown/messages", {"message": "Valid"})
        self.assertEqual(status, 404)
        self.assertEqual(payload["detail"], "Investigation not found.")

    def test_modified_steps_are_bounded_and_transition_from_pending(self):
        status, created = request(
            main.app,
            "POST",
            "/investigations",
            {"filename": "sample.log", "service": "auth-service"},
        )
        self.assertEqual(status, 201)
        url = f"/investigations/{created['id']}/decision"

        status, payload = request(
            main.app,
            "POST",
            url,
            {"decision": "modified", "modified_steps": ["   "]},
        )
        self.assertEqual(status, 422)

        status, payload = request(
            main.app,
            "POST",
            url,
            {"decision": "modified", "modified_steps": ["x" * (main.MAX_MODIFIED_STEP_CHARS + 1)]},
        )
        self.assertEqual(status, 422)

        status, payload = request(
            main.app,
            "POST",
            url,
            {"decision": "modified", "modified_steps": ["check"] * (main.MAX_MODIFIED_STEPS + 1)},
        )
        self.assertEqual(status, 422)

        status, payload = request(
            main.app,
            "POST",
            url,
            {"decision": "modified", "modified_steps": [" Check identity provider "]},
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["proposal"]["proposed_steps"], ["Check identity provider"])
        self.assertEqual(payload["decision"]["status"], "modified")

        status, payload = request(
            main.app,
            "POST",
            url,
            {"decision": "approved"},
        )
        self.assertEqual(status, 200)
        self.assertEqual([event["status"] for event in payload["decision_history"]], ["pending", "modified", "approved"])


if __name__ == "__main__":
    unittest.main()
