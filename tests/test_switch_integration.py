import json
import os
import unittest
from io import StringIO
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from backend.switch_adapter import LiveSwitchAdapter, LocalSwitchMock
from backend import main
from backend.switch_client import (
    ConnectionState,
    SwitchEventClient,
    SwitchHTTPClient,
    SwitchHTTPError,
    SwitchTransportError,
)
from backend.switch_config import SwitchSettings, redact_sensitive_text
from backend.switch_outbox import SwitchOutbox


@contextmanager
def test_db(label):
    path = Path(__file__).resolve().parent / f"switch-test-{label}.sqlite3"
    try:
        yield path
    finally:
        for candidate in (path, Path(str(path) + "-wal"), Path(str(path) + "-shm")):
            if candidate.exists():
                candidate.unlink()


def live_settings(path, **overrides):
    path = Path(path)
    values = {
        "mode": "live",
        "agent_base_url": "https://switch.example.test",
        "agent_id": "agent-id",
        "agent_api_key": "server-secret",
        "room_id": "room-id",
        "connection_id": "connection-id",
        "target_agent": "responder",
        "outbox_path": path if path.suffix == ".sqlite3" else path / "outbox.sqlite3",
    }
    values.update(overrides)
    return SwitchSettings(**values)


class FakeResponse:
    def __init__(self, body=b'{"ok":true}'):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, _limit=-1):
        return self.body


class CapturingOpener:
    def __init__(self, response=None, error=None):
        self.response = response or FakeResponse()
        self.error = error
        self.request = None
        self.timeout = None

    def __call__(self, request, timeout):
        self.request, self.timeout = request, timeout
        if self.error:
            raise self.error
        return self.response


class SequenceOpener:
    def __init__(self, bodies):
        self.bodies = list(bodies)
        self.requests = []

    def __call__(self, request, timeout):
        self.requests.append(request)
        return FakeResponse(self.bodies.pop(0))


class FakeWebSocket:
    def __init__(self, frames):
        self.frames = list(frames)
        self.sent = []
        self.closed = False

    def recv_json(self):
        if not self.frames:
            raise SwitchTransportError("test disconnect")
        return self.frames.pop(0)

    def send_json(self, value):
        self.sent.append(value)

    def close(self):
        self.closed = True


class SwitchConfigTests(unittest.TestCase):
    def test_default_mode_is_mock_and_needs_no_switch_credentials(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(SwitchSettings.from_env().mode, "mock")

    def test_live_mode_requires_complete_configuration_and_secure_url(self):
        with patch.dict(os.environ, {"AUTORCA_SWITCH_MODE": "live"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "requires"):
                SwitchSettings.from_env()
        env = {
            "AUTORCA_SWITCH_MODE": "live",
            "AUTORCA_SWITCH_AGENT_BASE_URL": "http://switch.example.test",
            "AUTORCA_SWITCH_AGENT_ID": "agent",
            "AUTORCA_SWITCH_AGENT_API_KEY": "secret",
            "AUTORCA_SWITCH_ROOM_ID": "room",
            "AUTORCA_SWITCH_CONNECTION_ID": "conn",
        }
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaisesRegex(RuntimeError, "HTTPS"):
                SwitchSettings.from_env()

    def test_timeout_must_be_finite(self):
        for value in ("nan", "inf", "-inf"):
            with self.subTest(value=value), patch.dict(os.environ, {"AUTORCA_SWITCH_TIMEOUT_SECONDS": value}, clear=True):
                with self.assertRaisesRegex(RuntimeError, "positive"):
                    SwitchSettings.from_env()

    def test_health_labels_live_configuration_as_unverified(self):
        with test_db("health") as db_path, patch.object(main, "switch_settings", live_settings(db_path)):
            self.assertEqual(main.health()["switch_mode"], "live_configured_unverified")

    def test_secret_and_contact_redaction(self):
        value = redact_sensitive_text("Bearer abc.def email me@corp.test call +1 (555) 123-4567 api_key=XYZ")
        self.assertNotIn("abc.def", value)
        self.assertNotIn("me@corp.test", value)
        self.assertNotIn("555", value)
        self.assertNotIn("XYZ", value)


class SwitchHTTPProtocolTests(unittest.TestCase):
    def test_http_client_rejects_insecure_remote_registration_endpoint_before_sending_key(self):
        for url in ("http://switch.example.test", "https://user:pass@switch.example.test", "https://switch.example.test/?x=1"):
            with self.subTest(url=url), test_db("bad-url") as db_path:
                settings = live_settings(db_path, agent_base_url=url)
                opener = CapturingOpener()
                with self.assertRaises(RuntimeError):
                    SwitchHTTPClient(settings, opener=opener)
                self.assertIsNone(opener.request)

    def test_registration_uses_documented_payload_and_returns_only_documented_fields(self):
        with test_db("shared") as db_path:
            opener = CapturingOpener(FakeResponse(b'{"id":"a1","api_key":"one-time"}'))
            client = SwitchHTTPClient(live_settings(db_path), opener=opener)
            result = client.register_agent("registration-secret", {
                "connection_model": "always_on", "message_exchange": True,
                "pre_invocation_mediation": [], "post_invocation_mediation": [], "event_reporting": [],
            }, name="autorca", description="test", connector_type="autorca")
            self.assertEqual(result, {"id": "a1", "api_key": "one-time"})
            self.assertEqual(opener.request.method, "POST")
            self.assertTrue(opener.request.full_url.endswith("/agents"))
            self.assertEqual(opener.request.get_header("Authorization"), "Bearer registration-secret")
            payload = json.loads(opener.request.data)
            self.assertEqual(payload["name"], "autorca")
            self.assertEqual(payload["integration_profile"]["event_reporting"], [])

    def test_post_message_uses_documented_route_and_body_without_response_assumptions(self):
        with test_db("shared") as db_path:
            opener = CapturingOpener(FakeResponse(b"not-a-documented-response-schema"))
            client = SwitchHTTPClient(live_settings(db_path), opener=opener)
            self.assertIsNone(client.post_message("room-id", "safe request"))
            self.assertEqual(opener.request.method, "POST")
            self.assertTrue(opener.request.full_url.endswith("/agents/agent-id/message"))
            self.assertEqual(opener.request.get_header("Authorization"), "Bearer server-secret")
            self.assertEqual(json.loads(opener.request.data), {"room_id": "room-id", "content": "safe request"})

    def test_operation_invocation_uses_unwrapped_arguments_and_connection_header(self):
        with test_db("shared") as db_path:
            opener = CapturingOpener(FakeResponse(b'{"result":{"ok":true}}'))
            client = SwitchHTTPClient(live_settings(db_path), opener=opener)
            result = client.invoke_operation("list_participants", {"room_id": "room-id"}, "conn-id")
            self.assertEqual(result, {"result": {"ok": True}})
            self.assertEqual(opener.request.get_header("X-switch-connection-id"), "conn-id")
            self.assertEqual(json.loads(opener.request.data), {"room_id": "room-id"})

    def test_gap_history_read_uses_discovered_operation_schema(self):
        with test_db("read-history") as db_path:
            opener = SequenceOpener([
                b'{"operations":{"read_context":{"input_schema":{"type":"object","properties":{"room_id":{"type":"string"}},"required":[]}}}}',
                b'{"result":{"threads":[]}}',
            ])
            client = SwitchHTTPClient(live_settings(db_path), opener=opener)
            result = client.read_room_context("room-id")
            self.assertEqual(result, {"result": {"threads": []}})
            self.assertEqual(opener.requests[0].method, "GET")
            self.assertTrue(opener.requests[1].full_url.endswith("/ops/read_context"))
            self.assertEqual(json.loads(opener.requests[1].data), {"room_id": "room-id"})

    def test_http_error_is_definitive_but_network_error_is_ambiguous(self):
        with test_db("shared") as db_path:
            http = SwitchHTTPClient(live_settings(db_path), opener=CapturingOpener(error=SwitchHTTPError(403, "denied")))
            with self.assertRaises(SwitchHTTPError):
                http.post_message("room-id", "body")
            network = SwitchHTTPClient(live_settings(db_path), opener=CapturingOpener(error=OSError("timeout")))
            with self.assertRaises(SwitchTransportError):
                network.post_message("room-id", "body")


class SwitchRegistrationTests(unittest.TestCase):
    def test_registration_command_never_prints_returned_api_key(self):
        from backend import switch_register

        output = StringIO()
        env = {
            "AUTORCA_SWITCH_AGENT_BASE_URL": "https://switch.example.test",
            "AUTORCA_SWITCH_REGISTRATION_API_KEY": "registration-secret",
        }
        with (patch.dict(os.environ, env, clear=True),
              patch.object(switch_register.platform, "system", return_value="Windows"),
              patch.object(switch_register.SwitchHTTPClient, "register_agent", return_value={"id": "agent-1", "api_key": "returned-secret"}),
              patch.object(switch_register, "store_windows_credential") as store,
              patch("sys.stdout", output)):
            self.assertEqual(switch_register.main(), 0)
        self.assertIn("agent-1", output.getvalue())
        self.assertNotIn("returned-secret", output.getvalue())
        store.assert_called_once_with("AutoRCA/Switch/agent-1", "agent-1", "returned-secret")


class SwitchOutboxAndAdapterTests(unittest.TestCase):
    def test_mock_adapter_remains_offline(self):
        adapter = LocalSwitchMock()
        card = adapter.create_incident_card("id", {"summary": "local"})
        self.assertFalse(card["live_switch_integration"])
        self.assertEqual(card["adapter"], "local-mock")

    def test_outbound_content_contains_only_minimized_redacted_fields(self):
        import uuid
        identifier = str(uuid.uuid4())
        content = LiveSwitchAdapter.build_content(identifier, {
            "service": "payments", "severity": "HIGH",
            "errors": [{"message": "customer@example.com Bearer abc"}],
        }, "responder")
        self.assertIn("@responder", content)
        self.assertIn(identifier, content)
        self.assertIn("Severity: HIGH", content)
        self.assertIn(f"mentioning @autorca; include Investigation: {identifier}", content)
        self.assertNotIn("customer@example.com", content)
        self.assertNotIn("Bearer abc", content)
        self.assertNotIn("errors", content)
        with self.assertRaises(ValueError):
            LiveSwitchAdapter.build_content(identifier, {"service": "payments"}, "bad @mention")

    def test_outbox_dedup_delivery_states_and_inflight_recovery(self):
        with test_db("shared") as db_path:
            outbox = SwitchOutbox(db_path)
            first = outbox.enqueue("investigation", "room", "content")
            duplicate = outbox.enqueue("investigation", "room", "different")
            self.assertEqual(first["id"], duplicate["id"])
            self.assertEqual(duplicate["content"], "content")
            claimed = outbox.claim(first["id"])
            self.assertEqual(claimed["status"], "sending")
            self.assertEqual(outbox.recover_inflight(), 1)
            self.assertEqual(outbox.get_delivery("investigation")["status"], "unknown")
            self.assertIsNone(outbox.claim(first["id"]))

    def test_live_handoff_sent_failed_unknown_and_no_duplicate_post(self):
        with test_db("shared") as db_path:
            class Success:
                calls = 0
                def post_message(self, *_):
                    self.calls += 1
                    return {"uninspected": "response"}

            http = Success()
            adapter = LiveSwitchAdapter(live_settings(db_path), http_client=http)
            import uuid
            identifier = str(uuid.uuid4())
            incident = {"service": "payments", "severity": "HIGH"}
            self.assertEqual(adapter.submit_approved_investigation(identifier, incident)["status"], "sent")
            self.assertEqual(adapter.submit_approved_investigation(identifier, incident)["status"], "sent")
            self.assertEqual(http.calls, 1)

            class Rejected:
                def post_message(self, *_):
                    raise SwitchHTTPError(403, "forbidden")
            adapter = LiveSwitchAdapter(live_settings(db_path), http_client=Rejected())
            failed = adapter.submit_approved_investigation(str(uuid.uuid4()), incident)
            self.assertEqual(failed["status"], "failed")

            class Ambiguous:
                def post_message(self, *_):
                    raise SwitchTransportError("timeout")
            adapter = LiveSwitchAdapter(live_settings(db_path), http_client=Ambiguous())
            unknown = adapter.submit_approved_investigation(str(uuid.uuid4()), incident)
            self.assertEqual(unknown["status"], "unknown")

    def test_restart_resumes_only_never_attempted_pending_outbox_items(self):
        with test_db("resume-pending") as db_path:
            class Success:
                def __init__(self):
                    self.calls = 0
                def post_message(self, *_):
                    self.calls += 1

            http = Success()
            settings = live_settings(db_path)
            outbox = SwitchOutbox(settings.outbox_path)
            pending = outbox.enqueue("investigation-1", "room-id", "safe content")
            ambiguous = outbox.enqueue("investigation-2", "room-id", "already attempted")
            outbox.claim(ambiguous["id"])
            adapter = LiveSwitchAdapter(settings, http_client=http, outbox=outbox)
            adapter.retry_pending()
            self.assertEqual(outbox.get_delivery("investigation-1")["status"], "sent")
            self.assertEqual(outbox.get_delivery("investigation-2")["status"], "unknown")
            self.assertEqual(http.calls, 1)

    def test_delivery_status_reports_no_delivery_as_not_requested(self):
        with test_db("not-requested") as db_path:
            settings = live_settings(db_path)
            adapter = LiveSwitchAdapter(settings, http_client=object())
            self.assertEqual(adapter.delivery_status("unshared")['status'], "not_requested")

    def test_explicit_switch_consent_is_required_for_live_handoff(self):
        from unittest.mock import patch

        with test_db("consent") as db_path:
            class Success:
                calls = 0
                def post_message(self, *_):
                    self.calls += 1
                    return None

            http = Success()
            adapter = LiveSwitchAdapter(live_settings(db_path), http_client=http)
            with patch.object(main, "switch_adapter", adapter):
                private_record = main.create_investigation(
                    main.InvestigationRequest(filename="sample.log", service="payment-service"),
                )
                response = main.record_investigation_decision(
                    private_record["id"], main.DecisionRequest(decision="approved"),
                )
                self.assertEqual(response["switch_delivery"]["status"], "not_shared")
                self.assertEqual(http.calls, 0)
                self.assertNotIn("server-secret", repr(response))

                shared_record = main.create_investigation(
                    main.InvestigationRequest(filename="sample.log", service="auth-service"),
                )
                response = main.record_investigation_decision(
                    shared_record["id"], main.DecisionRequest(decision="approved", share_with_switch=True),
                )
                self.assertEqual(response["switch_delivery"]["status"], "sent")
                self.assertEqual(http.calls, 1)
                main.investigations.pop(private_record["id"], None)
                main.investigations.pop(shared_record["id"], None)

    def test_inbound_duplicate_message_is_stored_once_and_redacted(self):
        with test_db("shared") as db_path:
            import uuid
            identifier = str(uuid.uuid4())
            adapter = LiveSwitchAdapter(live_settings(db_path), http_client=object())
            data = {"room_id": "room-id", "sequence": 4}
            payload = {"addressed": True, "message_id": "msg-1", "sender": "agent",
                       "thread_id": None, "body": f"Investigation: {identifier}\nContact me@corp.test"}
            self.assertTrue(adapter.handle_event(data, payload))
            self.assertFalse(adapter.handle_event(data, payload))
            messages = adapter.list_responses(identifier)
            self.assertEqual(len(messages), 1)
            self.assertNotIn("me@corp.test", messages[0]["content"])
            self.assertFalse(adapter.handle_event({**data, "room_id": "other"}, payload))
            self.assertFalse(adapter.handle_event(data, {**payload, "addressed": False}))


class SwitchWebSocketTests(unittest.TestCase):
    def test_frames_ping_cursor_duplicate_and_gap_recovery(self):
        with test_db("shared") as db_path:
            settings = live_settings(db_path)
            outbox = SwitchOutbox(settings.outbox_path)
            events = []
            client = SwitchEventClient(settings, outbox, lambda data, payload: events.append((data, payload)))
            state = {"event": "connection_state", "data": {"cursor": 10, "generation": 3}}
            self.assertEqual(client.handle_frame(state)["kind"], "state")
            ping = client.handle_frame({"event": "ping"})
            self.assertEqual(ping["pong"], {"type": "pong", "cursor": 10})
            message = {"event": "message", "id": 11, "data": {
                "type": "message", "room_id": "room-id", "sequence": 11,
                "payload": {"addressed": True, "message_id": "m", "body": "hello"},
            }}
            self.assertEqual(client.handle_frame(message)["kind"], "event")
            self.assertEqual(client.handle_frame(message)["kind"], "duplicate")
            self.assertEqual(len(events), 1)
            gap = client.handle_frame({"event": "gap", "data": {"resumed_at": 17}})
            self.assertFalse(gap["re_read_history"])
            self.assertTrue(gap["operator_review_required"])
            self.assertEqual(client.state.cursor, 17)
            self.assertEqual(outbox.get_stream_state(settings.connection_id), {"cursor": 17, "generation": 3})
            self.assertEqual(outbox.get_gap_state(settings.connection_id)["history_rechecked"], 0)

    def test_reconnect_url_uses_saved_cursor_and_expected_generation(self):
        with test_db("shared") as db_path:
            settings = live_settings(db_path)
            outbox = SwitchOutbox(settings.outbox_path)
            outbox.save_stream_state(settings.connection_id, 42, 7)
            client = SwitchEventClient(settings, outbox, lambda *_: None)
            url = client.connection_url()
            self.assertIn("start_from=42", url)
            self.assertIn("expected_generation=7", url)
            self.assertIn("connection_id=connection-id", url)

    def test_run_once_answers_ping_and_closes_connection(self):
        with test_db("shared") as db_path:
            settings = live_settings(db_path)
            frames = [
                {"event": "connection_state", "data": {"cursor": 2, "generation": 1}},
                {"event": "ping"},
            ]
            connection = FakeWebSocket(frames)
            client = SwitchEventClient(settings, SwitchOutbox(settings.outbox_path), lambda *_: None,
                                       connector=lambda *_: connection)
            with self.assertRaises(SwitchTransportError):
                client.run_once()
            self.assertEqual(connection.sent, [{"type": "pong", "cursor": 2}])
            self.assertTrue(connection.closed)

    def test_closed_eviction_is_not_retried_automatically(self):
        with test_db("eviction") as db_path:
            settings = live_settings(db_path)
            client = SwitchEventClient(settings, SwitchOutbox(settings.outbox_path), lambda *_: None)
            self.assertFalse(client.handle_frame({"event": "evicted", "data": {"code": "closed"}})["reconnect"])
            self.assertFalse(client.handle_frame({"event": "evicted", "data": {"code": "taken_over"}})["reconnect"])
            self.assertTrue(client.handle_frame({"event": "evicted", "data": {"code": "heartbeat_lapsed"}})["reconnect"])


if __name__ == "__main__":
    unittest.main()
