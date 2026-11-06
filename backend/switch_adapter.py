"""Mock/live adapter boundary for Switch handoffs."""

from abc import ABC, abstractmethod
import re
import uuid

from backend.switch_config import SwitchSettings, redact_sensitive_text
from backend.switch_outbox import SwitchOutbox
from backend.switch_client import SwitchHTTPClient, SwitchTransportError


class SwitchAdapter(ABC):
    @abstractmethod
    def create_incident_card(self, investigation_id: str, proposal: dict) -> dict:
        """Return a local handoff card without exposing credentials."""

    @abstractmethod
    def submit_approved_investigation(self, investigation_id: str, incident: dict,
                                      handoff_kind: str = "approved_plan") -> dict:
        """Share only a human-approved, minimized incident request."""

    def list_responses(self, investigation_id: str) -> list[dict]:
        return []


class LocalSwitchMock(SwitchAdapter):
    """Record the existing local mock handoff; it does not connect to Switch."""

    def create_incident_card(self, investigation_id: str, proposal: dict) -> dict:
        return {
            "adapter": "local-mock",
            "live_switch_integration": False,
            "live_switch_configured": False,
            "investigation_id": investigation_id,
            "message": proposal["summary"],
            "status": "awaiting_human_review",
        }

    def submit_approved_investigation(self, investigation_id: str, incident: dict,
                                      handoff_kind: str = "approved_plan") -> dict:
        return {"status": "mock", "mode": "mock", "message": "Local mock only; nothing was sent to Switch."}


class LiveSwitchAdapter(SwitchAdapter):
    def __init__(self, settings: SwitchSettings, http_client=None, outbox=None):
        self.settings = settings
        self.http = http_client or SwitchHTTPClient(settings)
        self.outbox = outbox or SwitchOutbox(settings.outbox_path)
        self.outbox.recover_inflight()

    def create_incident_card(self, investigation_id: str, proposal: dict) -> dict:
        return {
            "adapter": "switch-agent-protocol",
            "live_switch_integration": False,
            "live_switch_configured": True,
            "investigation_id": investigation_id,
            "message": "Switch handoff waits for human approval.",
            "status": "awaiting_human_review",
        }

    @staticmethod
    def build_content(investigation_id: str, incident: dict, target_agent: str = "",
                      agent_name: str = "autorca") -> str:
        try:
            canonical_id = str(uuid.UUID(investigation_id))
        except (ValueError, TypeError, AttributeError):
            raise ValueError("Invalid investigation identifier.") from None
        service = str(incident.get("service", ""))[:80]
        if not service or not re.fullmatch(r"[A-Za-z0-9_.:/-]+", service):
            service = "[REDACTED SERVICE]"
        severity = str(incident.get("severity", "UNKNOWN")).upper()
        if severity not in {"HIGH", "MEDIUM", "LOW", "UNKNOWN"}:
            severity = "UNKNOWN"
        target = ""
        if target_agent:
            if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", target_agent):
                raise ValueError("Invalid Switch target agent name.")
            target = f"@{target_agent} "
        # Deliberately omit proposal/context/errors/evidence and all raw log content.
        return (f"{target}AutoRCA investigation request\n"
                f"Investigation: {canonical_id}\nService: {service}\nSeverity: {severity}\n"
                f"Request: Review this incident and reply by mentioning @{agent_name}; "
                f"include Investigation: {canonical_id} and recommendations for human review.\n"
                "Do not execute remediation or production changes.")

    def submit_approved_investigation(self, investigation_id: str, incident: dict,
                                      handoff_kind: str = "approved_plan") -> dict:
        content = self.build_content(investigation_id, incident, self.settings.target_agent,
                                     self.settings.agent_name)
        delivery = self.outbox.enqueue(investigation_id, self.settings.room_id, content, handoff_kind)
        if delivery["status"] != "pending":
            return self.public_delivery(delivery)
        return self.deliver_pending(delivery["id"])

    def deliver_pending(self, delivery_id: int) -> dict:
        claimed = self.outbox.claim(delivery_id)
        if claimed is None:
            return {"status": "pending", "error": "Another sender is processing this handoff."}
        try:
            # Per protocol, any 2xx is success; do not depend on an undocumented body schema.
            self.http.post_message(claimed["room_id"], claimed["content"])
            delivery = self.outbox.set_delivery(claimed["id"], "sent")
        except SwitchTransportError:
            delivery = self.outbox.set_delivery(claimed["id"], "unknown",
                                                "Transport failed; delivery outcome may be ambiguous. Reconcile before retrying.")
        except Exception as exc:
            status = "failed"
            if getattr(exc, "status", None) is None:
                status = "unknown"
            delivery = self.outbox.set_delivery(claimed["id"], status, "Switch handoff failed; inspect server-side diagnostics.")
        return self.public_delivery(delivery)

    def retry_pending(self, limit: int = 100) -> None:
        """Resume only never-attempted outbox entries; ambiguous sends stay unknown."""
        for delivery in self.outbox.list_pending(limit=limit):
            self.deliver_pending(delivery["id"])

    @staticmethod
    def public_delivery(delivery: dict | None) -> dict:
        if not delivery:
            return {"status": "pending", "error": "Delivery record is unavailable."}
        return {"status": delivery["status"], "error": delivery.get("error", ""),
                "updated_at": delivery.get("updated_at")}

    def handle_event(self, data: dict, payload: dict) -> bool:
        if data.get("room_id") != self.settings.room_id or payload.get("addressed") is not True:
            return False
        message_id = payload.get("message_id")
        body = payload.get("body")
        seq = data.get("sequence")
        if not isinstance(message_id, str) or not isinstance(body, str) or len(body) > 8000 or not isinstance(seq, int):
            return False
        match = re.search(r"(?im)^Investigation:\s*([0-9a-f-]{36})\s*$", body)
        if not match:
            return False
        try:
            investigation_id = str(uuid.UUID(match.group(1)))
        except ValueError:
            return False
        safe_body = redact_sensitive_text(body, limit=4000)
        return self.outbox.save_inbound(
            sequence=seq, message_id=message_id, investigation_id=investigation_id,
            room_id=data["room_id"], sender=str(payload.get("sender", ""))[:255],
            thread_id=payload.get("thread_id"), content=safe_body,
        )

    def list_responses(self, investigation_id: str) -> list[dict]:
        return self.outbox.list_inbound(investigation_id)

    def recover_gap(self, room_id: str):
        # The live operation schema is discovered before read_context arguments are sent.
        # Reading history does not automatically replay/act on missed content; review remains required.
        return self.http.read_room_context(room_id)

    def delivery_status(self, investigation_id: str) -> dict:
        delivery = self.outbox.get_latest_delivery(investigation_id)
        public = self.public_delivery(delivery) if delivery else {"status": "not_requested", "error": ""}
        public["recovery_required"] = bool(self.outbox.get_gap_state(self.settings.connection_id))
        return public


def create_switch_adapter(settings: SwitchSettings | None = None) -> SwitchAdapter:
    settings = settings or SwitchSettings.from_env()
    if settings.mode == "live":
        return LiveSwitchAdapter(settings)
    return LocalSwitchMock()
