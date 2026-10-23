"""Local demo adapter until verified Switch integration documentation exists."""


class LocalSwitchMock:
    """Record a mock handoff locally; this class does not connect to Switch."""

    def create_incident_card(self, investigation_id: str, proposal: dict) -> dict:
        return {
            "adapter": "local-mock",
            "live_switch_integration": False,
            "investigation_id": investigation_id,
            "message": proposal["summary"],
            "status": "awaiting_human_review",
        }
