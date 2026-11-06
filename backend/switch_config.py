"""Server-only Switch configuration. Values are read from the process environment."""

from dataclasses import dataclass
import math
import os
from pathlib import Path
import re
from urllib.parse import urlsplit


PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class SwitchSettings:
    mode: str = "mock"
    agent_base_url: str = ""
    agent_id: str = ""
    agent_api_key: str = ""
    room_id: str = ""
    connection_id: str = ""
    target_agent: str = ""
    agent_name: str = "autorca"
    outbox_path: Path = PROJECT_ROOT / "data" / "autorca_switch.sqlite3"
    request_timeout_seconds: float = 5.0

    @classmethod
    def from_env(cls) -> "SwitchSettings":
        mode = os.getenv("AUTORCA_SWITCH_MODE", "mock").strip().casefold()
        if mode not in {"mock", "live"}:
            raise RuntimeError("AUTORCA_SWITCH_MODE must be 'mock' or 'live'.")
        timeout_text = os.getenv("AUTORCA_SWITCH_TIMEOUT_SECONDS", "5")
        try:
            timeout = float(timeout_text)
        except ValueError as exc:
            raise RuntimeError("AUTORCA_SWITCH_TIMEOUT_SECONDS must be positive.") from exc
        if not math.isfinite(timeout) or timeout <= 0:
            raise RuntimeError("AUTORCA_SWITCH_TIMEOUT_SECONDS must be positive.")
        raw_path = os.getenv("AUTORCA_SWITCH_OUTBOX_PATH", str(cls.outbox_path))
        settings = cls(
            mode=mode,
            agent_base_url=os.getenv("AUTORCA_SWITCH_AGENT_BASE_URL", "").strip().rstrip("/"),
            agent_id=os.getenv("AUTORCA_SWITCH_AGENT_ID", "").strip(),
            agent_api_key=os.getenv("AUTORCA_SWITCH_AGENT_API_KEY", ""),
            room_id=os.getenv("AUTORCA_SWITCH_ROOM_ID", "").strip(),
            connection_id=os.getenv("AUTORCA_SWITCH_CONNECTION_ID", "").strip(),
            target_agent=os.getenv("AUTORCA_SWITCH_TARGET_AGENT", "").strip(),
            agent_name=os.getenv("AUTORCA_SWITCH_AGENT_NAME", "autorca").strip(),
            outbox_path=Path(raw_path).expanduser(),
            request_timeout_seconds=timeout,
        )
        if mode == "live":
            missing = [key for key, value in (
                ("AUTORCA_SWITCH_AGENT_BASE_URL", settings.agent_base_url),
                ("AUTORCA_SWITCH_AGENT_ID", settings.agent_id),
                ("AUTORCA_SWITCH_AGENT_API_KEY", settings.agent_api_key),
                ("AUTORCA_SWITCH_ROOM_ID", settings.room_id),
                ("AUTORCA_SWITCH_CONNECTION_ID", settings.connection_id),
            ) if not value]
            if missing:
                raise RuntimeError("Live Switch mode requires: " + ", ".join(missing))
            validate_agent_base_url(settings.agent_base_url)
            if any(ch.isspace() for ch in settings.agent_api_key):
                raise RuntimeError("AUTORCA_SWITCH_AGENT_API_KEY contains invalid whitespace.")
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", settings.agent_name):
            raise RuntimeError("AUTORCA_SWITCH_AGENT_NAME must be a valid Switch agent name.")
        return settings


def validate_agent_base_url(value: str) -> str:
    """Validate a credential-bearing Switch endpoint before sending any bearer token."""
    parsed = urlsplit(value)
    local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if (parsed.scheme not in ({"https"} | ({"http"} if local else set()))
            or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment):
        raise RuntimeError("Switch agent base URL must be HTTPS (HTTP only on localhost) without user info, query, or fragment.")
    return value.rstrip("/")


def redact_sensitive_text(value: str, limit: int = 4000) -> str:
    """Bound text and remove common credentials/contact details before storage or sharing."""
    import re

    text = str(value)[:limit]
    text = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", text)
    text = re.sub(r"(?i)\b(api[_-]?key|access[_-]?token|secret|password)\s*[:=]\s*[^\s,;]+", r"\1=[REDACTED]", text)
    text = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[EMAIL REDACTED]", text)
    text = re.sub(r"(?<!\w)(?:\+?\d[\d .()-]{7,}\d)(?!\w)", "[PHONE REDACTED]", text)
    text = "".join(char for char in text if char in "\n\t" or ord(char) >= 32)
    return text.strip()
