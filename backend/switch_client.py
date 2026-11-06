"""Small stdlib-only HTTP and WebSocket client for the documented Switch agent protocol."""

import base64
import hashlib
import json
import os
import socket
import ssl
import struct
from threading import Thread
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from backend.switch_config import SwitchSettings, validate_agent_base_url


class SwitchHTTPError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class SwitchTransportError(RuntimeError):
    """Transport failure whose delivery outcome may be ambiguous."""


class SwitchHTTPClient:
    def __init__(self, settings: SwitchSettings, opener=None):
        self.settings = settings
        if settings.agent_base_url:
            validate_agent_base_url(settings.agent_base_url)
        self._opener = opener or urllib.request.urlopen

    def _request(self, method: str, path: str, body: dict | None, credential: str | None = None):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if credential:
            headers["Authorization"] = f"Bearer {credential}"
        request = urllib.request.Request(self.settings.agent_base_url + path, data=data, headers=headers, method=method)
        try:
            with self._opener(request, timeout=self.settings.request_timeout_seconds) as response:
                raw = response.read(1024 * 1024)
                if not raw:
                    return None
                try:
                    return json.loads(raw.decode("utf-8"))
                except (UnicodeError, json.JSONDecodeError):
                    return None
        except urllib.error.HTTPError as exc:
            # Avoid echoing response text which could contain sensitive server data.
            raise SwitchHTTPError(exc.code, f"Switch HTTP request rejected ({exc.code}).") from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise SwitchTransportError(f"Switch transport failed ({type(exc).__name__}).") from None

    def register_agent(self, registration_key: str, profile: dict, *, name: str, description: str,
                       connector_type: str = "autorca") -> dict:
        body = {"name": name, "description": description, "connector_type": connector_type,
                "integration_profile": profile}
        result = self._request("POST", "/agents", body, registration_key)
        if not isinstance(result, dict) or not isinstance(result.get("id"), str) or not isinstance(result.get("api_key"), str):
            raise SwitchTransportError("Switch registration response did not contain documented id and api_key fields.")
        return {"id": result["id"], "api_key": result["api_key"]}

    def discover_operations(self) -> dict:
        return self._request("GET", f"/agents/{urllib.parse.quote(self.settings.agent_id, safe='')}/ops", None,
                             self.settings.agent_api_key)

    def read_room_context(self, room_id: str):
        """Read history using the live operation schema rather than assuming its arguments."""
        catalog = self.discover_operations()
        operation = (catalog.get("operations", {}) if isinstance(catalog, dict) else {}).get("read_context")
        if not isinstance(operation, dict):
            raise SwitchTransportError("Switch did not advertise the read_context operation.")
        schema = operation.get("input_schema", {})
        properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
        required = schema.get("required", []) if isinstance(schema, dict) else []
        arguments = {"room_id": room_id} if "room_id" in properties else {}
        if any(field not in arguments for field in required):
            raise SwitchTransportError("Switch read_context requires arguments this client does not infer.")
        return self.invoke_operation("read_context", arguments)

    def post_message(self, room_id: str, content: str):
        path = f"/agents/{urllib.parse.quote(self.settings.agent_id, safe='')}/message"
        return self._request("POST", path, {"room_id": room_id, "content": content}, self.settings.agent_api_key)

    def invoke_operation(self, operation: str, arguments: dict, connection_id: str | None = None):
        path = f"/agents/{urllib.parse.quote(self.settings.agent_id, safe='')}/ops/{urllib.parse.quote(operation, safe='')}"
        data = json.dumps(arguments).encode("utf-8")
        headers = {"Authorization": f"Bearer {self.settings.agent_api_key}", "Content-Type": "application/json"}
        if connection_id:
            headers["X-Switch-Connection-Id"] = connection_id
        request = urllib.request.Request(self.settings.agent_base_url + path, data=data, headers=headers, method="POST")
        try:
            with self._opener(request, timeout=self.settings.request_timeout_seconds) as response:
                return json.loads(response.read(1024 * 1024).decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise SwitchHTTPError(exc.code, f"Switch operation rejected ({exc.code}).") from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise SwitchTransportError(f"Switch transport failed ({type(exc).__name__}).") from None


class WebSocketConnection:
    """Minimal RFC6455 client sufficient for Switch text/control frames; stdlib only."""

    def __init__(self, sock):
        self.sock = sock

    @classmethod
    def open(cls, url: str, api_key: str, timeout: float = 10.0):
        parsed = urllib.parse.urlsplit(url)
        secure = parsed.scheme == "wss"
        port = parsed.port or (443 if secure else 80)
        raw = socket.create_connection((parsed.hostname, port), timeout=timeout)
        if secure:
            raw = ssl.create_default_context().wrap_socket(raw, server_hostname=parsed.hostname)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        request = (f"GET {path} HTTP/1.1\r\nHost: {parsed.netloc}\r\nUpgrade: websocket\r\n"
                   f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
                   f"Authorization: Bearer {api_key}\r\n\r\n")
        raw.sendall(request.encode("ascii"))
        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = raw.recv(4096)
            if not chunk:
                raw.close()
                raise SwitchTransportError("Switch WebSocket closed during upgrade.")
            response.extend(chunk)
            if len(response) > 16384:
                raw.close()
                raise SwitchTransportError("Switch WebSocket upgrade headers exceeded the limit.")
        header_bytes, initial = bytes(response).split(b"\r\n\r\n", 1)
        lines = header_bytes.decode("latin1").split("\r\n")
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                name, value = line.split(":", 1)
                headers[name.strip().casefold()] = value.strip()
        expected = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        if not lines[0].endswith(" 101 Switching Protocols") or headers.get("sec-websocket-accept") != expected:
            raw.close()
            raise SwitchTransportError("Switch WebSocket upgrade was rejected.")
        conn = cls(raw)
        conn._buffer = bytearray(initial)
        conn._fragment = bytearray()
        conn._fragment_opcode = None
        return conn

    def _read_exact(self, size: int) -> bytes:
        while len(self._buffer) < size:
            data = self.sock.recv(max(4096, size - len(self._buffer)))
            if not data:
                raise SwitchTransportError("Switch WebSocket connection closed.")
            self._buffer.extend(data)
        result = bytes(self._buffer[:size])
        del self._buffer[:size]
        return result

    def send_frame(self, opcode: int, payload: bytes):
        first = bytes([0x80 | opcode])
        length = len(payload)
        if length < 126:
            header = first + bytes([0x80 | length])
        elif length <= 65535:
            header = first + bytes([0x80 | 126]) + struct.pack("!H", length)
        else:
            header = first + bytes([0x80 | 127]) + struct.pack("!Q", length)
        mask = os.urandom(4)
        masked = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
        self.sock.sendall(header + mask + masked)

    def send_json(self, value: dict):
        self.send_frame(1, json.dumps(value, separators=(",", ":")).encode("utf-8"))

    def recv_json(self):
        while True:
            first, second = self._read_exact(2)
            fin, opcode = bool(first & 0x80), first & 0x0F
            masked, length = bool(second & 0x80), second & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._read_exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._read_exact(8))[0]
            if length > 2 * 1024 * 1024:
                raise SwitchTransportError("Switch WebSocket frame exceeded 2 MiB.")
            mask = self._read_exact(4) if masked else b""
            payload = self._read_exact(length)
            if masked:
                payload = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
            if opcode == 8:
                raise SwitchTransportError("Switch closed the WebSocket connection.")
            if opcode == 9:
                self.send_frame(10, payload)
                continue
            if opcode == 10:
                continue
            if opcode in {1, 2}:
                if self._fragment_opcode is not None:
                    raise SwitchTransportError("Unexpected nested WebSocket data frame.")
                self._fragment_opcode = opcode
                self._fragment = bytearray(payload)
            elif opcode == 0 and self._fragment_opcode is not None:
                self._fragment.extend(payload)
            else:
                raise SwitchTransportError("Unsupported WebSocket frame type.")
            if len(self._fragment) > 2 * 1024 * 1024:
                raise SwitchTransportError("Switch WebSocket message exceeded 2 MiB.")
            if fin:
                opcode = self._fragment_opcode
                data = bytes(self._fragment)
                self._fragment_opcode, self._fragment = None, bytearray()
                if opcode != 1:
                    continue
                try:
                    return json.loads(data.decode("utf-8"))
                except (UnicodeError, json.JSONDecodeError):
                    raise SwitchTransportError("Switch sent an invalid JSON text frame.") from None

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


@dataclass
class ConnectionState:
    cursor: int = 0
    generation: int = 0
    ready: bool = False


class SwitchEventClient:
    def __init__(self, settings: SwitchSettings, outbox, on_message, connector=None, gap_handler=None):
        self.settings = settings
        self.outbox = outbox
        self.on_message = on_message
        self.connector = connector or WebSocketConnection.open
        self.gap_handler = gap_handler
        self.state = ConnectionState(**outbox.get_stream_state(settings.connection_id))

    def _recheck_history_after_gap(self, details: dict):
        try:
            self.gap_handler(self.settings.room_id)
            self.outbox.record_gap(self.settings.connection_id, details, True)
        except Exception:
            # Gap state remains durable and requires operator reconciliation.
            return

    def connection_url(self) -> str:
        query = urllib.parse.urlencode({
            "connection_id": self.settings.connection_id,
            "rooms": self.settings.room_id,
            "scope": "single",
            "filter": "all",
            "start_from": str(self.state.cursor) if self.state.cursor else "head",
            **({"expected_generation": str(self.state.generation)} if self.state.generation else {}),
        })
        parsed = urllib.parse.urlsplit(self.settings.agent_base_url)
        scheme = "wss" if parsed.scheme == "https" else "ws"
        path = parsed.path.rstrip("/") + f"/agents/{urllib.parse.quote(self.settings.agent_id, safe='')}/connection/ws"
        return urllib.parse.urlunsplit((scheme, parsed.netloc, path, query, ""))

    def handle_frame(self, frame: dict):
        kind = frame.get("event") or frame.get("type")
        if kind == "connection_state":
            data = frame.get("data", frame)
            self.state.cursor = int(data.get("cursor", self.state.cursor))
            self.state.generation = int(data.get("generation", self.state.generation))
            self.state.ready = True
            self.outbox.save_stream_state(self.settings.connection_id, self.state.cursor, self.state.generation)
            return {"kind": "state"}
        if kind == "ping":
            return {"kind": "ping", "pong": {"type": "pong", "cursor": self.state.cursor}}
        if kind == "gap":
            data = frame.get("data", frame)
            resumed = int(data.get("resumed_at", self.state.cursor))
            self.state.cursor = max(self.state.cursor, resumed)
            self.outbox.save_stream_state(self.settings.connection_id, self.state.cursor, self.state.generation)
            self.outbox.record_gap(self.settings.connection_id, data, False)
            if self.gap_handler:
                Thread(target=self._recheck_history_after_gap, args=(data,),
                       name="autorca-switch-gap-recheck", daemon=True).start()
            return {"kind": "gap", "re_read_history": False,
                    "operator_review_required": True, "cursor": self.state.cursor}
        if kind == "evicted":
            data = frame.get("data", frame)
            code = data.get("code")
            recoverable = {"heartbeat_lapsed", "no_stream", "unfenced", "connection_error"}
            return {"kind": "evicted", "code": code, "reconnect": code in recoverable}
        if kind == "refused":
            return {"kind": "refused", "status": frame.get("status"), "detail": frame.get("detail")}
        if kind in {"message", "command", "room_join"}:
            if not self.state.ready:
                raise SwitchTransportError("Received a Switch event before connection_state.")
            data = frame.get("data", {})
            seq = int(data.get("sequence", frame.get("id", 0)))
            if seq <= self.state.cursor:
                return {"kind": "duplicate"}
            payload = data.get("payload", {})
            if (kind == "message" and data.get("room_id") == self.settings.room_id
                    and payload.get("addressed") is True):
                self.on_message(data, payload)
            self.state.cursor = seq
            self.outbox.save_stream_state(self.settings.connection_id, self.state.cursor, self.state.generation)
            return {"kind": "event", "cursor": seq}
        return {"kind": "ignored"}

    def run_once(self):
        """Connect, consume until the socket fails, and return whether reconnect is permitted."""
        conn = self.connector(self.connection_url(), self.settings.agent_api_key,
                              self.settings.request_timeout_seconds)
        self.state.ready = False
        try:
            while True:
                frame = conn.recv_json()
                result = self.handle_frame(frame)
                if result["kind"] == "ping":
                    conn.send_json(result["pong"])
                elif result["kind"] == "evicted":
                    return result["reconnect"]
                elif result["kind"] == "gap":
                    # Resume delivery, but retain the gap flag for explicit reconciliation.
                    continue
                elif result["kind"] == "refused":
                    return False
        finally:
            conn.close()

    def run_forever(self, stop_event, sleep_fn=None):
        delay = 1
        while not stop_event.is_set():
            try:
                reconnect = self.run_once()
                if not reconnect:
                    return
                delay = 1
            except Exception:
                # No exception text: it could contain transport details or credentials.
                delay = min(delay * 2, 30)
            stop_event.wait(delay)
