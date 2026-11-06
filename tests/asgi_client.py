"""Tiny in-process ASGI test client; it opens no socket and adds no dependency."""

import asyncio
import json


def request(app, method: str, path: str, body: dict | bytes | None = None, content_type: str = "application/json"):
    request_body = (body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")) if body is not None else b""
    request_delivered = False
    messages = []
    path_bytes = path.encode("ascii")
    response_finished = asyncio.Event()

    async def receive():
        nonlocal request_delivered
        if request_delivered:
            await response_finished.wait()
            return {"type": "http.disconnect"}
        request_delivered = True
        return {"type": "http.request", "body": request_body, "more_body": False}

    async def send(message):
        messages.append(message)
        if message["type"] == "http.response.body" and not message.get("more_body", False):
            response_finished.set()

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method.upper(),
        "scheme": "http",
        "path": path,
        "raw_path": path_bytes,
        "query_string": b"",
        "root_path": "",
        "headers": [
            (b"host", b"testserver"),
            (b"content-type", content_type.encode("ascii")),
        ],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
        "state": {},
    }
    try:
        asyncio.run(app(scope, receive, send))
    except Exception:
        # Starlette sends a generic 500 response and then re-raises for server logging.
        if not any(item["type"] == "http.response.start" for item in messages):
            raise
    response_start = next(item for item in messages if item["type"] == "http.response.start")
    response_body = b"".join(
        item.get("body", b"") for item in messages if item["type"] == "http.response.body"
    )
    try:
        decoded_body = json.loads(response_body) if response_body else None
    except (UnicodeDecodeError, json.JSONDecodeError):
        decoded_body = response_body
    return response_start["status"], decoded_body
