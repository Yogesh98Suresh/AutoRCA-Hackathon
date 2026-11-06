"""FastAPI routes for log analysis and human-reviewed investigations."""

from datetime import datetime, timezone
import codecs
from pathlib import Path
import re
import tempfile
from threading import Event, Thread
from typing import Annotated
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, StringConstraints, field_validator

from backend import log_analyzer
from backend.agent import DeterministicInvestigator, Investigator
from backend.log_analyzer import LogFileTooLargeError, analyze_logs
from backend.switch_adapter import LiveSwitchAdapter, create_switch_adapter
from backend.switch_client import SwitchEventClient
from backend.switch_config import SwitchSettings


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
FRONTEND_DIR = PROJECT_ROOT / "frontend"

app = FastAPI(
    title="AutoRCA",
    description="Explainable system-log incident analysis with human-reviewed investigation plans.",
    version="0.2.0",
)


class UploadBodyLimitMiddleware:
    """Bound multipart request bodies before Starlette parses/spools their parts."""

    def __init__(self, application):
        self.application = application

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] != "POST" or scope["path"] != "/upload":
            await self.application(scope, receive, send)
            return

        max_body = log_analyzer.MAX_LOG_FILE_BYTES + 64 * 1024
        headers = dict(scope.get("headers", []))
        try:
            content_length = int(headers.get(b"content-length", b"0"))
        except ValueError:
            content_length = 0
        if content_length > max_body:
            await self._too_large(send)
            return

        # At most 64 KiB stays in memory; the rest is spooled to disk, capped at max_body.
        body_file = tempfile.SpooledTemporaryFile(max_size=64 * 1024, mode="w+b")
        total = 0
        try:
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                chunk = message.get("body", b"")
                total += len(chunk)
                if total > max_body:
                    await self._too_large(send)
                    return
                body_file.write(chunk)
                if not message.get("more_body", False):
                    break

            body_file.seek(0)
            sent = 0

            async def replay_body():
                nonlocal sent
                if sent < total:
                    chunk = body_file.read(min(64 * 1024, total - sent))
                    sent += len(chunk)
                    return {"type": "http.request", "body": chunk, "more_body": sent < total}
                return {"type": "http.disconnect"}

            await self.application(scope, replay_body, send)
        finally:
            body_file.close()

    @staticmethod
    async def _too_large(send):
        body = b'{"detail":"Upload request exceeds the configured size limit."}'
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode("ascii"))]})
        await send({"type": "http.response.body", "body": body, "more_body": False})


app.add_middleware(UploadBodyLimitMiddleware)
investigator: Investigator = DeterministicInvestigator()
switch_settings = SwitchSettings.from_env()
switch_adapter = create_switch_adapter(switch_settings)
investigations: dict[str, dict] = {}
switch_worker_stop = Event()
switch_worker_thread: Thread | None = None
MAX_INVESTIGATION_MESSAGES = 50
MAX_DECISION_HISTORY = 100
MAX_MODIFIED_STEPS = 20
MAX_MODIFIED_STEP_CHARS = 300
MAX_RETAINED_UPLOADS = 20
UPLOAD_CHUNK_BYTES = 64 * 1024
GENERATED_UPLOAD_NAME = re.compile(r"autorca-upload-[0-9a-f]{32}\.log\Z")
ModifiedStep = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=MAX_MODIFIED_STEP_CHARS),
]


class AnalyzeRequest(BaseModel):
    filename: str = Field(default="sample.log", min_length=1, max_length=255)


class InvestigationRequest(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    service: str = Field(min_length=1, max_length=255)
    context: str = Field(default="", max_length=4000)


class MessageRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)

    @field_validator("message", mode="before")
    @classmethod
    def trim_message(cls, value):
        return value.strip() if isinstance(value, str) else value


class DecisionRequest(BaseModel):
    decision: str = Field(min_length=1, max_length=16)
    note: str = Field(default="", max_length=4000)
    modified_steps: list[ModifiedStep] | None = Field(default=None, max_length=MAX_MODIFIED_STEPS)
    share_with_switch: bool = False

    @field_validator("decision", mode="before")
    @classmethod
    def trim_decision(cls, value):
        return value.strip() if isinstance(value, str) else value


@app.on_event("startup")
def start_switch_event_worker():
    """Start a server-side event reader only when live mode is explicitly enabled."""
    global switch_worker_thread
    if isinstance(switch_adapter, LiveSwitchAdapter) and not (switch_worker_thread and switch_worker_thread.is_alive()):
        switch_adapter.retry_pending()
        switch_worker_stop.clear()
        client = SwitchEventClient(switch_settings, switch_adapter.outbox, switch_adapter.handle_event,
                                   gap_handler=switch_adapter.recover_gap)
        switch_worker_thread = Thread(target=client.run_forever, args=(switch_worker_stop,),
                                      name="autorca-switch-events", daemon=True)
        switch_worker_thread.start()


@app.on_event("shutdown")
def stop_switch_event_worker():
    switch_worker_stop.set()
    if switch_worker_thread and switch_worker_thread.is_alive():
        switch_worker_thread.join(timeout=2)


def _log_path(filename: str) -> Path:
    """Resolve a data filename and ensure it cannot escape the log directory."""
    if Path(filename).name != filename or filename in {".", ".."} or not filename.casefold().endswith(".log"):
        raise HTTPException(status_code=400, detail="Provide a valid .log filename only.")
    root = _data_root()
    path = (root / filename).resolve()
    if not path.is_relative_to(root):
        raise HTTPException(status_code=400, detail="Log file must be inside the data folder.")
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Log file not found in the data folder.")
    return path


def _data_root() -> Path:
    """Return the approved project data directory without following a symlink outside it."""
    root = DATA_DIR.resolve()
    if DATA_DIR.is_symlink() or not root.is_relative_to(PROJECT_ROOT.resolve()):
        raise HTTPException(status_code=500, detail="The configured data directory must stay inside the project.")
    return root


def _cleanup_old_uploads(current: Path) -> None:
    """Retain only the newest generated upload files; never touch other logs."""
    root = _data_root()
    uploads = []
    for path in root.glob("autorca-upload-*.log"):
        if not GENERATED_UPLOAD_NAME.fullmatch(path.name) or path.resolve().parent != root:
            continue
        try:
            uploads.append((path, path.stat().st_mtime))
        except OSError:
            continue
    uploads.sort(key=lambda item: (item[0] == current, item[1]), reverse=True)
    for old_path, _modified in uploads[MAX_RETAINED_UPLOADS:]:
        try:
            old_path.unlink()
        except OSError:
            # Retention is best-effort; upload success must not be lost on cleanup errors.
            continue


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _append_decision_history(record: dict, status: str, note: str) -> None:
    if len(record["decision_history"]) >= MAX_DECISION_HISTORY:
        raise HTTPException(status_code=409, detail="Decision history limit reached for this investigation.")
    event = {
        "status": status,
        "note": note,
        "timestamp": _utc_timestamp(),
        "proposed_steps": list(record["proposal"]["proposed_steps"]),
    }
    record["decision"] = {"status": status, "note": note}
    record["decision_history"].append(event)


@app.get("/")
def home():
    return {
        "project": "AutoRCA",
        "status": "running",
        "message": "Automated log analysis API is ready.",
    }


@app.get("/health")
def health():
    return {"status": "ok", "project": "AutoRCA",
            "switch_mode": "live_configured_unverified" if switch_settings.mode == "live" else "mock"}


@app.get("/dashboard", include_in_schema=False)
def dashboard():
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/files")
def list_log_files():
    root = _data_root()
    return {"files": sorted(path.name for path in root.glob("*.log") if path.is_file())}


@app.post("/analyze")
def analyze(request: AnalyzeRequest):
    log_path = _log_path(request.filename)
    try:
        report = analyze_logs(str(log_path))
        return {"success": True, "report": report}
    except LogFileTooLargeError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except (OSError, UnicodeError) as exc:
        raise HTTPException(status_code=400, detail="Could not read the log file as UTF-8 text.") from exc


@app.post("/upload", status_code=201)
async def upload_log(file: UploadFile = File(...)):
    """Stream a browser-uploaded UTF-8 .log into a safe generated data filename."""
    original_name = file.filename or ""
    if (not original_name or len(original_name) > 255 or "/" in original_name or "\\" in original_name
            or any(ord(char) < 32 or ord(char) == 127 for char in original_name)
            or not original_name.casefold().endswith(".log")):
        await file.close()
        raise HTTPException(status_code=400, detail="Choose a safe .log filename without path separators.")

    try:
        root = _data_root()
        root.mkdir(parents=True, exist_ok=True)
    except HTTPException:
        await file.close()
        raise
    except OSError:
        await file.close()
        raise HTTPException(status_code=500, detail="Could not access the approved data directory.") from None
    stored_name = f"autorca-upload-{uuid4().hex}.log"
    stored_path = root / stored_name
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    total_bytes = 0
    created = False

    def discard_partial_upload() -> None:
        try:
            if created and GENERATED_UPLOAD_NAME.fullmatch(stored_path.name) and stored_path.resolve().parent == root:
                stored_path.unlink(missing_ok=True)
        except OSError:
            pass

    try:
        with stored_path.open("xb") as output:
            created = True
            while chunk := await file.read(UPLOAD_CHUNK_BYTES):
                total_bytes += len(chunk)
                if total_bytes > log_analyzer.MAX_LOG_FILE_BYTES:
                    raise HTTPException(status_code=413, detail="Uploaded log exceeds AUTORCA_MAX_LOG_BYTES.")
                decoder.decode(chunk, final=False)
                output.write(chunk)
            decoder.decode(b"", final=True)
        if total_bytes == 0:
            raise HTTPException(status_code=400, detail="The uploaded log file is empty.")
        report = analyze_logs(str(stored_path))
    except HTTPException:
        discard_partial_upload()
        raise
    except UnicodeDecodeError:
        discard_partial_upload()
        raise HTTPException(status_code=400, detail="The uploaded log file must be valid UTF-8 text.") from None
    except LogFileTooLargeError as exc:
        discard_partial_upload()
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except OSError:
        discard_partial_upload()
        raise HTTPException(status_code=400, detail="Could not store or read the uploaded log file.") from None
    finally:
        await file.close()

    _cleanup_old_uploads(stored_path)
    return {"success": True, "filename": stored_name, "original_filename": original_name, "report": report}


@app.post("/investigations", status_code=201)
def create_investigation(request: InvestigationRequest):
    log_path = _log_path(request.filename)
    try:
        report = analyze_logs(str(log_path))
    except LogFileTooLargeError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except (OSError, UnicodeError) as exc:
        raise HTTPException(status_code=400, detail="Could not read the log file as UTF-8 text.") from exc

    incident = next((item for item in report["incidents"] if item["service"] == request.service), None)
    if incident is None:
        raise HTTPException(status_code=404, detail="No incident found for that service in this log.")

    investigation_id = str(uuid4())
    proposal = investigator.propose(incident, request.context)
    record = {
        "id": investigation_id,
        "filename": request.filename,
        "service": request.service,
        "incident": incident,
        "proposal": proposal,
        "messages": [],
        "decision": {"status": "pending", "note": ""},
        "decision_history": [{
            "status": "pending",
            "note": "Investigation created; awaiting human review.",
            "timestamp": _utc_timestamp(),
            "proposed_steps": list(proposal["proposed_steps"]),
        }],
        "switch_handoff": switch_adapter.create_incident_card(investigation_id, proposal),
        "switch_delivery": {"status": "not_requested" if isinstance(switch_adapter, LiveSwitchAdapter) else "mock",
                            "error": ""},
    }
    investigations[investigation_id] = record
    return record


@app.post("/investigations/{investigation_id}/messages")
def add_investigation_message(investigation_id: str, request: MessageRequest):
    record = investigations.get(investigation_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    if len(record["messages"]) >= MAX_INVESTIGATION_MESSAGES:
        raise HTTPException(status_code=409, detail="Message limit reached for this investigation.")
    if len(record["decision_history"]) >= MAX_DECISION_HISTORY:
        raise HTTPException(status_code=409, detail="Decision history limit reached for this investigation.")
    record["messages"].append({"role": "human", "content": request.message})
    context = "\n".join(message["content"] for message in record["messages"])
    record["proposal"] = investigator.propose(record["incident"], context)
    was_closed = record["decision"]["status"] in {"approved", "rejected"}
    history_note = (
        "Investigation reopened after new human context; awaiting review."
        if was_closed
        else "Proposal updated after human context; awaiting review."
    )
    _append_decision_history(record, "pending", history_note)
    return record


@app.post("/investigations/{investigation_id}/decision")
def record_investigation_decision(investigation_id: str, request: DecisionRequest):
    record = investigations.get(investigation_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    decision = request.decision.casefold()
    if decision not in {"approved", "rejected", "modified"}:
        raise HTTPException(status_code=400, detail="Decision must be approved, rejected, or modified.")
    current_status = record["decision"]["status"]
    allowed_transitions = {
        "pending": {"approved", "rejected", "modified"},
        "modified": {"approved", "rejected", "modified"},
        "approved": set(),
        "rejected": set(),
    }
    if decision not in allowed_transitions[current_status]:
        raise HTTPException(
            status_code=409,
            detail=f"Cannot change investigation decision from '{current_status}' to '{decision}'.",
        )
    if len(record["decision_history"]) >= MAX_DECISION_HISTORY:
        raise HTTPException(status_code=409, detail="Decision history limit reached for this investigation.")
    if decision != "modified" and request.modified_steps is not None:
        raise HTTPException(status_code=400, detail="modified_steps can only be provided with a modified decision.")
    if decision == "modified":
        if not request.modified_steps or not all(step.strip() for step in request.modified_steps):
            raise HTTPException(status_code=400, detail="A modified decision must include non-empty modified_steps.")
        record["proposal"]["proposed_steps"] = list(request.modified_steps)
    _append_decision_history(record, decision, request.note.strip())
    if decision == "approved" and request.share_with_switch:
        record["switch_delivery"] = switch_adapter.submit_approved_investigation(
            investigation_id, record["incident"],
            f"approved_plan:{len(record['decision_history'])}",
        )
    elif decision == "approved" and isinstance(switch_adapter, LiveSwitchAdapter):
        record["switch_delivery"] = {"status": "not_shared", "error": "No Switch sharing approval was given."}
    return record


@app.get("/investigations/{investigation_id}/switch/messages")
def list_switch_responses(investigation_id: str):
    if investigations.get(investigation_id) is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return {"messages": switch_adapter.list_responses(investigation_id)}


@app.get("/investigations/{investigation_id}/switch/status")
def switch_delivery_status(investigation_id: str):
    record = investigations.get(investigation_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    if isinstance(switch_adapter, LiveSwitchAdapter):
        return switch_adapter.delivery_status(investigation_id)
    return {"status": "mock", "error": "", "recovery_required": False}


app.mount("/static", StaticFiles(directory=FRONTEND_DIR / "static"), name="static")
