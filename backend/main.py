"""FastAPI routes for log analysis and human-reviewed investigations."""

from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, StringConstraints, field_validator

from backend.agent import DeterministicInvestigator, Investigator
from backend.log_analyzer import LogFileTooLargeError, analyze_logs
from backend.switch_adapter import LocalSwitchMock


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
FRONTEND_DIR = PROJECT_ROOT / "frontend"

app = FastAPI(
    title="AutoRCA",
    description="Explainable system-log incident analysis with human-reviewed investigation plans.",
    version="0.2.0",
)
investigator: Investigator = DeterministicInvestigator()
switch_adapter = LocalSwitchMock()
investigations: dict[str, dict] = {}
MAX_INVESTIGATION_MESSAGES = 50
MAX_DECISION_HISTORY = 100
MAX_MODIFIED_STEPS = 20
MAX_MODIFIED_STEP_CHARS = 300
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

    @field_validator("decision", mode="before")
    @classmethod
    def trim_decision(cls, value):
        return value.strip() if isinstance(value, str) else value


def _log_path(filename: str) -> Path:
    """Resolve a data filename and ensure it cannot escape the log directory."""
    if Path(filename).name != filename or filename in {".", ".."} or not filename.casefold().endswith(".log"):
        raise HTTPException(status_code=400, detail="Provide a valid .log filename only.")
    root = DATA_DIR.resolve()
    path = (root / filename).resolve()
    if not path.is_relative_to(root):
        raise HTTPException(status_code=400, detail="Log file must be inside the data folder.")
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Log file not found in the data folder.")
    return path


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
    return {"status": "ok", "project": "AutoRCA"}


@app.get("/dashboard", include_in_schema=False)
def dashboard():
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/files")
def list_log_files():
    return {"files": sorted(path.name for path in DATA_DIR.glob("*.log") if path.is_file())}


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
    return record


app.mount("/static", StaticFiles(directory=FRONTEND_DIR / "static"), name="static")
