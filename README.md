# AutoRCA

AutoRCA is a small, explainable system-log analysis demo for the WeMakeDevs **Flip the Switch** Hackathon. It groups error events by service, labels heuristic severity, shows the log lines behind rule-based cause hypotheses, and provides a local investigation plan for a human to review.

## Current features

- Parses UTF-8 logs using timestamps in `YYYY-MM-DD HH:MM:SS` or ISO-style `YYYY-MM-DDTHH:MM:SS` form, with optional fractional seconds and timezone. Dates and times are validated, not only pattern-matched.
- Counts nonblank lines, reports malformed entries with their line numbers, and groups `ERROR`, `CRITICAL`, and `FATAL` events by service (`FATAL` is normalized to `CRITICAL`). Long lines are counted as malformed without being retained in full.
- Limits the input file to 5 MiB by default, limits lines to 65,536 characters, and returns at most 100 malformed-line examples. The full malformed-line count is retained even when the example list is capped.
- Labels an incident HIGH when it includes a CRITICAL event or at least three error events; otherwise it is MEDIUM. This is a demo heuristic, not a production incident assessment.
- Shows database, authentication, timeout, memory, and network/dependency cause hypotheses with matching messages and timestamps. Keyword rules are evidence prompts, not proof of cause.
- Serves a responsive dashboard from the same FastAPI app.
- Generates an investigation plan using a provider-independent local interface. It can accept human context, allow the human to approve/reject/edit the plan, and keep that decision in the current server process.
- Trims and validates human messages. Edited plans allow at most 20 steps of up to 300 characters each. The decision lifecycle is `pending` → `approved`, `rejected`, or `modified`; a `modified` plan may be edited again or approved/rejected. Approved and rejected decisions cannot be changed directly; new human context reopens the investigation to `pending`. Decision history is retained in memory, including timestamps and step snapshots.
- Provides a **local Switch mock only**. There is no live Switch SDK or integration because verified hackathon integration documentation is not available in this project.

## Project structure

```text
backend/
  agent.py             Deterministic investigation-plan provider
  log_analyzer.py      Parsing, grouping, severity, cause evidence
  main.py              FastAPI endpoints and validation
  switch_adapter.py    Local mock boundary; no live Switch calls
data/
  sample.log           Public demo log with database, auth, timeout, malformed cases
frontend/
  index.html           Dashboard structure
  static/app.js        Dashboard API calls and interactions
  static/style.css     Responsive dark console styling
tests/
  asgi_client.py      Minimal no-dependency in-process HTTP test helper
  test_http_api.py    FastAPI status/validation/JSON contract tests
  test_api.py
  test_log_analyzer.py
```

## Windows setup

Use Python 3.10 or newer and PowerShell from the project directory. The existing `.venv` can be reused.

```powershell
cd C:\Users\HP\Desktop\AutoRCA-Hackathon
\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

The package versions in `requirements.txt` cover the FastAPI server only. Install into the project virtual environment; do not install globally. No AI provider key is needed. `.env.example` documents the reserved configuration location without containing secrets.

The `.env.example` file is a template and is **not loaded automatically**. To override the defaults for one PowerShell session, set the values before starting Uvicorn, for example:

```powershell
$env:AUTORCA_MAX_LOG_BYTES = '10485760'
$env:AUTORCA_MAX_LOG_LINE_CHARS = '65536'
$env:AUTORCA_MAX_MALFORMED_EXAMPLES = '100'
```

All three settings must be positive integers. An invalid value prevents the backend from importing and names the invalid setting.

## Start the application

```powershell
cd C:\Users\HP\Desktop\AutoRCA-Hackathon
\.venv\Scripts\python.exe -m uvicorn backend.main:app --reload
```

Open [http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard) for the dashboard or [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) for interactive API documentation. The root route remains a JSON health-style welcome response; `/health` is the explicit health endpoint.

## API examples

List available local log files:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/files
```

Analyze the sample log:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/analyze `
  -ContentType 'application/json' -Body '{"filename":"sample.log"}'
```

The analysis response preserves `success`, `report.total_lines_analyzed`, `report.incident_count`, and `report.incidents`. It also includes `malformed_line_count`, capped `malformed_lines` examples, and `malformed_lines_truncated`. A file over the configured size limit returns HTTP 413. The report includes cause hypotheses with evidence and severity reasoning.

Create a human-review plan for an incident:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/investigations `
  -ContentType 'application/json' `
  -Body '{"filename":"sample.log","service":"payment-service","context":"Recent database maintenance"}'
```

The response includes the proposal, evidence, mock handoff, a `pending` human decision, and `decision_history`. Unknown investigation IDs return 404; invalid actions return 400; changing a final decision directly returns 409. New human context after approval or rejection reopens the investigation to `pending`, records that transition, and requires review again. The dashboard offers follow-up context and buttons to approve, reject, or edit the proposed steps.

## Run tests

```powershell
cd C:\Users\HP\Desktop\AutoRCA-Hackathon
\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The tests use Python's standard `unittest` and do not require `pytest` or `httpx`. API contract tests invoke the FastAPI ASGI app directly in-process, so they verify HTTP status codes, validation responses, and JSON without starting a server or opening a socket. They are not network-level tests.

## Demo walkthrough

1. Start the server and open `/dashboard`.
2. Select `sample.log` and click **Analyze logs**. Point out the total lines, three incidents, and one malformed line.
3. Select `payment-service`: the report shows database evidence and its matching timestamps; the cause remains a hypothesis.
4. Select `inventory-service` to show the timeout hypothesis and troubleshooting recommendation.
5. Ask the local agent for an investigation plan, add a short human note, then approve, reject, or edit the checks.
6. Point out the **Switch: local mock only** label. Do not present it as a live integration.

## Limitations and next work

- The parser currently supports documented timestamp forms and a single-token service name. Unrecognized nonblank lines are reported but not interpreted.
- Cause matching is keyword-based. It filters common negations and substring matches, but may miss synonyms or misunderstand complex language; it gives no numeric confidence score.
- Investigation records and decision history are stored in memory and disappear when the server restarts. A deployment with multiple workers may not share these records. The fallback does not call an LLM and does not execute operational actions.
- There is no live Switch integration. Implement one only after the actual hackathon requirements and verified documentation are available.
- The in-process ASGI tests do not cover network-server behavior, browser rendering, or multi-worker operation.
- Useful future work includes durable investigation history, richer log formats, rule configuration, and validation against labeled incidents.
