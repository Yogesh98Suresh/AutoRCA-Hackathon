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
- Provides an offline Switch mock by default and an opt-in server-side client for the documented Switch agent protocol. Live mode requires an operator-registered agent and stays disabled unless explicitly configured.
- Sends only an investigation ID, validated service identifier, and severity to Switch, and only after a human checks the separate sharing consent box while approving the plan. Raw logs, evidence, and human context are not sent. Switch replies are stored as untrusted recommendations for human review.

## Project structure

```text
backend/
  agent.py             Deterministic investigation-plan provider
  log_analyzer.py      Parsing, grouping, severity, cause evidence
  main.py              FastAPI endpoints and validation
  switch_adapter.py    Mock/live adapter boundary and minimized handoff
  switch_client.py     Stdlib HTTP/WebSocket protocol client and reconnect loop
  switch_config.py     Server-only Switch settings and redaction
  switch_outbox.py     SQLite delivery outbox, stream cursor, and inbound deduplication
  switch_register.py   Explicit one-time operator registration command
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
  test_switch_integration.py  Mocked Switch HTTP/WebSocket and outbox tests
```

## Windows setup

Use Python 3.10 or newer and PowerShell from the project directory. The existing `.venv` can be reused.

```powershell
cd C:\Users\HP\Desktop\AutoRCA-Hackathon
\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

The package versions in `requirements.txt` cover the FastAPI server only. Switch HTTP/WebSocket support uses the Python standard library; no package was added. No AI provider key is needed. `.env.example` documents configuration names without containing secrets.

The `.env.example` file is a template and is **not loaded automatically**. To override the defaults for one PowerShell session, set the values before starting Uvicorn, for example:

```powershell
$env:AUTORCA_MAX_LOG_BYTES = '10485760'
$env:AUTORCA_MAX_LOG_LINE_CHARS = '65536'
$env:AUTORCA_MAX_MALFORMED_EXAMPLES = '100'
```

All three settings must be positive integers. An invalid value prevents the backend from importing and names the invalid setting.

Switch runs in mock mode by default. The `.env.example` file is not auto-loaded. To use live mode, first register an agent once using the documented agent bridge URL and a Switch registration key. In PowerShell, set the bridge URL and one-time registration key, then run:

```powershell
$env:AUTORCA_SWITCH_AGENT_BASE_URL = 'https://<switch-agent-api-host>'
$env:AUTORCA_SWITCH_REGISTRATION_API_KEY = '<registration-key>'
.\.venv\Scripts\python.exe -m backend.switch_register
```

On Windows, the command stores the returned agent API key in the current user's Windows Credential Manager and prints only the agent ID and credential target name. It deliberately refuses to register on other operating systems until a secure credential-store adapter is provided. Retrieve the key through your approved secret-handling process before setting the server environment; remove the one-time registration key afterward. The integration currently uses the `always_on` registration profile and this deployment-specific choice should be confirmed with the Switch administrator. Live configuration is not proof of connectivity; the dashboard labels it unverified until a real server exchange has been confirmed.

For live mode, set `AUTORCA_SWITCH_MODE=live`, `AUTORCA_SWITCH_AGENT_BASE_URL`, `AUTORCA_SWITCH_AGENT_ID`, `AUTORCA_SWITCH_AGENT_API_KEY`, `AUTORCA_SWITCH_ROOM_ID`, and a stable `AUTORCA_SWITCH_CONNECTION_ID` UUID in the server process environment. Optionally set `AUTORCA_SWITCH_TARGET_AGENT` to the exact responder agent name and `AUTORCA_SWITCH_AGENT_NAME` to AutoRCA's registered name so replies can address it and include the investigation ID. `AUTORCA_SWITCH_OUTBOX_PATH` and `AUTORCA_SWITCH_TIMEOUT_SECONDS` are optional. The SQLite outbox tracks handoff and inbound event state. A shared multi-worker deployment should run only one Switch event worker for a given agent/room connection.

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

The response includes the proposal, evidence, handoff metadata, a `pending` human decision, and `decision_history`. Unknown investigation IDs return 404; invalid actions return 400; changing a final decision directly returns 409. New human context after approval or rejection reopens the investigation to `pending`, records that transition, and requires review again. In live mode, approving the plan does not share anything unless the user also checks the explicit Switch sharing consent box. The dashboard shows delivery state and lets the user load addressed Switch recommendations, clearly marked for human review.

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
6. In the default mode, point out the **Switch: local mock only** label. Live mode remains disabled until an operator completes registration and configures server credentials.

## Limitations and next work

- The parser currently supports documented timestamp forms and a single-token service name. Unrecognized nonblank lines are reported but not interpreted.
- Cause matching is keyword-based. It filters common negations and substring matches, but may miss synonyms or misunderstand complex language; it gives no numeric confidence score.
- Investigation records and decision history are stored in memory and disappear when the server restarts. A deployment with multiple workers may not share these records. The fallback does not call an LLM and does not execute operational actions.
- The live protocol client has mocked contract tests but has not been connected to a real Switch workspace. Registration profile compatibility and deployed operation schemas still need isolated-workspace verification. Only outbox entries that remain `pending` are resumed on startup; in-flight/ambiguous sends become `unknown` and require reconciliation, and definite failures are not retried automatically.
- Investigation and decision records remain in memory; only Switch handoff, cursor, gaps, and inbound de-duplication state are stored in SQLite.
- The in-process ASGI tests do not cover network-server behavior, browser rendering, or multi-worker operation.
- Useful future work includes durable investigation history, richer log formats, rule configuration, and validation against labeled incidents.
