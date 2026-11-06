"""Parse supported application logs and build explainable service incidents."""

import os
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path


# Supported timestamps are ISO-style date/time values or the space-separated
# format used by data/sample.log. A timezone and fractional seconds are optional.
TIMESTAMP = r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
LOG_LINE = re.compile(
    rf"^(?P<timestamp>{TIMESTAMP})\s+(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL|FATAL)\s+(?P<service>\S+)\s+(?P<message>.+)$",
    re.IGNORECASE,
)
APACHE_LOG_LINE = re.compile(
    r"^\[(?P<timestamp>[^]\r\n]+)\]\s+\[(?P<level>[A-Za-z]+)\]\s+(?P<message>.+)$"
)
APACHE_LEVELS = {
    "emerg": "CRITICAL", "alert": "CRITICAL", "crit": "CRITICAL",
    "error": "ERROR", "warn": "WARN", "notice": "INFO", "info": "INFO", "debug": "DEBUG",
}
HIGH_SEVERITY_ERROR_THRESHOLD = 3
MALFORMED_EXAMPLE_CHARS = 500


def _positive_setting(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a positive integer") from exc
    if parsed <= 0:
        raise RuntimeError(f"{name} must be a positive integer")
    return parsed


MAX_LOG_FILE_BYTES = _positive_setting("AUTORCA_MAX_LOG_BYTES", 5 * 1024 * 1024)
MAX_LOG_LINE_CHARS = _positive_setting("AUTORCA_MAX_LOG_LINE_CHARS", 64 * 1024)
MAX_MALFORMED_EXAMPLES = _positive_setting("AUTORCA_MAX_MALFORMED_EXAMPLES", 100)


class LogFileTooLargeError(Exception):
    """Raised when an input log exceeds a configured processing limit."""

CAUSE_RULES = (
    {
        "cause": "Possible authentication or identity-service problem",
        "terms": ("authentication", "identity", "unauthorized", "invalid credential", "token expired"),
        "recommendation": "Check authentication service health, identity-provider availability, and credential or token validity.",
    },
    {
        "cause": "Possible database connectivity or availability problem",
        "terms": ("database", "db connection", "sql connection", "query failed", "connection pool"),
        "recommendation": "Check database availability, connection limits, connection-pool health, and recent query failures.",
    },
    {
        "cause": "Possible service timeout",
        "terms": ("timeout", "timed out", "deadline exceeded"),
        "recommendation": "Inspect service response times, dependency latency, and timeout configuration.",
    },
    {
        "cause": "Possible memory exhaustion",
        "terms": ("memory", "out of memory", "oom", "heap exhausted"),
        "recommendation": "Check memory and heap usage, recent workload changes, and possible memory leaks.",
    },
    {
        "cause": "Possible network or dependency connectivity problem",
        "terms": ("network", "connection refused", "connection reset", "host unreachable", "dns", "unreachable"),
        "recommendation": "Check network reachability, DNS, and the health of the named upstream dependency.",
    },
)


def _possible_causes(errors: list[dict]) -> list[dict]:
    """Return every matching rule with the exact log entries that support it."""
    matches = []
    for rule in CAUSE_RULES:
        evidence = [
            {"timestamp": item["timestamp"], "message": item["message"]}
            for item in errors
            if any(_term_is_supported(item["message"], term) for term in rule["terms"])
        ]
        if evidence:
            matches.append({
                "cause": rule["cause"],
                "evidence": evidence,
                "recommendation": rule["recommendation"],
                "basis": "Keyword-based heuristic; this is a hypothesis, not a confirmed cause.",
            })

    if not matches:
        matches.append({
            "cause": "Unknown or ambiguous cause",
            "evidence": [
                {"timestamp": item["timestamp"], "message": item["message"]}
                for item in errors
            ],
            "recommendation": "Review the service logs around the first error and check recent changes and dependency health.",
            "basis": "No known rule matched; further investigation is required.",
        })
    return matches


def _term_is_supported(message: str, term: str) -> bool:
    """Match whole phrases and avoid common explicit negations."""
    pattern = re.compile(rf"(?<!\w){re.escape(term)}(?!\w)", re.IGNORECASE)
    for match in pattern.finditer(message):
        before = message[max(0, match.start() - 48):match.start()]
        after = message[match.end():match.end() + 48]
        if re.search(r"\bnot(?:\s+\w+){0,4}\s*$", before, re.IGNORECASE):
            continue
        if re.match(
            r"\s+(?:(?:is|was|were)\s+)?not\s+(?:involved|related|responsible|the\s+cause|a\s+factor)\b",
            after,
            re.IGNORECASE,
        ):
            continue
        if re.search(r"\bno\s*$", before, re.IGNORECASE) and re.match(
            r"\s+(?:known\s+)?(?:issue|problem|failure|outage|incident|cause)\b",
            after,
            re.IGNORECASE,
        ):
            continue
        if re.match(r"\s+(?:(?:is|was|were)\s+)?(?:healthy|available|working|operational)\b", after, re.IGNORECASE):
            continue
        return True
    return False


def _add_malformed_example(
    examples: list[dict], line_number: int, content: str, was_truncated: bool = False
) -> None:
    if len(examples) >= MAX_MALFORMED_EXAMPLES:
        return
    excerpt = content.strip()[:MALFORMED_EXAMPLE_CHARS]
    examples.append({
        "line_number": line_number,
        "content": excerpt,
        "truncated": was_truncated or len(content.strip()) > MALFORMED_EXAMPLE_CHARS,
    })


def analyze_logs(log_file: str) -> dict:
    """Analyze a log file while preserving the original report fields."""
    path = Path(log_file)
    if not path.is_file():
        raise FileNotFoundError(f"Log file not found: {path}")
    if path.stat().st_size > MAX_LOG_FILE_BYTES:
        raise LogFileTooLargeError(f"Log file exceeds the {MAX_LOG_FILE_BYTES}-byte limit")

    incidents = defaultdict(list)
    parsed_level_counts = defaultdict(int)
    total_lines = 0
    malformed_lines = []
    malformed_line_count = 0
    bytes_read = 0
    read_size = min(MAX_LOG_LINE_CHARS + 2, MAX_LOG_FILE_BYTES + 2)

    def account_for_bytes(raw: str) -> None:
        nonlocal bytes_read
        bytes_read += len(raw.encode("utf-8"))
        if bytes_read > MAX_LOG_FILE_BYTES:
            raise LogFileTooLargeError(f"Log file exceeds the {MAX_LOG_FILE_BYTES}-byte limit")

    def record_malformed(line_number: int, content: str, was_truncated: bool = False) -> None:
        nonlocal malformed_line_count
        malformed_line_count += 1
        _add_malformed_example(malformed_lines, line_number, content, was_truncated)

    with path.open("r", encoding="utf-8") as file:
        line_number = 0
        while True:
            raw_line = file.readline(read_size)
            if not raw_line:
                break
            line_number += 1
            account_for_bytes(raw_line)
            content = raw_line.rstrip("\r\n")
            truncated_line = len(content) > MAX_LOG_LINE_CHARS or (
                not raw_line.endswith("\n") and len(raw_line) >= read_size
            )

            if truncated_line:
                nonblank = bool(raw_line.strip())
                drain_line = raw_line
                while not drain_line.endswith("\n") and len(drain_line) >= read_size:
                    drain_line = file.readline(read_size)
                    if not drain_line:
                        break
                    account_for_bytes(drain_line)
                    nonblank = nonblank or bool(drain_line.strip())
                if nonblank:
                    total_lines += 1
                    record_malformed(line_number, content, was_truncated=True)
                continue

            line = raw_line.strip()
            if not line:
                continue
            total_lines += 1
            match = LOG_LINE.match(line)
            apache_match = None if match else APACHE_LOG_LINE.match(line)
            if not match and not apache_match:
                record_malformed(line_number, line)
                continue

            if apache_match:
                timestamp = apache_match.group("timestamp")
                try:
                    datetime.strptime(timestamp, "%a %b %d %H:%M:%S %Y")
                except ValueError:
                    record_malformed(line_number, line)
                    continue
                level = APACHE_LEVELS.get(apache_match.group("level").casefold())
                if level is None:
                    record_malformed(line_number, line)
                    continue
                service = "apache"
                message = apache_match.group("message")
            else:
                timestamp = match.group("timestamp")
                try:
                    datetime.fromisoformat(timestamp[:-1] + "+00:00" if timestamp.endswith("Z") else timestamp)
                except ValueError:
                    record_malformed(line_number, line)
                    continue
                level = match.group("level").upper()
                service = match.group("service")
                message = match.group("message")
            parsed_level_counts[level] += 1
            if level in ("ERROR", "CRITICAL", "FATAL"):
                incidents[service].append({
                    "timestamp": timestamp,
                    "level": "CRITICAL" if level == "FATAL" else level,
                    "message": message,
                })

    results = []
    for service, errors in incidents.items():
        causes = _possible_causes(errors)
        is_high_severity = (
            any(item["level"] == "CRITICAL" for item in errors)
            or len(errors) >= HIGH_SEVERITY_ERROR_THRESHOLD
        )
        severity = "HIGH" if is_high_severity else "MEDIUM"
        cause_summary = "; ".join(item["cause"] for item in causes)
        recommendations = list(dict.fromkeys(item["recommendation"] for item in causes))
        results.append({
            "service": service,
            "error_count": len(errors),
            "severity": severity,
            "possible_root_cause": cause_summary,
            "summary": f"{service} reported {len(errors)} error(s). Suspected cause(s): {cause_summary}.",
            "errors": errors,
            "recommendation": " ".join(recommendations),
            "possible_causes": causes,
            "severity_basis": "Heuristic: CRITICAL entry or at least three errors means HIGH; otherwise MEDIUM.",
        })

    # Sorting by count and then service name makes output order predictable.
    results.sort(key=lambda incident: (-incident["error_count"], incident["service"].casefold()))
    return {
        "total_lines_analyzed": total_lines,
        "malformed_line_count": malformed_line_count,
        "malformed_lines": malformed_lines,
        "malformed_lines_truncated": malformed_line_count > len(malformed_lines),
        "parsed_level_counts": dict(sorted(parsed_level_counts.items())),
        "incident_count": len(results),
        "incidents": results,
    }
