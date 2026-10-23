"""Provider-independent incident investigation advice with a local fallback."""

from typing import Protocol


class Investigator(Protocol):
    """Interface that a future approved LLM provider can implement."""

    def propose(self, incident: dict, context: str = "") -> dict:
        """Return a human-reviewable investigation proposal."""
        ...


class DeterministicInvestigator:
    """Create a reviewable plan from analyzer output without calling an LLM."""

    def propose(self, incident: dict, context: str = "") -> dict:
        facts = [
            f"Service {incident.get('service', 'unknown')} has {incident.get('error_count', 0)} error event(s).",
            f"Severity is {incident.get('severity', 'unknown')} under AutoRCA's heuristic rules.",
        ]
        for entry in incident.get("errors", []):
            facts.append(f"{entry.get('timestamp', 'unknown time')} [{entry.get('level', 'UNKNOWN')}]: {entry.get('message', '')}")

        hypotheses = incident.get("possible_causes", [])
        steps = []
        for hypothesis in hypotheses:
            for evidence in hypothesis.get("evidence", []):
                steps.append(f"Verify the signal '{evidence.get('message', '')}' against {hypothesis.get('cause', 'the suspected cause').lower()}.")
        if not steps:
            steps.append("Review the service logs around the first error and inspect recent deployments and dependencies.")
        steps.append("Share findings with the incident owner before taking any operational action.")

        return {
            "provider": "deterministic-local-fallback",
            "summary": incident.get("summary", "Incident requires review."),
            "facts": facts,
            "hypotheses": hypotheses,
            "context": context.strip(),
            "proposed_steps": list(dict.fromkeys(steps)),
            "requires_human_review": True,
            "execution_policy": "Recommendations only; no commands or remediation are executed.",
        }
