from __future__ import annotations

from typing import List

from ..models.schemas import FixSuggestion, VulnerabilityRequest


class RecommendationService:
    def __init__(self) -> None:
        self._rules = {
            "sql": FixSuggestion(
                title="Harden SQL Layer",
                description="Use parameterized queries or an ORM. Reject stacked statements and enforce allow-lists for risky keywords.",
                reference="OWASP ASVS 5.3"
            ),
            "xss": FixSuggestion(
                title="Escape Dynamic Output",
                description="Sanitize user-controlled HTML fragments, adopt a CSP, and favor framework templating helpers over manual string concatenation.",
                reference="OWASP ASVS 5.1"
            ),
            "path": FixSuggestion(
                title="Normalize File Paths",
                description="Collapse ../ sequences, restrict to approved root directories, and store secrets outside the web root.",
                reference="NIST 800-53 SI-10"
            ),
        }

    def generate(self, request: VulnerabilityRequest, prediction) -> List[FixSuggestion]:
        lowered = f"{request.url} {request.payload}".lower()
        suggestions: List[FixSuggestion] = []
        if any(token in lowered for token in ("select", "union", "sleep")):
            suggestions.append(self._rules["sql"])
        if "<script" in lowered or "onerror" in lowered:
            suggestions.append(self._rules["xss"])
        if "../" in lowered or "..\\" in lowered:
            suggestions.append(self._rules["path"])
        if not suggestions:
            suggestions.append(
                FixSuggestion(
                    title="General Hardening",
                    description="Validate input on both client and server, log rejected payloads, and keep dependency inventories up to date.",
                    reference="OWASP Top 10 2021",
                )
            )
        return suggestions
