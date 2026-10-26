"""Triage one incident with the model: retry once, then fall back to ``unknown`` (LLD 07)."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass

from nazar.analyst.backend import LlmBackend
from nazar.analyst.parser import ParseError, parse_verdict
from nazar.analyst.prompt import Messages, PromptTemplate, build_messages, repair_messages
from nazar.core.errors import LlmError
from nazar.core.log import get_logger
from nazar.models import VERDICT_JSON_SCHEMA, Incident, Verdict

log = get_logger(__name__)

INVALID_ALERT_THRESHOLD = 3


@dataclass(frozen=True)
class TriageResult:
    verdict: Verdict
    valid_output: bool
    attempts: int
    latency_ms: int | None
    model: str
    prompt_version: str
    error: str | None = None
    model_unavailable: bool = False
    """The backend was unreachable: the verdict is a placeholder, retry later."""


class Analyst:
    def __init__(self, backend: LlmBackend, template: PromptTemplate) -> None:
        self._backend = backend
        self.template = template
        self.consecutive_invalid = 0

    @property
    def model(self) -> str:
        return self._backend.model

    def _result(
        self, verdict: Verdict, valid: bool, attempts: int, latency: int | None, err: str | None
    ) -> TriageResult:
        if valid:
            self.consecutive_invalid = 0
        elif err != "model unavailable":
            self.consecutive_invalid += 1
        return TriageResult(
            verdict, valid, attempts, latency, self.model, self.template.version, err
        )

    async def triage(self, incident: Incident) -> TriageResult:
        """Never raises: any failure becomes an ``unknown`` verdict with no action."""
        messages: Messages = build_messages(self.template, incident)
        latency = 0
        try:
            first = await self._backend.chat(messages, VERDICT_JSON_SCHEMA)
            latency += first.latency_ms
            try:
                return self._result(parse_verdict(first.content), True, 1, latency, None)
            except ParseError as exc:
                log.warning(
                    "model_output_invalid", incident_id=incident.incident_id, error=str(exc)
                )
                retry = repair_messages(messages, first.content, str(exc))
            second = await self._backend.chat(retry, VERDICT_JSON_SCHEMA)
            latency += second.latency_ms
            try:
                return self._result(parse_verdict(second.content), True, 2, latency, None)
            except ParseError as exc:
                log.warning(
                    "model_output_invalid_after_retry",
                    incident_id=incident.incident_id,
                    error=str(exc),
                )
                fallback = Verdict.unknown("model output invalid; no action taken")
                return self._result(fallback, False, 2, latency, "model output invalid")
        except LlmError as exc:
            log.warning("model_unavailable", incident_id=incident.incident_id, error=str(exc))
            fallback = Verdict.unknown("model unavailable; no action taken")
            result = self._result(fallback, False, 1, None, "model unavailable")
            return dataclasses.replace(result, model_unavailable=True)

    @property
    def output_unhealthy(self) -> bool:
        return self.consecutive_invalid >= INVALID_ALERT_THRESHOLD
