"""Model evaluation over labelled incidents, for ``nazar test-model`` (LLD 07)."""

from __future__ import annotations

import json
import statistics
from collections.abc import Sequence
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

from nazar.analyst.analyst import Analyst
from nazar.models import Incident

EVAL_FILE = "eval_incidents.jsonl"


@dataclass(frozen=True)
class EvalCase:
    case_id: str
    incident: Incident
    verdicts: frozenset[str]
    actions: frozenset[str]


@dataclass
class EvalReport:
    model: str
    prompt_version: str
    cases: int = 0
    verdict_correct: int = 0
    action_correct: int = 0
    invalid: int = 0
    retried: int = 0
    latencies_ms: list[int] = field(default_factory=list)
    failures: list[dict[str, Any]] = field(default_factory=list)

    def _pct(self, n: int) -> float:
        return round(100.0 * n / self.cases, 1) if self.cases else 0.0

    def _latency(self, q: float) -> int | None:
        if not self.latencies_ms:
            return None
        data = sorted(self.latencies_ms)
        return data[min(len(data) - 1, round(q * (len(data) - 1)))]

    def summary(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "prompt_version": self.prompt_version,
            "cases": self.cases,
            "verdict_accuracy_pct": self._pct(self.verdict_correct),
            "action_agreement_pct": self._pct(self.action_correct),
            "invalid_output_pct": self._pct(self.invalid),
            "retry_pct": self._pct(self.retried),
            "latency_ms_p50": self._latency(0.5),
            "latency_ms_p95": self._latency(0.95),
            "latency_ms_mean": round(statistics.fmean(self.latencies_ms))
            if self.latencies_ms
            else None,
        }


def _as_set(value: str | list[str]) -> frozenset[str]:
    return frozenset([value] if isinstance(value, str) else value)


def load_cases(path: Path | None = None) -> list[EvalCase]:
    if path is None:
        text = (resources.files("nazar") / "data" / EVAL_FILE).read_text(encoding="utf-8")
    else:
        text = path.read_text(encoding="utf-8")
    cases: list[EvalCase] = []
    for n, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("//"):
            continue
        raw = json.loads(line)
        expected = raw["expected"]
        cases.append(
            EvalCase(
                case_id=str(raw.get("id", n)),
                incident=Incident.model_validate(raw["incident"]),
                verdicts=_as_set(expected["verdict"]),
                actions=_as_set(expected["action"]),
            )
        )
    return cases


async def run_eval(analyst: Analyst, cases: Sequence[EvalCase]) -> EvalReport:
    report = EvalReport(model=analyst.model, prompt_version=analyst.template.version)
    for case in cases:
        result = await analyst.triage(case.incident)
        report.cases += 1
        if not result.valid_output:
            report.invalid += 1
        if result.attempts > 1:
            report.retried += 1
        if result.latency_ms is not None:
            report.latencies_ms.append(result.latency_ms)
        verdict_ok = result.verdict.verdict.value in case.verdicts
        action_ok = result.verdict.proposed_action.value in case.actions
        report.verdict_correct += verdict_ok
        report.action_correct += action_ok
        if not (verdict_ok and action_ok):
            report.failures.append(
                {
                    "id": case.case_id,
                    "expected": {"verdict": sorted(case.verdicts), "action": sorted(case.actions)},
                    "got": {
                        "verdict": result.verdict.verdict.value,
                        "action": result.verdict.proposed_action.value,
                        "valid_output": result.valid_output,
                    },
                }
            )
    return report
