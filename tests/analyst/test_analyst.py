from __future__ import annotations

import json
from collections.abc import AsyncIterator

import httpx
import pytest
import respx

from nazar.analyst import Analyst, OllamaBackend, PromptTemplate
from nazar.config import AnalystConfig
from nazar.core.errors import LlmError
from nazar.models import VERDICT_JSON_SCHEMA, Action, Incident, VerdictLabel
from tests.analyst.conftest import FakeBackend
from tests.conftest import FIXTURES

VALID = (FIXTURES / "model_outputs" / "valid_clean.txt").read_text()
OLLAMA = "http://ollama.test"


def _analyst(backend: FakeBackend) -> Analyst:
    return Analyst(backend, PromptTemplate.load())


async def test_first_try(incident: Incident) -> None:
    backend = FakeBackend(VALID)
    r = await _analyst(backend).triage(incident)
    assert r.valid_output and r.attempts == 1
    assert r.verdict.verdict is VerdictLabel.MALICIOUS
    assert r.prompt_version == "triage-v1" and r.model == "fake-model"


async def test_retry_then_success(incident: Incident) -> None:
    backend = FakeBackend("garbage", VALID)
    r = await _analyst(backend).triage(incident)
    assert r.valid_output and r.attempts == 2 and r.latency_ms == 20
    assert len(backend.calls[1]) == 4


async def test_retry_then_fallback(incident: Incident) -> None:
    analyst = _analyst(FakeBackend("garbage", "more garbage"))
    r = await analyst.triage(incident)
    assert not r.valid_output and r.attempts == 2
    assert r.verdict.verdict is VerdictLabel.UNKNOWN
    assert r.verdict.proposed_action is Action.NONE
    assert analyst.consecutive_invalid == 1


async def test_backend_down(incident: Incident) -> None:
    analyst = _analyst(FakeBackend(LlmError("down")))
    r = await analyst.triage(incident)
    assert not r.valid_output and r.verdict.verdict is VerdictLabel.UNKNOWN
    assert r.error == "model unavailable"


async def test_invalid_counter_alerts_and_resets(incident: Incident) -> None:
    analyst = _analyst(FakeBackend(*(["bad"] * 6), VALID))
    for _ in range(3):
        await analyst.triage(incident)
    assert analyst.output_unhealthy
    await analyst.triage(incident)
    assert analyst.consecutive_invalid == 0


@pytest.fixture
async def http() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(base_url=OLLAMA) as client:
        yield client


@respx.mock
async def test_ollama_payload_and_thinking_ignored(http: httpx.AsyncClient) -> None:
    route = respx.post(f"{OLLAMA}/api/chat").mock(
        return_value=httpx.Response(
            200,
            json={
                "model": "m",
                "message": {"role": "assistant", "content": VALID, "thinking": "secret plan"},
                "done": True,
            },
        )
    )
    backend = OllamaBackend(AnalystConfig(model="m"), http)
    result = await backend.chat([{"role": "user", "content": "x"}], VERDICT_JSON_SCHEMA)
    assert result.content == VALID and "secret plan" not in result.content
    body = json.loads(route.calls[0].request.content)
    assert body["stream"] is False and body["format"] == VERDICT_JSON_SCHEMA
    assert body["options"] == {"temperature": 0.1, "num_ctx": 4096, "num_predict": 512}
    assert "think" not in body


@respx.mock
async def test_ollama_think_option(http: httpx.AsyncClient) -> None:
    route = respx.post(f"{OLLAMA}/api/chat").mock(
        return_value=httpx.Response(200, json={"message": {"content": "{}"}})
    )
    await OllamaBackend(AnalystConfig(think=False), http).chat([], {})
    assert json.loads(route.calls[0].request.content)["think"] is False


@respx.mock
@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(500),
        httpx.Response(200, text="not json"),
        httpx.Response(200, json={"no": "message"}),
    ],
)
async def test_ollama_errors(http: httpx.AsyncClient, response: httpx.Response) -> None:
    respx.post(f"{OLLAMA}/api/chat").mock(return_value=response)
    with pytest.raises(LlmError):
        await OllamaBackend(AnalystConfig(), http).chat([], {})


@respx.mock
async def test_ollama_timeout(http: httpx.AsyncClient) -> None:
    respx.post(f"{OLLAMA}/api/chat").mock(side_effect=httpx.ReadTimeout("slow"))
    with pytest.raises(LlmError, match="timed out"):
        await OllamaBackend(AnalystConfig(), http).chat([], {})


@respx.mock
async def test_ollama_health(http: httpx.AsyncClient) -> None:
    respx.get(f"{OLLAMA}/api/version").mock(
        return_value=httpx.Response(200, json={"version": "0.12"})
    )
    respx.get(f"{OLLAMA}/api/tags").mock(
        return_value=httpx.Response(
            200, json={"models": [{"name": "hf.co/Nguuma/security-slm-unsloth-1.5b:latest"}]}
        )
    )
    h = await OllamaBackend(AnalystConfig(), http).health()
    assert h.reachable and h.model_present and h.version == "0.12"
    h2 = await OllamaBackend(AnalystConfig(model="other"), http).health()
    assert h2.reachable and not h2.model_present
