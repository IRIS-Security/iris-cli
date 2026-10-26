"""iris compliance scan --from openrouter — HTTP mocked, never hits openrouter.ai."""

from __future__ import annotations

import json

import httpx
import pytest
from click.testing import CliRunner

iris_openrouter_reader = pytest.importorskip("iris_openrouter.reader")

from iris_cli.compliance_scan_cmd import compliance_scan_cmd  # noqa: E402

ACTIVITY = {
    "data": [
        {
            "date": "2026-09-28",
            "model": "openai/gpt-4.1",
            "model_permaslug": "openai/gpt-4.1-2025-04-14",
            "endpoint_id": "11111111-1111-4111-8111-111111111111",
            "provider_name": "OpenAI",
            "requests": 5,
            "prompt_tokens": 50,
            "completion_tokens": 125,
            "reasoning_tokens": 0,
            "cached_tokens": 0,
            "usage": 0.015,
            "byok_usage_inference": 0,
        }
    ]
}


def _mock(monkeypatch, status: int, body: dict) -> list[httpx.Request]:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(status, json=body)

    monkeypatch.setattr(
        iris_openrouter_reader,
        "_make_client",
        lambda timeout: httpx.Client(transport=httpx.MockTransport(handler), timeout=timeout),
    )
    return calls


def test_scan_from_openrouter_outputs_models_and_providers(monkeypatch):
    calls = _mock(monkeypatch, 200, ACTIVITY)
    monkeypatch.setenv("OPENROUTER_MANAGEMENT_KEY", "sk-or-v1-test")
    result = CliRunner().invoke(compliance_scan_cmd, ["--from", "openrouter", "--json"])
    assert result.exit_code == 0, result.output
    profile = json.loads(result.output)["profile"]
    assert profile["models"] == ["openai/gpt-4.1"]
    assert profile["providers"] == ["openai"]
    assert len(calls) == 1


def test_scan_from_openrouter_wrong_key_type_prints_iris_message(monkeypatch):
    _mock(monkeypatch, 403, {"error": {"code": 403, "message": "Only management keys can perform this operation"}})
    monkeypatch.setenv("OPENROUTER_MANAGEMENT_KEY", "sk-or-v1-inference")
    result = CliRunner().invoke(compliance_scan_cmd, ["--from", "openrouter"])
    assert result.exit_code == 1
    assert "This looks like it might be a regular OpenRouter inference key." in result.output
    assert "Only management keys can perform this operation" not in result.output


def test_scan_from_openrouter_subtitle_states_live_call(monkeypatch):
    _mock(monkeypatch, 200, ACTIVITY)
    monkeypatch.setenv("OPENROUTER_MANAGEMENT_KEY", "sk-or-v1-test")
    result = CliRunner().invoke(compliance_scan_cmd, ["--from", "openrouter"])
    assert result.exit_code == 0, result.output
    assert "live call to openrouter.ai" in result.output
    assert "Offline detection" not in result.output
