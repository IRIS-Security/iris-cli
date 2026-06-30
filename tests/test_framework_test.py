from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from iris_cli.framework_test import _readiness_level
from iris_cli.main import cli


def _passport_yaml(
    *,
    name: str = "payment-agent",
    owner: str = "owner@example.com",
    policy_ref: str | None = "governance/agents/payment-agent/policy.cedar",
    intent_ref: str | None = "governance/agents/payment-agent/policy-intent.md",
    evidence_vault_id: str | None = "IA-payment-agent-123",
    is_high_risk_ai: bool = True,
) -> str:
    def _yaml_value(value: str | None) -> str:
        return "null" if value is None else value

    return f"""
apiVersion: iris.io/v1alpha1
kind: AgentPassport
metadata:
  name: {name}
  agent_id: 11111111-1111-1111-1111-111111111111
spec:
  version: 0.1.0
  owner: {owner}
  team: platform
  data_classification: pii
  compliance_tags:
  - colorado-ai-act
  environments:
  - dev
  policy_ref: {_yaml_value(policy_ref)}
  intent_ref: {_yaml_value(intent_ref)}
  is_high_risk_ai: {str(is_high_risk_ai).lower()}
  evidence_vault_id: {_yaml_value(evidence_vault_id)}
""".strip()


def _setup_agent(tmp_path: Path, passport: str, with_policy: bool = True, with_assessment: bool = True) -> Path:
    agent_dir = tmp_path / "governance" / "agents" / "payment-agent"
    agent_dir.mkdir(parents=True, exist_ok=True)
    (agent_dir / "passport.yaml").write_text(passport)
    if with_policy:
        (agent_dir / "policy.cedar").write_text("permit (principal, action, resource);")
    if with_assessment:
        (agent_dir / "impact-assessment.md").write_text("# Assessment")
    return agent_dir


def _write_vault_events(home: Path, agent: str, count: int, *, hitl: int = 0) -> None:
    vault_dir = home / ".iris" / "evidence" / agent
    vault_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for i in range(count):
        decision = "HITL" if i < hitl else "PERMIT"
        rows.append(
            {
                "event_id": f"e{i}",
                "timestamp": f"2026-06-0{(i % 9) + 1}T00:00:00",
                "agent_id": agent,
                "action": "call",
                "resource": "payments-api",
                "environment": "dev",
                "decision": decision,
                "violations": [],
            }
        )
    (vault_dir / "events.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + ("\n" if rows else ""))


def test_colorado_act_full_pass(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    _setup_agent(tmp_path, _passport_yaml())
    _write_vault_events(tmp_path, "payment-agent", 5)
    runner = CliRunner()
    result = runner.invoke(cli, ["test", "--framework", "colorado-ai-act", "--agent", "payment-agent", "--format", "json"], catch_exceptions=False)
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["failed_controls"] == 0
    assert payload["partial_controls"] == 0
    assert payload["score_percent"] == 100


def test_colorado_act_partial_fail(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    passport = _passport_yaml(evidence_vault_id=None)
    _setup_agent(tmp_path, passport, with_policy=False, with_assessment=False)
    runner = CliRunner()
    result = runner.invoke(cli, ["test", "--framework", "colorado-ai-act", "--agent", "payment-agent", "--format", "json"], catch_exceptions=False)
    payload = json.loads(result.output)
    assert payload["failed_controls"] >= 1
    assert payload["score_percent"] < 100


def test_nist_rmf_requires_license(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    _setup_agent(tmp_path, _passport_yaml())
    _write_vault_events(tmp_path, "payment-agent", 35, hitl=2)
    runner = CliRunner()
    result = runner.invoke(cli, ["test", "--framework", "nist-ai-rmf", "--agent", "payment-agent"])
    assert result.exit_code == 0
    assert "TOP 3 GAPS (free preview)" in result.output


def test_score_calculation_correct(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    _setup_agent(tmp_path, _passport_yaml(), with_policy=True, with_assessment=True)
    _write_vault_events(tmp_path, "payment-agent", 4)
    runner = CliRunner()
    result = runner.invoke(cli, ["test", "--framework", "nist-ai-rmf", "--agent", "payment-agent", "--format", "json"], catch_exceptions=False)
    payload = json.loads(result.output)
    assert payload["passed_controls"] == 3
    assert payload["total_controls"] == 5
    assert payload["score_percent"] == 60


def test_readiness_level_thresholds() -> None:
    assert _readiness_level(99) == "CERTIFIED_READY"
    assert _readiness_level(80) == "ADVANCED"
    assert _readiness_level(50) == "DEVELOPING"
    assert _readiness_level(49) == "INITIAL"


def test_free_tier_shows_only_top_3_gaps(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    passport = _passport_yaml(owner="", policy_ref=None, intent_ref=None, evidence_vault_id=None, is_high_risk_ai=False)
    _setup_agent(tmp_path, passport, with_policy=False, with_assessment=False)
    runner = CliRunner()
    result = runner.invoke(cli, ["test", "--framework", "nist-ai-rmf", "--agent", "payment-agent", "--format", "json"], catch_exceptions=False)
    payload = json.loads(result.output)
    assert len(payload["gaps"]) == 3
    assert payload["hidden_gap_count"] >= 1


def test_paid_tier_shows_all_gaps(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("IRIS_ALLOW_DEV_LICENSE_KEYS", "1")
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".iris").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".iris" / "license.key").write_text("IRIS-TEST-0000-0000-0001")
    passport = _passport_yaml(owner="", policy_ref=None, intent_ref=None, evidence_vault_id=None, is_high_risk_ai=False)
    _setup_agent(tmp_path, passport, with_policy=False, with_assessment=False)
    runner = CliRunner()
    result = runner.invoke(cli, ["test", "--framework", "nist-ai-rmf", "--agent", "payment-agent", "--format", "json"], catch_exceptions=False)
    payload = json.loads(result.output)
    assert len(payload["gaps"]) >= 3
    assert "hidden_gap_count" not in payload


def test_json_output_format(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    _setup_agent(tmp_path, _passport_yaml())
    _write_vault_events(tmp_path, "payment-agent", 1)
    runner = CliRunner()
    result = runner.invoke(cli, ["test", "--framework", "colorado-ai-act", "--agent", "payment-agent", "--format", "json"], catch_exceptions=False)
    payload = json.loads(result.output)
    assert payload["framework"] == "colorado-ai-act"
    assert payload["agent_name"] == "payment-agent"
    assert "timestamp" in payload


def test_gap_ranking_by_severity(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    passport = _passport_yaml(owner="", policy_ref=None, intent_ref=None, evidence_vault_id=None, is_high_risk_ai=False)
    _setup_agent(tmp_path, passport, with_policy=False, with_assessment=False)
    runner = CliRunner()
    result = runner.invoke(cli, ["test", "--framework", "nist-ai-rmf", "--agent", "payment-agent", "--format", "json"], catch_exceptions=False)
    payload = json.loads(result.output)
    severities = [g["severity"] for g in payload["gaps"]]
    assert severities == sorted(severities, key=lambda s: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(s, 9))
