"""Tests for entitlements-aware CLI output (status, compliance check, test, entitlements)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from iris import AgentPassport
from iris_core.compliance.license import ENV_LICENSE_KEY, TEST_LICENSE_KEY
from iris_core.entitlements.display import build_entitlements_panel, build_status_tier_footer
from iris_cli.main import cli


@pytest.fixture(autouse=True)
def clear_license(monkeypatch, tmp_path):
    monkeypatch.delenv(ENV_LICENSE_KEY, raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    license_file = tmp_path / ".iris" / "license.key"
    if license_file.exists():
        license_file.unlink()
    yield


def _write_agent(tmp_path: Path, name: str = "my-agent") -> Path:
    agent_dir = tmp_path / "governance" / "agents" / name
    agent_dir.mkdir(parents=True, exist_ok=True)
    passport = AgentPassport(
        name=name,
        owner="owner@example.com",
        team="platform",
        intent_ref=f"governance/agents/{name}/policy-intent.md",
    )
    (agent_dir / "passport.yaml").write_text(passport.to_yaml())
    (agent_dir / "policy-intent.md").write_text("# intent")
    return agent_dir


def test_status_shows_current_tier(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_agent(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli, ["status"])
    assert result.exit_code == 0
    assert "YOUR PLAN: Community tier" in result.output
    assert "Colorado AI Act" in result.output
    assert "iris license activate" in result.output

    footer = build_status_tier_footer()
    assert "Community tier" in footer


def test_compliance_check_pro_bundle_shows_preview(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_agent(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli, ["compliance", "check", "--framework", "nist-ai-rmf"])
    assert result.exit_code == 1
    assert "PRO REQUIRED" in result.output
    assert "Preview (first 3 controls free)" in result.output
    assert "GV-1.1" in result.output


def test_compliance_check_pro_bundle_shows_upgrade(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_agent(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli, ["compliance", "check", "--framework", "hipaa"])
    assert "iris license activate" in result.output
    assert "https://iris.ai/pricing" in result.output
    assert "controls available with Pro license" in result.output


def test_test_command_shows_top3_in_free(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    agent_dir = _write_agent(tmp_path, "my-agent")
    (agent_dir / "passport.yaml").write_text(
        AgentPassport(name="my-agent", owner="", team="platform").to_yaml()
    )
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["test", "--framework", "hipaa", "--agent", "my-agent"],
    )
    assert result.exit_code == 0
    assert "TOP 3 GAPS (free preview)" in result.output
    assert "requires Pro for full evaluation" in result.output
    assert "HIPAA-001" in result.output


def test_test_command_shows_all_in_pro(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("IRIS_ALLOW_DEV_LICENSE_KEYS", "1")
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".iris").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".iris" / "license.key").write_text(TEST_LICENSE_KEY)
    agent_dir = _write_agent(tmp_path, "my-agent")
    (agent_dir / "passport.yaml").write_text(
        AgentPassport(name="my-agent", owner="", team="platform").to_yaml()
    )
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["test", "--framework", "nist-ai-rmf", "--agent", "my-agent", "--format", "json"],
        catch_exceptions=False,
    )
    payload = json.loads(result.output)
    assert len(payload["gaps"]) >= 3
    assert "hidden_gap_count" not in payload

    table_result = runner.invoke(
        cli,
        ["test", "--framework", "nist-ai-rmf", "--agent", "my-agent"],
    )
    assert "ALL GAPS" in table_result.output
    assert "IRIS Pro active" in table_result.output or "Business" in table_result.output


def test_entitlements_command_shows_complete_map(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli, ["entitlements"])
    assert result.exit_code == 0
    assert "IRIS Feature Entitlements" in result.output
    assert "Your plan: Community tier" in result.output
    assert "Colorado AI Act bundle" in result.output
    assert "NIST AI RMF bundle" in result.output
    assert "iris test (score + top 3 gaps)" in result.output
    assert "iris test full report" in result.output

    panel = build_entitlements_panel()
    assert "FREE (available now)" in panel
    assert "PRO (upgrade to unlock)" in panel
