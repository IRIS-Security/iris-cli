"""Tests for iris compliance scan --fail-on CI thresholds."""

from __future__ import annotations

from click.testing import CliRunner

from iris_cli.main import cli


def test_compliance_scan_fail_on_blocker_exits_nonzero(monkeypatch):
    runner = CliRunner()
    profile = {
        "providers": ["openai"],
        "frameworks": ["langchain"],
        "models": ["gpt-4"],
        "data_categories": ["pii"],
        "deployment_regions": ["eu"],
        "agent_count": 5,
        "autonomy_level": "autonomous",
        "customer_facing": True,
    }
    obligations = [
        {"severity": "blocker", "framework_key": "eu_ai_act", "recommended_action": "test"},
    ]

    monkeypatch.setattr(
        "iris_cli.compliance_scan_cmd.detect_workload",
        lambda path: profile,
    )
    monkeypatch.setattr(
        "iris_cli.compliance_scan_cmd.evaluate_workload_profile",
        lambda profile: obligations,
    )

    result = runner.invoke(cli, ["compliance", "scan", "--json", "--fail-on", "blocker"])
    assert result.exit_code == 1


def test_compliance_scan_fail_on_none_always_zero(monkeypatch):
    runner = CliRunner()
    profile = {"providers": [], "frameworks": [], "models": [], "agent_count": 0}
    obligations = [
        {"severity": "blocker", "framework_key": "eu_ai_act", "recommended_action": "test"},
    ]

    monkeypatch.setattr(
        "iris_cli.compliance_scan_cmd.detect_workload",
        lambda path: profile,
    )
    monkeypatch.setattr(
        "iris_cli.compliance_scan_cmd.evaluate_workload_profile",
        lambda profile: obligations,
    )

    result = runner.invoke(cli, ["compliance", "scan", "--json", "--fail-on", "none"])
    assert result.exit_code == 0
