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


def test_compliance_scan_fail_on_blocker_ignores_informational_only_findings(monkeypatch):
    """SOC 2's universal Community teaser fires for every workload regardless
    of what it actually does — it must not gate --fail-on on its own, or the
    dogfood check (and every user's CI) would permanently fail."""
    runner = CliRunner()
    profile = {"providers": [], "frameworks": [], "models": [], "agent_count": 0}
    obligations = [
        {
            "severity": "blocker",
            "framework_key": "soc2",
            "recommended_action": "test",
            "triggered_by": ["universal:ai_agent_scope"],
            "informational": True,
        },
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
    assert result.exit_code == 0


def test_compliance_scan_fail_on_blocker_still_fails_on_real_findings(monkeypatch):
    """A blocker triggered by an actual detected signal (not just the
    universal teaser) must still gate --fail-on."""
    runner = CliRunner()
    profile = {"providers": [], "frameworks": [], "models": [], "agent_count": 0}
    obligations = [
        {
            "severity": "blocker",
            "framework_key": "soc2",
            "recommended_action": "test",
            "triggered_by": ["universal:ai_agent_scope", "data_categories:financial"],
            "informational": False,
        },
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
