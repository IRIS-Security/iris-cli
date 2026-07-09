"""CLI guardrail tests — solo-local free, org/auditor paths gated."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from iris_core.entitlements import Entitlements, Feature, Tier
from iris_core.evidence.vault import EvidenceVault
from iris_core.models.passport import AgentPassport, DataClassification


@pytest.fixture(autouse=True)
def clear_license(monkeypatch, tmp_path):
    monkeypatch.delenv("IRIS_LICENSE_KEY", raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    yield


@pytest.fixture
def gov_agent(tmp_path):
    agent_dir = tmp_path / "governance" / "agents" / "solo-agent"
    agent_dir.mkdir(parents=True)
    passport = AgentPassport(
        name="solo-agent",
        owner="dev@example.com",
        team="solo",
        data_classification=DataClassification.INTERNAL,
        evidence_vault_id="vault-solo",
    )
    (agent_dir / "passport.yaml").write_text(passport.to_yaml())
    vault = EvidenceVault("solo-agent", vault_dir=tmp_path / ".iris" / "evidence" / "solo-agent")
    vault.record_raw(
        {
            "event_type": "policy_evaluation",
            "decision": "ALLOW",
            "policy_name": "test",
            "cedar_rule": "TEST-001",
            "resource": "test",
        }
    )
    return tmp_path


def test_compliance_scan_offline_no_license():
    from iris_cli.compliance_scan_cmd import compliance_scan_cmd

    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("main.py").write_text('import openai\nopenai.ChatCompletion.create()\n')
        result = runner.invoke(compliance_scan_cmd, ["--path", "."])
    assert result.exit_code == 0, result.output


def test_personal_evidence_export_json_free(gov_agent):
    from iris_cli.evidence import evidence_export

    runner = CliRunner()
    out = gov_agent / "export.json"
    result = runner.invoke(
        evidence_export,
        [
            "--agent",
            "solo-agent",
            "--output",
            str(out),
            "--format",
            "json",
            "--dir",
            str(gov_agent / "governance" / "agents"),
            "--vault-dir",
            str(gov_agent / ".iris" / "evidence" / "solo-agent"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert out.exists()


def test_personal_evidence_export_csv_free(gov_agent):
    from iris_cli.evidence import evidence_export

    runner = CliRunner()
    out = gov_agent / "export.csv"
    result = runner.invoke(
        evidence_export,
        [
            "--agent",
            "solo-agent",
            "--output",
            str(out),
            "--format",
            "csv",
            "--dir",
            str(gov_agent / "governance" / "agents"),
            "--vault-dir",
            str(gov_agent / ".iris" / "evidence" / "solo-agent"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert out.exists()


def _assert_entitlement_blocked(result) -> None:
    assert result.exit_code != 0
    exc = result.exception
    if exc is not None:
        text = str(exc)
    else:
        text = result.output or ""
    assert any(
        token in text.lower()
        for token in (
            "pro",
            "business",
            "scm_org_scanner",
            "team_rbac",
            "cost_org_summary",
            "evidence_export_auditor",
            "iris pro feature",
        )
    ), f"expected entitlement block, got: {text!r}"


def test_auditor_oscal_export_blocked_without_business(gov_agent):
    from iris_cli.evidence import evidence_export

    runner = CliRunner()
    out = gov_agent / "audit.oscal.json"
    result = runner.invoke(
        evidence_export,
        [
            "--agent",
            "solo-agent",
            "--output",
            str(out),
            "--format",
            "oscal",
            "--dir",
            str(gov_agent / "governance" / "agents"),
            "--vault-dir",
            str(gov_agent / ".iris" / "evidence" / "solo-agent"),
        ],
    )
    _assert_entitlement_blocked(result)


def test_aiuc1_b006_export_blocked_without_business(gov_agent):
    from iris_cli.evidence import evidence_export

    runner = CliRunner()
    out = gov_agent / "aiuc1.json"
    result = runner.invoke(
        evidence_export,
        [
            "--agent",
            "solo-agent",
            "--output",
            str(out),
            "--format",
            "aiuc1",
            "--dir",
            str(gov_agent / "governance" / "agents"),
        ],
    )
    assert result.exit_code != 0


def test_scm_scan_org_blocked_without_business():
    from iris_cli.scm import scan_org

    runner = CliRunner()
    result = runner.invoke(
        scan_org,
        ["--platform", "github", "--org", "acme", "--token", "fake"],
    )
    _assert_entitlement_blocked(result)


def test_scm_scan_repo_free_with_token(monkeypatch):
    from iris_cli.scm import scan_repo

    class FakeScanner:
        def scan_repository(self, repo):
            return []

    monkeypatch.setattr(
        "iris_cli.scm._github_scanner",
        lambda *args, **kwargs: FakeScanner(),
    )
    runner = CliRunner()
    result = runner.invoke(
        scan_repo,
        ["--platform", "github", "--repo", "acme/demo", "--token", "fake"],
    )
    assert result.exit_code == 0, result.output


def test_users_first_add_free_second_blocked(gov_agent):
    from iris_cli.users import users_add

    runner = CliRunner()
    agent_dir = str(gov_agent / "governance" / "agents" / "solo-agent")
    first = runner.invoke(
        users_add,
        ["--email", "alice@co.com", "--role", "developer", "--agent", "solo-agent", "--dir", agent_dir],
    )
    assert first.exit_code == 0, first.output

    second = runner.invoke(
        users_add,
        ["--email", "bob@co.com", "--role", "developer", "--agent", "solo-agent", "--dir", agent_dir],
    )
    _assert_entitlement_blocked(second)


def test_cost_summary_blocked_without_business():
    from iris_cli.cost import cost_summary

    runner = CliRunner()
    result = runner.invoke(cost_summary, [])
    _assert_entitlement_blocked(result)


def test_cost_report_single_agent_free(monkeypatch):
    from iris_cli.cost import cost_report
    from iris_core.cost.tracker import CostSummary

    class FakeTracker:
        agent_name = "solo-agent"

        def get_summary(self, since=None):
            return CostSummary(
                agent_id="solo-agent",
                agent_name="solo-agent",
                period_start="2026-01-01",
                period_end="2026-02-01",
                total_cost_usd=1.23,
                total_calls=5,
                total_input_tokens=100,
                total_output_tokens=50,
                avg_cost_per_call=0.25,
                avg_tokens_per_call=30,
                most_expensive_call=None,
                most_expensive_tool=None,
                cost_by_model={"gpt-4o": 1.23},
                cost_by_tool={},
                cost_trend="STABLE",
                estimated_monthly_cost=10.0,
            )

    monkeypatch.setattr("iris_cli.cost._resolve_trackers", lambda agent: [FakeTracker()])
    runner = CliRunner()
    result = runner.invoke(cost_report, ["--agent", "solo-agent"])
    assert result.exit_code == 0, result.output
