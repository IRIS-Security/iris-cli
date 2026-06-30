"""Tests for IRIS command vocabulary (declare, preview, enforce, witness, certify, sentinel)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from iris_cli.main import cli
from iris_cli.preview import render_preview
from iris_cli.policy_diff import PolicyDiffResult
from iris_cli.cedar_parser import CedarDiff, CedarRule, summarize_diffs


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def agent_dir(tmp_path):
    agent = tmp_path / "governance" / "agents" / "loan-processor"
    agent.mkdir(parents=True)
    (agent / "passport.yaml").write_text(
        """
apiVersion: iris.io/v1alpha1
kind: AgentPassport
metadata:
  name: loan-processor
  agent_id: agent-123
spec:
  version: "0.1.0"
  owner: platform@apexcapital.com
  team: ai-platform
  description: Processes loan applications
  data_classification: pii
  compliance_tags:
    - colorado-ai-act
  environments:
    - dev
    - production
  is_high_risk_ai: true
"""
    )
    (agent / "policy-intent.md").write_text("# Loan processor intent\nAllows credit bureau reads.")
    (agent / "policy.cedar").write_text(
        'permit(principal, action, resource) when { context.environment == "production" };'
    )
    draft = (
        'permit(principal, action, resource) when { context.environment in ["production"] };'
    )
    (agent / "policy-draft.cedar").write_text(draft)
    return agent


class TestDeclare:
    def test_declare_creates_passport_from_plain_english(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(
            cli,
            [
                "declare",
                "--name",
                "loan-processor",
                "--owner",
                "platform@apexcapital.com",
                "--team",
                "ai-platform",
            ],
        )
        assert result.exit_code == 0
        passport = tmp_path / "governance" / "agents" / "loan-processor" / "passport.yaml"
        assert passport.exists()
        assert "loan-processor" in passport.read_text()

    def test_declare_launches_interactive_wizard(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(
            cli,
            ["declare"],
            input="loan-processor\nProcesses loans\nplatform@co.com\nai-platform\nyes\n3\ny\n",
        )
        assert result.exit_code == 0
        assert (tmp_path / "governance" / "agents" / "loan-processor" / "passport.yaml").exists()


class TestPreview:
    def test_preview_shows_risk_delta(self, runner, tmp_path, monkeypatch, agent_dir):
        monkeypatch.chdir(tmp_path)
        with patch("iris_cli.preview.run_policy_diff") as mock_diff:
            rule = CedarRule(
                type="permit",
                principal='iris::AgentPassport::"loan-processor"',
                action='iris::Action::"read"',
                resource='iris::API::"payments-api"',
                conditions=["context.environment == \"production\""],
                plain_english="Agent may call payments-api in production only",
                compliance_refs=["CO-004"],
            )
            old_rule = CedarRule(
                type="permit",
                principal='iris::AgentPassport::"loan-processor"',
                action='iris::Action::"read"',
                resource='iris::API::"payments-api"',
                conditions=[],
                plain_english="Agent may call payments-api in any environment",
                compliance_refs=["CO-004"],
            )
            diff = CedarDiff(
                status="MODIFIED",
                old_rule=old_rule,
                new_rule=rule,
                risk_delta="DECREASED",
                risk_reason="Narrower scope reduces dev/test exposure.",
                compliance_affected=["CO-004"],
            )
            mock_diff.return_value = PolicyDiffResult(
                agent="loan-processor",
                diffs=[diff],
                summary=summarize_diffs([diff]),
            )
            result = runner.invoke(cli, ["preview", "--agent", "loan-processor"])
        assert result.exit_code == 0
        assert "Risk delta" in result.output

    def test_preview_safer_change_labeled_correctly(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with patch("iris_cli.preview.run_policy_diff") as mock_diff:
            diff = CedarDiff(
                status="MODIFIED",
                old_rule=CedarRule(
                    type="permit",
                    principal="p",
                    action="a",
                    resource="r",
                    plain_english="any environment",
                ),
                new_rule=CedarRule(
                    type="permit",
                    principal="p",
                    action="a",
                    resource="r",
                    plain_english="production only",
                ),
                risk_delta="DECREASED",
                risk_reason="Narrower scope reduces dev/test exposure.",
                compliance_affected=["CO-004"],
            )
            mock_diff.return_value = PolicyDiffResult(
                agent="loan-processor",
                diffs=[diff],
                summary=summarize_diffs([diff]),
            )
            result = runner.invoke(cli, ["preview", "--agent", "loan-processor"])
        assert "SAFER" in result.output

    def test_preview_riskier_change_labeled_correctly(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with patch("iris_cli.preview.run_policy_diff") as mock_diff:
            diff = CedarDiff(
                status="ADDED",
                old_rule=None,
                new_rule=CedarRule(
                    type="permit",
                    principal="p",
                    action="read",
                    resource='iris::API::"hr-api"',
                    plain_english="Agent may read from hr-api with PII classification",
                    compliance_refs=["CO-004"],
                ),
                risk_delta="INCREASED",
                risk_reason="New data access with PII.",
                compliance_affected=["CO-004"],
            )
            mock_diff.return_value = PolicyDiffResult(
                agent="loan-processor",
                diffs=[diff],
                summary=summarize_diffs([diff]),
            )
            result = runner.invoke(cli, ["preview", "--agent", "loan-processor"])
        assert "RISKIER" in result.output


class TestEnforce:
    def test_enforce_shows_active_agents(self, runner, tmp_path, monkeypatch, agent_dir):
        monkeypatch.chdir(tmp_path)
        with patch("iris_cli.enforce._detect_drop_in", return_value="IrisOpenAI"):
            result = runner.invoke(cli, ["enforce", "--agent", "loan-processor"])
        assert result.exit_code == 0
        assert "ENFORCING" in result.output

    def test_enforce_shows_inactive_agents_with_fix(self, runner, tmp_path, monkeypatch, agent_dir):
        monkeypatch.chdir(tmp_path)
        with patch("iris_cli.enforce._detect_drop_in", return_value=None):
            result = runner.invoke(cli, ["enforce", "--agent", "loan-processor"])
        assert result.exit_code == 0
        assert "NOT ENFORCING" in result.output
        assert "IrisOpenAI" in result.output

    def test_enforce_verify_flag_runs_test_call(self, runner, tmp_path, monkeypatch, agent_dir):
        monkeypatch.chdir(tmp_path)
        with patch("iris_cli.enforce._detect_drop_in", return_value="IrisOpenAI"):
            result = runner.invoke(cli, ["enforce", "--agent", "loan-processor", "--verify"])
        assert result.exit_code == 0
        assert "Enforcement probe" in result.output


class TestWitness:
    def test_witness_shows_user_delegation_context(self, tmp_path):
        vault_dir = tmp_path / "evidence"
        agent = "apex-loan-processor"
        events_file = vault_dir / agent / "events.jsonl"
        events_file.parent.mkdir(parents=True)
        events_file.write_text(
            json.dumps(
                {
                    "timestamp": "2026-06-15T14:23:01.842000",
                    "decision": "PERMIT",
                    "action": "call",
                    "resource": "openai-api",
                    "environment": "production",
                    "acting_for_user": "alice@apexcapital.com",
                    "user_email": "alice@apexcapital.com",
                    "cost_usd": 0.023,
                }
            )
            + "\n"
        )
        from iris_cli.witness import _format_witness_event

        line = _format_witness_event(json.loads(events_file.read_text().strip()), agent)
        assert "alice@apexcapital.com" in line
        assert "0.023" in line

    def test_witness_shows_cost_per_call(self, tmp_path):
        from iris_cli.witness import _format_witness_event

        event = {
            "timestamp": "2026-06-15T14:23:01.842000",
            "decision": "PERMIT",
            "action": "call",
            "resource": "openai-api",
            "environment": "production",
            "user_email": "bob@apexcapital.com",
            "cost_usd": 0.019,
        }
        line = _format_witness_event(event, "apex-loan-processor")
        assert "$0.019" in line


class TestCertify:
    def test_certify_shows_certification_ready(self, runner, tmp_path, monkeypatch, agent_dir):
        monkeypatch.chdir(tmp_path)
        with patch("iris_cli.certify._build_result") as mock_build:
            from iris_cli.framework_test import FrameworkTestResult

            mock_build.return_value = FrameworkTestResult(
                framework="colorado-ai-act",
                agent_name="loan-processor",
                total_controls=6,
                passed_controls=6,
                failed_controls=0,
                partial_controls=0,
                not_applicable=0,
                score=1.0,
                score_percent=100,
                readiness_level="CERTIFIED_READY",
                gaps=[],
                timestamp="2026-06-15T14:23:01Z",
            )
            result = runner.invoke(
                cli,
                ["certify", "--framework", "colorado-ai-act", "--agent", "loan-processor"],
            )
        assert result.exit_code == 0
        assert "CERTIFICATION" in result.output.upper() or "Certification" in result.output


class TestSentinel:
    def test_sentinel_alerts_on_score_degradation(self, runner, tmp_path, monkeypatch, agent_dir):
        monkeypatch.chdir(tmp_path)

        class FakeChange:
            direction = "degraded"
            agent_name = "loan-processor"
            previous_score = 0.83
            current_score = 0.67
            framework = "colorado-ai-act"

        class FakeReport:
            new_violations = []
            score_changes = [FakeChange()]

            def has_degradation(self):
                return True

        class FakeDetector:
            def list_snapshots(self):
                return ["snap.json"]
            def take_snapshot(self):
                return None
            def detect_drift(self):
                return FakeReport()
            def generate_alert(self, report):
                return "score dropped"

        with patch("iris_cli.sentinel.DriftDetector", return_value=FakeDetector()):
            with patch("iris_cli.sentinel.time.sleep", side_effect=KeyboardInterrupt):
                result = runner.invoke(cli, ["sentinel", "--interval", "1"])
        assert result.exit_code == 0
        assert "ALERT" in result.output

    def test_sentinel_alerts_on_new_ungoverned_agent(self, runner, tmp_path, monkeypatch, agent_dir):
        monkeypatch.chdir(tmp_path)

        class FakeFinding:
            pass

        class FakeScan:
            ungoverned_findings = [FakeFinding(), FakeFinding()]

        class FakeReport:
            new_violations = []
            score_changes = []

            def has_degradation(self):
                return False

        class FakeDetector:
            def list_snapshots(self):
                return ["snap.json"]
            def take_snapshot(self):
                return None
            def detect_drift(self):
                return FakeReport()

        with patch("iris_cli.sentinel.DriftDetector", return_value=FakeDetector()):
            with patch("iris_cli.sentinel.CodebaseScanner") as mock_scanner:
                mock_scanner.return_value.scan_directory.return_value = FakeScan()
                with patch("iris_cli.sentinel.time.sleep", side_effect=KeyboardInterrupt):
                    result = runner.invoke(cli, ["sentinel", "--interval", "1"])
        assert "ungoverned" in result.output.lower()


class TestLegacyAliases:
    def test_legacy_commands_still_work_as_aliases(self, runner):
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        for name in ("declare", "register", "preview", "witness", "watch", "certify", "test", "sentinel"):
            assert name in result.output
