"""CLI tests for iris hitl commands."""

from __future__ import annotations

from click.testing import CliRunner
from unittest.mock import patch

from iris_cli.hitl import hitl
from iris_core.hitl.models import HITLReview, HITLStatus
from iris_core.hitl.queue import HITLQueue


def test_iris_hitl_list_shows_pending(tmp_path, monkeypatch):
    queue_path = tmp_path / "queue.jsonl"
    monkeypatch.setattr(HITLQueue, "QUEUE_PATH", queue_path)
    queue = HITLQueue(queue_path=queue_path)
    queue.submit(
        HITLReview(
            review_id="rev_cli_test01",
            agent_name="demo-agent",
            agent_id="a1",
            tool_name="tool",
            action="read",
            triggered_by_rule="test",
            risk_level="HIGH",
            environment="dev",
            created_at="2026-06-15T12:00:00Z",
            expires_at="2026-06-15T12:05:00Z",
        )
    )
    runner = CliRunner()
    result = runner.invoke(hitl, ["list"])
    assert result.exit_code == 0
    assert "rev_cli_test" in result.output or "demo-agent" in result.output


def test_iris_hitl_approve_resolves_review(tmp_path, monkeypatch):
    queue_path = tmp_path / "queue.jsonl"
    monkeypatch.setattr(HITLQueue, "QUEUE_PATH", queue_path)
    queue = HITLQueue(queue_path=queue_path)
    queue.submit(
        HITLReview(
            review_id="rev_approve01",
            agent_name="demo-agent",
            agent_id="a1",
            tool_name="tool",
            action="read",
            triggered_by_rule="test",
            risk_level="HIGH",
            environment="dev",
            created_at="2026-06-15T12:00:00Z",
            expires_at="2026-06-15T12:05:00Z",
        )
    )
    runner = CliRunner()
    with patch("iris_cli.hitl.HITLQueue", return_value=queue):
        result = runner.invoke(hitl, ["approve", "rev_approve01", "--note", "ok"])
    assert result.exit_code == 0
    assert "approved" in result.output.lower()
    assert queue.get("rev_approve01").status == HITLStatus.APPROVED


def test_iris_hitl_reject_resolves_review(tmp_path, monkeypatch):
    queue_path = tmp_path / "queue.jsonl"
    monkeypatch.setattr(HITLQueue, "QUEUE_PATH", queue_path)
    queue = HITLQueue(queue_path=queue_path)
    queue.submit(
        HITLReview(
            review_id="rev_reject01",
            agent_name="demo-agent",
            agent_id="a1",
            tool_name="tool",
            action="read",
            triggered_by_rule="test",
            risk_level="HIGH",
            environment="dev",
            created_at="2026-06-15T12:00:00Z",
            expires_at="2026-06-15T12:05:00Z",
        )
    )
    runner = CliRunner()
    with patch("iris_cli.hitl.HITLQueue", return_value=queue):
        result = runner.invoke(hitl, ["reject", "rev_reject01", "--reason", "no"])
    assert result.exit_code == 0
    assert "rejected" in result.output.lower()
    assert queue.get("rev_reject01").status == HITLStatus.REJECTED


def test_iris_hitl_test_sends_test_notification(monkeypatch, tmp_path):
    gov = tmp_path / "governance" / "agents" / "demo-agent"
    gov.mkdir(parents=True)
    gov.joinpath("passport.yaml").write_text(
        """
apiVersion: iris.io/v1alpha1
kind: AgentPassport
metadata:
  name: demo-agent
  agent_id: agent-1
spec:
  owner: test@test.com
  hitl:
    enabled: true
    timeout_seconds: 300
    timeout_policy: deny
"""
    )
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(hitl, ["test", "--agent", "demo-agent"])
    assert result.exit_code == 0
    assert "Test notification" in result.output
