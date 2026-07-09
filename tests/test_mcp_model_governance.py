"""Tests for MCP model governance integration."""

from __future__ import annotations

from iris_cli.mcp_server import (
    handle_check_agent_code,
    handle_fix_violation,
    handle_models_status,
)


def test_mcp_flags_restricted_model_without_work_authorization(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    code = """
from iris_anthropic import IrisAnthropic
client = IrisAnthropic(passport=passport)
client.messages.create(model="claude-fable-5", messages=[])
"""
    result = handle_check_agent_code({"code": code, "workspace_path": str(tmp_path)})
    rule_ids = [v["rule_id"] for v in result["violations"]]
    assert "IRIS-MODEL-004" in rule_ids


def test_mcp_models_status_returns_registry():
    result = handle_models_status({"workspace_path": "."})
    assert "models" in result
    assert "active_directives" in result
    assert result["docs"] == "docs/MODEL_GOVERNANCE.md"


def test_mcp_fix_violation_model_rules():
    for rule_id in ("IRIS-MODEL-001", "IRIS-MODEL-004", "IRIS-MODEL-005"):
        result = handle_fix_violation({"violation_rule_id": rule_id, "code": ""})
        assert result["rule_id"] == rule_id
        assert "fix" in result
        assert result["fix"].get("explanation")
