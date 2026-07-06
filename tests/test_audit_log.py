# Copyright 2024-2025 Gilbert Martin / IRIS Security, Inc.
# All Rights Reserved.
# Author: Gilbert Martin <gilbert@iris-security.io>
# IRIS CLI — Policy as Code for AI Agents — https://iris-security.io

"""Tests for iris audit-log export."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from iris_cli.audit_log import (
    _format_cef,
    _format_splunk,
    _serialize_events,
)
from iris_cli.main import cli


def _sample_event(agent: str = "billing-agent") -> dict:
    return {
        "event_id": "ev_test_001",
        "timestamp": "2026-06-01T10:00:00",
        "agent_id": agent,
        "_agent": agent,
        "action": "GetSecretValue",
        "resource": "stripe-prod-key",
        "environment": "prod",
        "decision": "DENY",
        "violations": [
            {
                "rule_id": "SecretAccessPolicy",
                "severity": "HIGH",
                "message": "Secret access denied",
                "compliance_refs": ["AIUC-1"],
            }
        ],
    }


def test_splunk_format_includes_iris_fields():
    payload = _format_splunk(_sample_event())
    assert payload["host"] == "iris-governance"
    assert payload["event"]["iris_decision"] == "DENY"
    assert payload["event"]["aarm_r5"] is False


def test_cef_format_is_single_line():
    line = _format_cef(_sample_event())
    assert line.startswith("CEF:0|IRIS Security|")
    assert "act=DENY" in line


def test_audit_log_export_json(tmp_path, monkeypatch):
    vault_root = tmp_path / "evidence"
    agent_dir = vault_root / "billing-agent"
    agent_dir.mkdir(parents=True)
    event = _sample_event()
    (agent_dir / "events.jsonl").write_text(json.dumps(event) + "\n")

    out_file = tmp_path / "audit.json"
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "audit-log",
            "export",
            "--format",
            "json",
            "--agent",
            "billing-agent",
            "--since",
            "2026-06-01",
            "--until",
            "2026-06-30",
            "--output",
            str(out_file),
            "--vault-dir",
            str(vault_root),
        ],
    )
    assert result.exit_code == 0, result.output
    data = json.loads(out_file.read_text())
    assert len(data) == 1
    assert data[0]["decision"] == "DENY"


def test_otel_export_envelope():
    body = _serialize_events([_sample_event()], "otel")
    payload = json.loads(body)
    assert "resourceSpans" in payload
    spans = payload["resourceSpans"][0]["scopeSpans"][0]["spans"]
    assert spans[0]["name"] == "iris.agent.action.deny"
