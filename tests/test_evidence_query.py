# Copyright 2024-2025 Gilbert Martin / IRIS Security, Inc.
# All Rights Reserved. Proprietary and Confidential.
# Author:

"""Tests for iris evidence query command."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from iris_cli.evidence import filter_query_events
from iris_cli.main import cli

from vault_fixtures import recent_date, recent_iso


PASSPORT_YAML = """
apiVersion: iris.io/v1alpha1
kind: AgentPassport
metadata:
  name: payment-agent
  agent_id: 6684638e-582c-4be5-ad94-f6029738305f
spec:
  version: 0.1.0
  owner: gilbert.martin@gmail.com
  team: iris-platform
  data_classification: pii
  compliance_tags:
  - colorado-ai-act
  environments:
  - dev
  is_high_risk_ai: true
"""


def _write_vault(vault_root: Path, agent: str, events: list) -> None:
    agent_dir = vault_root / agent
    agent_dir.mkdir(parents=True)
    with open(agent_dir / "events.jsonl", "w") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")


def _sample_events(agent: str) -> list:
    return [
        {
            "event_id": "e1",
            "timestamp": recent_iso(days_ago=1, hour=10),
            "agent_id": agent,
            "action": "call",
            "resource": "payments-api",
            "environment": "dev",
            "decision": "PERMIT",
            "violations": [],
        },
        {
            "event_id": "e2",
            "timestamp": recent_iso(days_ago=1, hour=11),
            "agent_id": agent,
            "action": "call",
            "resource": "unknown-tool",
            "environment": "dev",
            "decision": "DENY",
            "violations": [
                {
                    "rule_id": "IRIS-TOOL-001",
                    "severity": "HIGH",
                    "message": "Tool not in declared permissions",
                    "compliance_refs": ["AIUC-1"],
                }
            ],
        },
        {
            "event_id": "e3",
            "timestamp": recent_iso(days_ago=1, hour=12),
            "agent_id": agent,
            "action": "write",
            "resource": "storage-api",
            "environment": "staging",
            "decision": "DENY",
            "violations": [
                {
                    "rule_id": "IRIS-XR-001",
                    "severity": "CRITICAL",
                    "message": "Cross-region transfer attempted",
                    "compliance_refs": ["china-pipl"],
                }
            ],
        },
    ]


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def gov_dir(tmp_path):
    agent_dir = tmp_path / "governance" / "agents" / "payment-agent"
    agent_dir.mkdir(parents=True)
    (agent_dir / "passport.yaml").write_text(PASSPORT_YAML)
    return tmp_path / "governance" / "agents"


@pytest.fixture
def vault_root(tmp_path):
    root = tmp_path / "evidence"
    _write_vault(root, "payment-agent", _sample_events("payment-agent"))
    return root


def test_query_no_results(runner, gov_dir, vault_root):
    result = runner.invoke(
        cli,
        [
            "evidence",
            "query",
            "--agent",
            "payment-agent",
            "--decision",
            "modify",
            "--dir",
            str(gov_dir),
            "--vault-dir",
            str(vault_root),
        ],
    )
    assert result.exit_code == 0
    assert "No events match the given filters" in result.output


def test_query_by_decision_deny(runner, gov_dir, vault_root):
    result = runner.invoke(
        cli,
        [
            "evidence",
            "query",
            "--agent",
            "payment-agent",
            "--decision",
            "deny",
            "--dir",
            str(gov_dir),
            "--vault-dir",
            str(vault_root),
        ],
    )
    assert result.exit_code == 0
    assert "unknow" in result.output
    assert "storag" in result.output
    assert "payments-api" not in result.output


def test_query_by_regulation(runner, gov_dir, vault_root):
    result = runner.invoke(
        cli,
        [
            "evidence",
            "query",
            "--agent",
            "payment-agent",
            "--regulation",
            "AIUC-1",
            "--dir",
            str(gov_dir),
            "--vault-dir",
            str(vault_root),
        ],
    )
    assert result.exit_code == 0
    assert "unknow" in result.output
    assert "storag" not in result.output


def test_query_json_output(runner, gov_dir, vault_root):
    result = runner.invoke(
        cli,
        [
            "evidence",
            "query",
            "--agent",
            "payment-agent",
            "--decision",
            "deny",
            "--format",
            "json",
            "--dir",
            str(gov_dir),
            "--vault-dir",
            str(vault_root),
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert isinstance(payload, list)
    assert len(payload) == 2
    assert all(item["decision"].upper() == "DENY" for item in payload)


def test_filter_query_events_unit():
    events = [
        {"timestamp": "2026-05-28T11:00:00", "decision": "DENY", "violations": []},
        {"timestamp": "2026-05-28T10:00:00", "decision": "PERMIT", "violations": []},
    ]
    filtered = filter_query_events(events, decision="deny")
    assert len(filtered) == 1
    assert filtered[0]["decision"] == "DENY"
