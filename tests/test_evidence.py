"""Tests for Evidence Vault read path and iris evidence CLI."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from click.testing import CliRunner

from iris_cli.evidence import (
    aggregate_stats,
    build_report_data,
    format_report_json,
    format_report_markdown,
)
from iris_cli.main import cli
from iris_core.evidence.vault import EvidenceVault


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
  - staging
  intent_ref: governance/agents/payment-agent/policy-intent.md
  is_high_risk_ai: true
  evidence_vault_id: IA-payment-agent-A3F2B1C4
  last_reviewed_at: '2026-05-20T07:28:24.684454'
"""


def _write_vault(vault_root: Path, agent: str, events: list, assessments: list | None = None):
    agent_dir = vault_root / agent
    agent_dir.mkdir(parents=True)
    with open(agent_dir / "events.jsonl", "w") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")
    if assessments is not None:
        with open(agent_dir / "assessments.jsonl", "w") as f:
            for assessment in assessments:
                f.write(json.dumps(assessment) + "\n")


def _sample_events(agent: str) -> list:
    return [
        {
            "event_id": "e1",
            "timestamp": "2026-05-28T10:00:00",
            "agent_id": agent,
            "action": "call",
            "resource": "payments-api",
            "environment": "dev",
            "decision": "PERMIT",
            "violations": [],
        },
        {
            "event_id": "e2",
            "timestamp": "2026-05-28T11:00:00",
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
                    "compliance_refs": [],
                }
            ],
        },
        {
            "event_id": "e3",
            "timestamp": "2026-05-28T12:00:00",
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
        {
            "event_id": "e4",
            "timestamp": "2026-05-28T13:00:00",
            "agent_id": agent,
            "action": "approve",
            "resource": "loan-decision",
            "environment": "staging",
            "decision": "HITL",
            "violations": [],
        },
    ]


@pytest.fixture
def gov_dir(tmp_path):
    agent_dir = tmp_path / "governance" / "agents" / "payment-agent"
    agent_dir.mkdir(parents=True)
    (agent_dir / "passport.yaml").write_text(PASSPORT_YAML)
    return tmp_path / "governance" / "agents"


@pytest.fixture
def vault_root(tmp_path):
    return tmp_path / "evidence"


@pytest.fixture
def populated_vault(vault_root):
    assessments = [
        {
            "assessment_id": "IA-payment-agent-A3F2B1C4",
            "agent": "payment-agent",
            "risk_level": "MEDIUM",
            "assessed_by": "iris-platform",
            "timestamp": "2026-05-20T07:28:24.684454",
            "findings_count": 2,
            "framework": "colorado-ai-act",
        }
    ]
    _write_vault(
        vault_root,
        "payment-agent",
        _sample_events("payment-agent"),
        assessments=assessments,
    )
    return vault_root


def test_vault_summary_calculates_correctly(populated_vault):
    vault = EvidenceVault(agent_id="payment-agent", vault_dir=populated_vault)
    summary = vault.get_summary(last_reviewed_at="2026-05-20T07:28:24.684454")

    assert summary.agent_id == "payment-agent"
    assert summary.total_evaluations == 4
    assert summary.total_violations == 2
    assert summary.violations_by_severity["HIGH"] == 1
    assert summary.violations_by_severity["CRITICAL"] == 1
    assert summary.violations_by_rule["IRIS-TOOL-001"] == 1
    assert summary.violations_by_rule["IRIS-XR-001"] == 1
    assert summary.most_violated_rule in ("IRIS-TOOL-001", "IRIS-XR-001")
    assert summary.compliance_pass_rate == pytest.approx(0.5)
    assert set(summary.environments_active) == {"dev", "staging"}
    assert summary.cross_region_blocks == 1
    assert summary.hitl_gates_triggered == 1
    assert summary.last_assessment_date.startswith("2026-05-20")


def test_report_includes_all_sections(gov_dir, populated_vault):
    from iris_core.models.passport import AgentPassport

    passport = AgentPassport.from_yaml((gov_dir / "payment-agent" / "passport.yaml").read_text())
    vault = EvidenceVault(agent_id="payment-agent", vault_dir=populated_vault)
    data = build_report_data("payment-agent", passport, vault)

    markdown = format_report_markdown(data)
    required_sections = [
        "## Agent Identity",
        "## Compliance Status",
        "## Evaluation Statistics",
        "## Top Violations",
        "## Impact Assessment History",
        "## Cross-Region Detection",
        "## HITL Gate Events",
        "## Annual Review",
        "## Evidence Vault Integrity",
    ]
    for section in required_sections:
        assert section in markdown

    json_report = json.loads(format_report_json(data))
    assert json_report["schema_version"] == "1.0"
    assert json_report["integrity"]["valid"] is True


def test_export_json_is_valid(gov_dir, populated_vault, tmp_path):
    runner = CliRunner()
    output = tmp_path / "audit.json"
    result = runner.invoke(
        cli,
        [
            "evidence",
            "export",
            "--agent",
            "payment-agent",
            "--output",
            str(output),
            "--dir",
            str(gov_dir),
            "--vault-dir",
            str(populated_vault),
        ],
    )
    assert result.exit_code == 0, result.output

    exported = json.loads(output.read_text())
    assert exported["agent_id"] == "payment-agent"
    assert len(exported["events"]) == 4
    assert len(exported["assessments"]) == 1
    assert exported["integrity"]["valid"] is True


def test_stats_aggregates_across_agents(gov_dir, vault_root):
    loan_dir = gov_dir / "loan-agent"
    loan_dir.mkdir()
    (loan_dir / "passport.yaml").write_text(
        PASSPORT_YAML.replace("payment-agent", "loan-agent").replace(
            "IA-payment-agent-A3F2B1C4", "IA-loan-agent-B1C2D3E4"
        )
    )

    _write_vault(
        vault_root,
        "payment-agent",
        _sample_events("payment-agent"),
        assessments=[
            {
                "assessment_id": "IA-payment-agent-A3F2B1C4",
                "timestamp": "2026-05-20T07:28:24.684454",
            }
        ],
    )
    _write_vault(
        vault_root,
        "loan-agent",
        [
            {
                "event_id": "l1",
                "timestamp": datetime.utcnow().isoformat(),
                "agent_id": "loan-agent",
                "action": "read",
                "resource": "credit-score",
                "environment": "dev",
                "decision": "DENY",
                "violations": [
                    {
                        "rule_id": "IRIS-TOOL-001",
                        "severity": "CRITICAL",
                        "message": "blocked",
                        "compliance_refs": [],
                    }
                ],
            }
        ],
    )

    stats = aggregate_stats(gov_dir, vault_root=vault_root)
    assert stats["total_agents"] == 2
    assert stats["total_evaluations_this_week"] >= 1
    assert any(r["rule_id"] == "IRIS-TOOL-001" for r in stats["top_violated_rules"])
    assert any(a["agent"] == "loan-agent" for a in stats["agents_with_critical_violations"])


def test_annual_review_deadline_calculated(gov_dir, populated_vault):
    from iris_core.models.passport import AgentPassport

    passport = AgentPassport.from_yaml((gov_dir / "payment-agent" / "passport.yaml").read_text())
    vault = EvidenceVault(agent_id="payment-agent", vault_dir=populated_vault)

    reviewed = datetime.utcnow() - timedelta(days=10)
    passport.last_reviewed_at = reviewed
    summary = vault.get_summary(last_reviewed_at=reviewed.isoformat())

    assert summary.days_until_annual_review == 355

    data = build_report_data("payment-agent", passport, vault)
    assert data["annual_review"]["status"] == "CURRENT"
    assert data["annual_review"]["days_until"] == 355

    passport.last_reviewed_at = None
    summary_no_review = vault.get_summary(last_reviewed_at=None)
    assert summary_no_review.days_until_annual_review is None

    data_overdue = build_report_data("payment-agent", passport, vault)
    assert data_overdue["annual_review"]["status"] == "OVERDUE"
