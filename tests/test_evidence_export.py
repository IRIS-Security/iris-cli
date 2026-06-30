# Copyright 2024-2025 Gilbert Martin / IRIS Security, Inc.
# All Rights Reserved.
# Author: Gilbert Martin <gilbert@iris-security.io>
# IRIS CLI — Policy as Code for AI Agents

"""Tests for offline evidence export (Track A2)."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from iris_core.compliance.exporters.evidence_html import build_evidence_html
from iris_core.entitlements import Entitlements, Feature
from iris_core.models.passport import AgentPassport


@pytest.fixture
def payment_passport() -> AgentPassport:
    passport_file = (
        Path(__file__).resolve().parents[3]
        / "governance"
        / "agents"
        / "payment-agent"
        / "passport.yaml"
    )
    if not passport_file.exists():
        pytest.skip("payment-agent fixture not available")
    return AgentPassport.from_yaml(passport_file.read_text())


def test_build_evidence_html_offline(payment_passport, monkeypatch):
    monkeypatch.setattr(
        Entitlements,
        "has",
        lambda self, feature: feature in {
            Feature.BUNDLE_AIUC1,
            Feature.CLI_TEST_FULL_REPORT,
            Feature.CERTIFICATION_READINESS_PDF,
        },
    )
    html = build_evidence_html(
        "payment-agent",
        payment_passport,
        governance_dir=Path(__file__).resolve().parents[3] / "governance",
    )
    assert "HTML report generated" in html
    assert "AIUC-1" in html
    assert "Certification Readiness" in html


def test_evidence_export_pdf_writes_html(tmp_path, monkeypatch):
    from iris_cli.evidence import evidence_export

    monkeypatch.setattr(
        Entitlements,
        "has",
        lambda self, feature: feature in {
            Feature.BUNDLE_AIUC1,
            Feature.CLI_TEST_FULL_REPORT,
            Feature.CERTIFICATION_READINESS_PDF,
        },
    )
    runner = CliRunner()
    out = tmp_path / "report.pdf"
    gov = Path(__file__).resolve().parents[3] / "governance" / "agents"
    result = runner.invoke(
        evidence_export,
        [
            "--agent", "payment-agent",
            "--output", str(out),
            "--format", "pdf",
            "--dir", str(gov),
        ],
    )
    assert result.exit_code == 0, result.output
    html_path = out.with_suffix(".html")
    assert html_path.exists()
    assert "print to PDF" in result.output.lower() or "HTML report" in result.output
