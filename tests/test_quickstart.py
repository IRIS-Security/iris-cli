"""Tests for iris quickstart."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from iris_cli.main import cli
from iris_cli.quickstart import (
    AGENT_NAME,
    analyze_sample_agents,
    create_workspace,
    governance_agents_dir,
    quickstart_dir,
    run_quickstart,
    sample_agent_path,
)


@pytest.fixture(autouse=True)
def isolated_home(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    for key in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("IRIS_TELEMETRY_OPT_OUT", "1")
    yield


def test_quickstart_runs_without_api_key():
    code = run_quickstart(skip_compile=True)
    assert code == 0


def test_quickstart_creates_workspace():
    create_workspace()
    root = quickstart_dir()
    assert root.is_dir()
    assert sample_agent_path().is_file()
    assert "Anthropic" in sample_agent_path().read_text()


def test_quickstart_finds_sample_agents():
    create_workspace()
    findings = analyze_sample_agents(sample_agent_path())
    assert len(findings) == 2
    names = {item["func_name"] for item in findings}
    assert names == {"answer_customer_question", "process_loan_application"}
    high_risk = [item for item in findings if item["risk_level"] == "HIGH"]
    assert len(high_risk) == 1
    assert high_risk[0]["func_name"] == "process_loan_application"


def test_quickstart_registers_agent():
    run_quickstart(skip_compile=True)
    passport = governance_agents_dir() / AGENT_NAME / "passport.yaml"
    assert passport.is_file()
    text = passport.read_text()
    assert AGENT_NAME in text
    assert "quickstart@iris.ai" in text


def test_quickstart_shows_compliance_fail():
    runner = CliRunner()
    result = runner.invoke(cli, ["quickstart", "--skip-compile"])
    assert result.exit_code == 0, result.output
    assert "FAIL" in result.output
    assert "colorado-ai-act" in result.output.lower() or "Colorado" in result.output


def test_quickstart_skip_compile_flag():
    runner = CliRunner()
    result = runner.invoke(cli, ["quickstart", "--skip-compile"])
    assert result.exit_code == 0, result.output
    assert "What iris policy compile would generate" in result.output
    assert "quickstart-loan-processor" in result.output
    assert STATIC_MARKER in result.output or "permit(" in result.output


STATIC_MARKER = 'iris::Agent::"quickstart-loan-processor"'


def test_quickstart_clean_flag_removes_workspace():
    create_workspace()
    marker = quickstart_dir() / "old-marker.txt"
    marker.write_text("stale")

    runner = CliRunner()
    result = runner.invoke(cli, ["quickstart", "--clean", "--skip-compile"])
    assert result.exit_code == 0, result.output
    assert not marker.exists()
    assert sample_agent_path().is_file()
    assert (governance_agents_dir() / AGENT_NAME / "passport.yaml").is_file()
