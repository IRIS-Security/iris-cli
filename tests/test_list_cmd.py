# Copyright 2024-2025 Gilbert Martin / IRIS Security, Inc.
# All Rights Reserved. Proprietary and Confidential.
# Author:

"""
Tests for iris list command.
Copyright 2024-2025 Gilbert Martin / IRIS Security, Inc.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from iris_cli.main import cli

PASSPORT_TEMPLATE = """
name: {name}
owner: {owner}@example.com
team: platform
data_classification: internal
compliance_tags:
  - colorado-ai-act
environments:
  - dev
is_high_risk_ai: false
"""


@pytest.fixture
def runner():
    return CliRunner()


def _write_agent(gov_root: Path, name: str, governed: bool = False) -> None:
    agent_dir = gov_root / name
    agent_dir.mkdir(parents=True, exist_ok=True)
    (agent_dir / "passport.yaml").write_text(
        PASSPORT_TEMPLATE.format(name=name, owner=name)
    )
    if governed:
        (agent_dir / "policy.cedar").write_text(
            f'permit(principal == iris::AgentPassport::"{name}", action, resource);'
        )


def test_list_empty_governance_dir(runner, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(cli, ["list"])
    assert result.exit_code == 0
    assert "No agents found" in result.output


def test_list_with_agents(runner, tmp_path, monkeypatch):
    gov_root = tmp_path / "governance" / "agents"
    _write_agent(gov_root, "billing-agent")
    _write_agent(gov_root, "payment-agent")
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(cli, ["list"])
    assert result.exit_code == 0
    assert "billing-agent" in result.output
    assert "payment-agent" in result.output


def test_list_filter_ungoverned(runner, tmp_path, monkeypatch):
    gov_root = tmp_path / "governance" / "agents"
    _write_agent(gov_root, "governed-agent", governed=True)
    _write_agent(gov_root, "ungoverned-agent", governed=False)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(cli, ["list", "--filter-ungoverned"])
    assert result.exit_code == 0
    assert "ungoverned-ag" in result.output
    assert "governed-agent" not in result.output


def test_list_json_format(runner, tmp_path, monkeypatch):
    gov_root = tmp_path / "governance" / "agents"
    _write_agent(gov_root, "billing-agent")
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(cli, ["list", "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert isinstance(payload, list)
    assert len(payload) == 1
    agent = payload[0]
    for field in ("name", "owner", "team", "frameworks", "governed", "risk"):
        assert field in agent
    assert agent["name"] == "billing-agent"
