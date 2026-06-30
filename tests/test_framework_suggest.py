"""Tests for iris framework suggest."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from iris_cli.main import cli


def _invoke_suggest(tmp_path: Path, answers: list[str], output_format: str = "table"):
    runner = CliRunner()
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    input_data = "\n".join(answers) + "\n"
    return runner.invoke(
        cli,
        ["framework", "suggest", "--format", output_format],
        input=input_data,
        env={"HOME": str(home)},
    )


def test_federal_user_gets_nist_and_fedramp(tmp_path):
    result = _invoke_suggest(
        tmp_path,
        answers=["2", "1", "2", "3", "n", "y", "4", "2"],
    )
    assert result.exit_code == 0, result.output
    assert "nist-ai-rmf" in result.output
    assert "fedramp" in result.output
    assert "REQUIRED" in result.output


def test_colorado_consequential_gets_colorado_act(tmp_path):
    result = _invoke_suggest(
        tmp_path,
        answers=["1", "5", "4", "5", "y", "n", "5", "1"],
    )
    assert result.exit_code == 0, result.output
    assert "colorado-ai-act" in result.output
    assert "SB 26-189" in result.output


def test_hipaa_trigger_on_health_data(tmp_path):
    result = _invoke_suggest(
        tmp_path,
        answers=["2", "3", "4", "1", "n", "n", "5", "2"],
    )
    assert result.exit_code == 0, result.output
    assert "hipaa" in result.output
    assert "REQUIRED" in result.output


def test_gdpr_trigger_on_eu_users(tmp_path):
    result = _invoke_suggest(
        tmp_path,
        answers=["3", "5", "4", "5", "n", "n", "5", "6"],
    )
    assert result.exit_code == 0, result.output
    assert "gdpr" in result.output
    assert "Required for EU users" in result.output


def test_soc2_trigger_on_b2b(tmp_path):
    result = _invoke_suggest(
        tmp_path,
        answers=["2", "6", "4", "5", "n", "n", "5", "2"],
    )
    assert result.exit_code == 0, result.output
    assert "soc2" in result.output
    assert "RECOMMENDED" in result.output


def test_free_frameworks_shown_clearly(tmp_path):
    result = _invoke_suggest(
        tmp_path,
        answers=["1", "5", "4", "5", "y", "n", "5", "1"],
    )
    assert result.exit_code == 0, result.output
    assert "FREE" in result.output
    assert "1 free framework available now." in result.output


def test_paid_frameworks_show_upgrade_path(tmp_path):
    result = _invoke_suggest(
        tmp_path,
        answers=["2", "6", "4", "5", "n", "n", "2", "2"],
    )
    assert result.exit_code == 0, result.output
    assert "frameworks require IRIS Pro" in result.output
    assert "iris license activate <your-key>" in result.output


def test_json_output_format(tmp_path):
    result = _invoke_suggest(
        tmp_path,
        answers=["2", "5", "4", "5", "n", "n", "5", "2"],
        output_format="json",
    )
    assert result.exit_code == 0, result.output
    start = result.output.find("{")
    end = result.output.rfind("}")
    payload = json.loads(result.output[start : end + 1])
    assert payload["answers"]["q2"] == "General consumers (B2C)"
    frameworks = {item["framework"] for item in payload["recommendations"]}
    assert "colorado-ai-act" in frameworks
    saved_path = Path(payload["saved_to"])
    assert saved_path.name == "framework-recommendations.json"
