import json

from click.testing import CliRunner

from iris_cli.main import cli

PASSPORT = """
metadata:
  name: helpdesk
spec:
  owner: it@acme.example
  environments: [production]
  tool_permissions:
    - tool_id: okta
      allowed_actions: [grant_app_access]
"""


import pytest


@pytest.fixture
def enterprise(monkeypatch):
    monkeypatch.setenv("IRIS_ALLOW_DEV_LICENSE_KEYS", "1")
    monkeypatch.setenv("IRIS_LICENSE_KEY", "IRIS-TEST-0000-0000-0002")


def _gov(tmp_path):
    d = tmp_path / "governance" / "agents" / "helpdesk"
    d.mkdir(parents=True)
    (d / "passport.yaml").write_text(PASSPORT)
    return tmp_path / "governance" / "agents"


def test_threat_model_json(tmp_path, enterprise):
    result = CliRunner().invoke(cli, ["threat-model", "--dir", str(_gov(tmp_path)), "--format", "json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["agents"][0]["agent"] == "helpdesk"


def test_threat_model_without_passports_explains(tmp_path):
    result = CliRunner().invoke(cli, ["threat-model", "--dir", str(tmp_path)])
    assert result.exit_code != 0 and "iris declare" in result.output


def test_engagement_report_writes_markdown(tmp_path, enterprise):
    out = tmp_path / "report.md"
    result = CliRunner().invoke(cli, [
        "engagement-report", "--dir", str(_gov(tmp_path)), "--vault-dir", str(tmp_path / "vault"),
        "--client", "Acme", "--output", str(out),
    ])
    assert result.exit_code == 0, result.output
    text = out.read_text()
    assert "Client: Acme" in text and "## Recommended next steps" in text
