"""Free tier finds the problem; Business runs the program; the engagement report is the services kit."""

import pytest
from click.testing import CliRunner

from iris_cli.main import cli

PASSPORT = "metadata:\n  name: helpdesk\nspec:\n  owner: it@acme.example\n  tool_permissions:\n" \
           "    - tool_id: okta\n      allowed_actions: [grant_app_access]\n"


@pytest.fixture
def free(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("IRIS_LICENSE_KEY", raising=False)
    d = tmp_path / "governance" / "agents" / "helpdesk"
    d.mkdir(parents=True)
    (d / "passport.yaml").write_text(PASSPORT)
    (tmp_path / "requirements.txt").write_text("openai\n")
    return tmp_path


def _run(*args):
    return CliRunner().invoke(cli, list(args))


def test_free_gets_findings(free):
    assert _run("threat-model", "--dir", str(free / "governance/agents")).exit_code == 0
    sc = _run("supply-chain", "--dir", str(free))
    assert sc.exit_code == 0 and "openai" in sc.output.lower()
    assert _run("detect", "--vault-dir", str(free / "vault")).exit_code == 0


@pytest.mark.parametrize("args", [
    ("threat-model", "--format", "md"),
    ("detect", "--format", "json"),
    ("detect", "--webhook", "https://hooks.example.com/x"),
    ("supply-chain", "--bom", "bom.json"),
    ("engagement-report",),
])
def test_paid_options_explain_the_upgrade(free, args, monkeypatch):
    monkeypatch.chdir(free)
    result = _run(*args)
    assert result.exit_code == 2
    assert "iris license activate" in result.output


def test_business_does_not_unlock_services_kit(free, monkeypatch):
    monkeypatch.chdir(free)
    monkeypatch.setenv("IRIS_ALLOW_DEV_LICENSE_KEYS", "1")
    monkeypatch.setenv("IRIS_LICENSE_KEY", "IRIS-TEST-0000-0000-0001")  # Business
    assert _run("threat-model", "--format", "md").exit_code == 0
    assert _run("engagement-report").exit_code == 2
