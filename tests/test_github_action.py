"""The Marketplace Action: metadata is publishable and the summary is correct."""

import json
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "action" / "flight_recorder_summary.py"


def test_metadata_is_marketplace_ready():
    meta = yaml.safe_load((ROOT / "action.yml").read_text())
    assert meta["name"] == "IRIS Agent Flight Recorder"
    assert meta["branding"] == {"icon": "shield", "color": "red"}
    assert meta["inputs"]["command"]["default"] == "flight-recorder"
    run = next(s for s in meta["runs"]["steps"] if s.get("id") == "iris")["run"]
    assert "action/flight_recorder_summary.py" in run and SUMMARY.exists()


def _write(tmp_path, scan=None, supply=None):
    (tmp_path / "scan.json").write_text(json.dumps(scan or {}))
    (tmp_path / "supply.json").write_text(json.dumps(supply or {}))


def _run(tmp_path, threshold):
    env = {"GITHUB_STEP_SUMMARY": str(tmp_path / "s.md"), "GITHUB_OUTPUT": str(tmp_path / "o.txt"), "PATH": ""}
    return subprocess.run([sys.executable, str(SUMMARY), str(tmp_path), threshold], env=env,
                          capture_output=True, text=True)


def test_summary_counts_and_threshold(tmp_path):
    _write(tmp_path,
           scan={"governed_agents": ["a"], "ungoverned_findings": [
               {"file_path": "bot.py", "line_number": 3, "risk_level": "HIGH", "framework_detected": "openai",
                "suggested_command": "iris register --name bot"}]},
           supply={"summary": {"libraries": 1, "models": 0, "mcp_servers": 1},
                   "findings": [{"severity": "MEDIUM", "title": "Unpinned | lib", "location": "requirements.txt",
                                 "fix": "Pin it"}]})
    assert _run(tmp_path, "none").returncode == 0
    text = (tmp_path / "s.md").read_text()
    assert "IRIS Agent Flight Recorder" in text and "bot.py:3" in text and "Unpinned \\| lib" in text
    assert "high=1" in (tmp_path / "o.txt").read_text()
    assert _run(tmp_path, "high").returncode == 1


def test_clean_repo_passes(tmp_path):
    _write(tmp_path)
    assert _run(tmp_path, "high").returncode == 0
    assert "No ungoverned AI calls" in (tmp_path / "s.md").read_text()
