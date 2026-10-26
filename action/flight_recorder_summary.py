# Copyright 2024-2025 Gilbert Martin / IRIS Security, Inc.
"""Turn IRIS flight recorder output into a GitHub job summary and outputs.

Used by action.yml. Standard library only, so it runs on any runner Python.

    python flight_recorder_summary.py <out_dir> <threshold: none|medium|high>

Reads <out_dir>/scan.json, supply.json and threat-model.txt|.md (each optional),
appends Markdown to $GITHUB_STEP_SUMMARY, writes counts to $GITHUB_OUTPUT, and
exits 1 when a finding meets the threshold.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
THRESHOLD = {"none": 99, "medium": 2, "high": 3}


def _load(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def _cell(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render(out_dir: Path) -> tuple[str, dict]:
    scan = _load(out_dir / "scan.json")
    supply = _load(out_dir / "supply.json")
    ungoverned = scan.get("ungoverned_findings", []) or []
    governed = scan.get("governed_agents", []) or []
    findings = supply.get("findings", []) or []
    summary = supply.get("summary", {}) or {}

    severities = [f.get("severity", "LOW") for f in findings]
    severities += [u.get("risk_level", "LOW") for u in ungoverned]
    counts = {
        "high": sum(1 for s in severities if RANK.get(s, 0) >= 3),
        "medium": sum(1 for s in severities if RANK.get(s, 0) == 2),
        "ungoverned": len(ungoverned),
        "governed": len(governed),
    }

    lines = ["## IRIS Agent Flight Recorder", ""]
    lines.append(
        f"**{counts['governed']}** governed agents · **{counts['ungoverned']}** AI calls not governed by IRIS · "
        f"**{summary.get('libraries', 0)}** AI libraries · **{summary.get('models', 0)}** models · "
        f"**{summary.get('mcp_servers', 0)}** MCP servers · **{counts['high']}** high and "
        f"**{counts['medium']}** medium findings"
    )
    lines.append("")

    if ungoverned:
        lines += ["### AI calls not governed by IRIS", "", "| Risk | Where | Framework | Next step |", "|---|---|---|---|"]
        for u in ungoverned[:50]:
            lines.append(
                f"| {_cell(u.get('risk_level', ''))} | `{_cell(u.get('file_path', ''))}:{u.get('line_number', '')}` "
                f"| {_cell(u.get('framework_detected', ''))} | `{_cell(u.get('suggested_command', ''))}` |"
            )
        lines.append("")

    if findings:
        lines += ["### AI supply chain", "", "| Severity | Finding | Where | Fix |", "|---|---|---|---|"]
        for f in findings[:50]:
            lines.append(
                f"| {_cell(f.get('severity', ''))} | {_cell(f.get('title', ''))} | `{_cell(f.get('location', ''))}` "
                f"| {_cell(f.get('fix', ''))} |"
            )
        lines.append("")

    md = out_dir / "threat-model.md"
    txt = out_dir / "threat-model.txt"
    if md.exists() and md.stat().st_size:
        report = "\n".join("##" + ln if ln.startswith("#") else ln for ln in md.read_text().strip().splitlines())
        lines += ["### Threat model", "", report, ""]
    elif txt.exists() and txt.stat().st_size:
        lines += ["### Threat model", "", "```text", txt.read_text().rstrip(), "```", "",
                  "Full report with recommendations: set `license-key` (IRIS Business).", ""]

    if not (ungoverned or findings):
        lines += ["No ungoverned AI calls or supply chain findings. ✅", ""]

    lines.append("Docs: https://iris-security.github.io/iris-sdk/github-action.html")
    return "\n".join(lines) + "\n", counts


def main(argv: list[str]) -> int:
    out_dir = Path(argv[1])
    threshold = THRESHOLD.get(argv[2] if len(argv) > 2 else "none", 99)
    text, counts = render(out_dir)

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)

    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path:
        with open(output_path, "a", encoding="utf-8") as fh:
            for key, value in counts.items():
                fh.write(f"{key}={value}\n")

    worst = 3 if counts["high"] else 2 if counts["medium"] else 0
    if worst >= threshold:
        print(f"IRIS: findings at or above the fail-on threshold ({counts['high']} high, {counts['medium']} medium).",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
