# Copyright 2024-2025 Gilbert Martin / IRIS Security, Inc.
# All Rights Reserved. Proprietary and Confidential.
# Author:
"""
iris list — list all governed agents.
Copyright 2024-2025 Gilbert Martin / IRIS Security, Inc.
All Rights Reserved.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.table import Table

from iris_core.evidence.vault import EvidenceVault, VaultSummary
from iris_core.models.passport import AgentPassport

console = Console()


def _agents_root(governance_dir: Optional[Path]) -> Path:
    base = governance_dir or Path.cwd()
    agents = base / "governance" / "agents"
    if agents.exists():
        return agents
    if any(base.glob("*/passport.yaml")) or base.name == "agents":
        return base
    return agents


def _risk_from_summary(
    summary: Optional[VaultSummary], is_high_risk: bool
) -> tuple[str, Optional[int]]:
    if summary is None:
        return ("medium" if is_high_risk else "low"), None

    critical = summary.violations_by_severity.get("CRITICAL", 0)
    high = summary.violations_by_severity.get("HIGH", 0)
    medium = summary.violations_by_severity.get("MEDIUM", 0)

    if critical > 0:
        return "critical", min(100, 75 + critical * 5)
    if high > 0:
        return "high", min(100, 55 + high * 5)
    if medium > 0 or is_high_risk:
        return "medium", 40 if is_high_risk else 30
    if summary.total_violations > 0:
        return "medium", 25
    return "low", 10


def _load_agents(
    agents_root: Path, vault_root: Optional[Path] = None
) -> List[dict]:
    records: List[dict] = []
    if not agents_root.exists():
        return records

    for passport_file in sorted(agents_root.rglob("passport.yaml")):
        try:
            passport = AgentPassport.from_yaml(passport_file.read_text())
        except Exception:
            continue

        agent_dir = passport_file.parent
        agent_name = passport.name or agent_dir.name
        governed = (agent_dir / "policy.cedar").exists()

        vault = EvidenceVault(agent_id=agent_name, vault_dir=vault_root)
        last_reviewed = (
            passport.last_reviewed_at.isoformat() if passport.last_reviewed_at else None
        )
        try:
            summary = vault.get_summary(last_reviewed_at=last_reviewed)
        except Exception:
            summary = None

        risk_level, risk_score = _risk_from_summary(summary, passport.is_high_risk_ai)
        frameworks = [t.value for t in passport.compliance_tags]
        last_reviewed_display = ""
        if passport.last_reviewed_at:
            last_reviewed_display = passport.last_reviewed_at.strftime("%Y-%m-%d")

        passing = governed and risk_level in ("low", "medium") and (
            summary is None or summary.violations_by_severity.get("CRITICAL", 0) == 0
        )

        records.append(
            {
                "name": agent_name,
                "owner": passport.owner,
                "team": passport.team,
                "frameworks": frameworks,
                "governed": governed,
                "risk": risk_level,
                "risk_score": risk_score,
                "last_reviewed": last_reviewed_display,
                "is_high_risk_ai": passport.is_high_risk_ai,
                "passing": passing,
            }
        )

    return records


def _apply_filters(
    agents: List[dict],
    filter_risk: Optional[str],
    filter_ungoverned: bool,
    filter_framework: Optional[str],
) -> List[dict]:
    filtered = agents
    if filter_risk:
        filtered = [a for a in filtered if a["risk"] == filter_risk]
    if filter_ungoverned:
        filtered = [a for a in filtered if not a["governed"]]
    if filter_framework:
        needle = filter_framework.lower()
        filtered = [
            a
            for a in filtered
            if any(needle in fw.lower() for fw in a["frameworks"])
        ]
    return filtered


def _render_table(agents: List[dict], all_agents: List[dict]) -> None:
    table = Table(title="Governed Agents")
    table.add_column("Name")
    table.add_column("Owner")
    table.add_column("Team")
    table.add_column("Frameworks")
    table.add_column("Governed")
    table.add_column("Risk")
    table.add_column("Last Reviewed", style="dim")

    for agent in agents:
        name = agent["name"]
        if agent["passing"]:
            name = f"[green]{name}[/green]"
        elif not agent["governed"]:
            name = f"[red dim]{name}[/red dim]"

        risk = agent["risk"]
        if risk == "critical":
            risk_cell = f"[bold red]{risk}[/bold red]"
        elif risk == "high":
            risk_cell = f"[yellow]{risk}[/yellow]"
        else:
            risk_cell = risk

        governed_cell = (
            "[green]yes[/green]" if agent["governed"] else "[red]no[/red]"
        )
        frameworks = ", ".join(agent["frameworks"]) or "—"
        last_reviewed = agent["last_reviewed"] or "—"

        row_style = "red dim" if not agent["governed"] else None
        table.add_row(
            name,
            agent["owner"] or "—",
            agent["team"] or "—",
            frameworks,
            governed_cell,
            risk_cell,
            last_reviewed,
            style=row_style,
        )

    console.print(table)

    total = len(all_agents)
    governed = sum(1 for a in all_agents if a["governed"])
    ungoverned = total - governed
    critical = sum(1 for a in all_agents if a["risk"] == "critical")
    console.print(
        f"\n{total} agents · {governed} governed · {ungoverned} ungoverned · "
        f"{critical} critical risk"
    )


def _render_json(agents: List[dict]) -> str:
    return json.dumps(agents, indent=2)


def _render_csv(agents: List[dict]) -> str:
    output = io.StringIO()
    fieldnames = [
        "name",
        "owner",
        "team",
        "frameworks",
        "governed",
        "risk",
        "last_reviewed",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for agent in agents:
        writer.writerow(
            {
                "name": agent["name"],
                "owner": agent["owner"],
                "team": agent["team"],
                "frameworks": ";".join(agent["frameworks"]),
                "governed": agent["governed"],
                "risk": agent["risk"],
                "last_reviewed": agent["last_reviewed"],
            }
        )
    return output.getvalue()


@click.command("list")
@click.option("--dir", "governance_dir", type=Path, default=None)
@click.option(
    "--format",
    "output_format",
    default="table",
    type=click.Choice(["table", "json", "csv"]),
)
@click.option(
    "--filter-risk",
    default=None,
    type=click.Choice(["critical", "high", "medium", "low"]),
    help="Filter by risk level",
)
@click.option(
    "--filter-ungoverned",
    is_flag=True,
    help="Show only agents with no policy.cedar bound",
)
@click.option(
    "--filter-framework",
    default=None,
    help="Filter by compliance framework tag e.g. colorado-ai-act",
)
def list_cmd(
    governance_dir,
    output_format,
    filter_risk,
    filter_ungoverned,
    filter_framework,
):
    """
    List all governed agents in the governance directory.

    The fast answer to: "what agents does IRIS know about?"

    Examples:
      iris list
      iris list --filter-ungoverned
      iris list --filter-risk critical
      iris list --format json
      iris list --format csv > agents.csv
    """
    agents_root = _agents_root(governance_dir)
    all_agents = _load_agents(agents_root)
    agents = _apply_filters(
        all_agents, filter_risk, filter_ungoverned, filter_framework
    )

    if not agents:
        if not all_agents:
            console.print("[yellow]No agents found[/yellow]")
        else:
            console.print("[yellow]No agents match the given filters.[/yellow]")
        raise SystemExit(0)

    if output_format == "json":
        click.echo(_render_json(agents))
    elif output_format == "csv":
        click.echo(_render_csv(agents))
    else:
        _render_table(agents, all_agents)
