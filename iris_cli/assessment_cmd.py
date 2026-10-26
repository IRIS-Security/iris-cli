"""iris threat-model and iris engagement-report."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

console = Console()


def _governance(dir_opt: Optional[Path]) -> Path:
    return dir_opt or Path.cwd() / "governance" / "agents"


def _write(text: str, output: Optional[Path]) -> None:
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text)
        console.print(f"[green]Written:[/green] {output}")
    else:
        click.echo(text)


@click.command("threat-model")
@click.option("--agent", default=None, help="One agent name; default is every agent in the governance folder")
@click.option("--dir", "governance_dir", type=click.Path(path_type=Path), default=None,
              help="Governance folder (default: ./governance/agents)")
@click.option("--format", "fmt", type=click.Choice(["md", "json", "table"]), default="table")
@click.option("--output", type=click.Path(path_type=Path), default=None, help="Write to a file")
def threat_model_cmd(agent, governance_dir, fmt, output):
    """Threat model each agent against the OWASP LLM and Agentic Top 10.

    Reads agent passports only. A starting point for a threat modeling
    workshop, not a penetration test.

    \b
    Examples:
      iris threat-model
      iris threat-model --agent helpdesk --format md --output threat-model.md
    """
    from iris_core.assessment.engagement import load_passports
    from iris_core.assessment.threat_model import build_threat_model, to_dict, to_markdown
    from iris_core.entitlements import Feature

    from iris_cli._tiers import require

    if fmt != "table" or output:
        require(Feature.THREAT_MODEL_REPORT, "The full threat model report with recommendations")

    passports = load_passports(_governance(governance_dir))
    if agent:
        passports = [p for p in passports if p.name == agent]
    if not passports:
        raise click.ClickException(
            "No agent passports found. Run `iris declare` first, or pass --dir to your governance folder."
        )
    models = [build_threat_model(p) for p in passports]

    if fmt == "json":
        _write(json.dumps(to_dict(models), indent=2), output)
    elif fmt == "md":
        _write(to_markdown(models), output)
    else:
        for m in models:
            draft = "  ·  DRAFT passport" if m.is_draft else ""
            table = Table(title=f"{m.agent}  ·  {m.summary['High']} high, {m.summary['Medium']} medium, {m.summary['Low']} low{draft}")
            table.add_column("Rating")
            table.add_column("Risk")
            table.add_column("Why")
            for f in m.findings:
                color = {"High": "red", "Medium": "yellow", "Low": "dim"}[f.rating]
                table.add_row(f"[{color}]{f.rating}[/{color}]", f"{f.risk_id} {f.title}", "; ".join(f.why))
            console.print(table)
            if m.is_draft:
                console.print(f"[yellow]Draft: {'; '.join(m.draft_reasons)}. Edit passport.yaml to complete it.[/yellow]")
        console.print("Full report with recommendations (IRIS Business): "
                      "[bold]iris threat-model --format md --output threat-model.md[/bold]")


@click.command("engagement-report")
@click.option("--dir", "governance_dir", type=click.Path(path_type=Path), default=None,
              help="Governance folder (default: ./governance/agents)")
@click.option("--vault-dir", type=click.Path(path_type=Path), default=None,
              help="Evidence vault root (default: ~/.iris/evidence)")
@click.option("--scan", "scan_dir", type=click.Path(path_type=Path, exists=True, file_okay=False), default=None,
              help="Also scan this source folder for ungoverned AI calls")
@click.option("--client", default="", help="Client name for the report header")
@click.option("--prepared-by", default="", help="Your name or firm")
@click.option("--format", "fmt", type=click.Choice(["md", "json"]), default="md")
@click.option("--output", type=click.Path(path_type=Path), default=None, help="Write to a file")
def engagement_report_cmd(governance_dir, vault_dir, scan_dir, client, prepared_by, fmt, output):
    """Build an assessment report: inventory, threats, evidence, next steps.

    Part of the IRIS services kit (Enterprise and certified partner licenses).

    \b
    Example:
      iris engagement-report --scan . --client "Acme Health" \\
        --prepared-by "Gilbert Martin" --output acme-assessment.md
    """
    from iris_core.assessment.engagement import build_report, to_markdown
    from iris_core.entitlements import Feature

    from iris_cli._tiers import require

    require(Feature.ENGAGEMENT_REPORT, "The engagement report")

    report = build_report(
        _governance(governance_dir),
        vault_dir or Path.home() / ".iris" / "evidence",
        client=client,
        prepared_by=prepared_by,
        scan_dir=scan_dir,
    )
    if not report.agents and not report.ungoverned:
        raise click.ClickException(
            "Nothing to report: no agent passports found and no ungoverned AI found. "
            "Pass --dir to your governance folder or --scan to your source folder."
        )
    if fmt == "json":
        data = asdict(report)
        for section in data["agents"]:
            section["passport"] = {"name": section["passport"]["name"], "agent_id": section["passport"]["agent_id"],
                                   "owner": section["passport"]["owner"]}
        _write(json.dumps(data, indent=2, default=str), output)
    else:
        _write(to_markdown(report), output)
