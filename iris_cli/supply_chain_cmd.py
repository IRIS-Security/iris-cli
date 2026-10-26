"""iris supply-chain — AI-BOM and supply chain findings."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

console = Console()


def _allowed_models(gov_dir: Path) -> list:
    from iris_core.assessment.engagement import load_passports

    models = []
    for p in load_passports(gov_dir):
        models.extend(p.allowed_models or [])
    return models


@click.command("supply-chain")
@click.option("--dir", "scan_dir", type=click.Path(path_type=Path, exists=True, file_okay=False), default=Path("."),
              help="Repository to inventory")
@click.option("--governance", "governance_dir", type=click.Path(path_type=Path), default=None,
              help="Governance folder, for approved models (default: <dir>/governance/agents)")
@click.option("--bom", "bom_path", type=click.Path(path_type=Path), default=None,
              help="Write a CycloneDX 1.6 AI-BOM to this file")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.option("--record-agent", default=None, help="Record the scan as signed evidence for this agent")
@click.option("--fail-on", type=click.Choice(["none", "medium", "high"]), default="none", show_default=True)
def supply_chain(scan_dir, governance_dir, bom_path, fmt, record_agent, fail_on):
    """Inventory AI libraries, models, and MCP servers, and flag supply chain risks.

    Offline: reads files only. Finds unpinned AI libraries, MCP servers that run
    the latest package on every start, secrets in MCP configs, plain HTTP MCP
    endpoints, unpinned or remote-code Hugging Face models, and models not
    approved in any passport.

    \b
    Examples:
      iris supply-chain
      iris supply-chain --bom ai-bom.cdx.json --fail-on high
    """
    from iris_core.entitlements import Feature
    from iris_core.supplychain.aibom import bom_hash, scan_supply_chain, to_cyclonedx, to_dict

    from iris_cli._tiers import require

    if bom_path:
        require(Feature.SUPPLY_CHAIN_AIBOM, "The CycloneDX AI-BOM (--bom)")
    if record_agent:
        require(Feature.SUPPLY_CHAIN_AIBOM, "Signed supply chain evidence (--record-agent)")

    gov = governance_dir or scan_dir / "governance" / "agents"
    report = scan_supply_chain(scan_dir, allowed_models=_allowed_models(gov) or None)
    bom = to_cyclonedx(report)
    if bom_path:
        bom_path.parent.mkdir(parents=True, exist_ok=True)
        bom_path.write_text(json.dumps(bom, indent=2))

    if fmt == "json":
        click.echo(json.dumps({**to_dict(report), "bom_sha256": bom_hash(bom)}, indent=2))
    else:
        s = report.summary
        console.print(f"[bold]AI supply chain[/bold]  ·  {s['libraries']} AI libraries, {s['models']} models, "
                      f"{s['mcp_servers']} MCP servers  ·  lockfiles: {', '.join(report.lockfiles) or 'none'}")
        if report.findings:
            table = Table(show_lines=True)
            for col in ("Severity", "Finding", "Where", "Fix"):
                table.add_column(col)
            for f in report.findings:
                style = {"HIGH": "red", "MEDIUM": "yellow"}.get(f.severity, "dim")
                table.add_row(f"[{style}]{f.severity}[/{style}]", f"{f.title}\n[dim]{f.detail}[/dim]", f.location, f.fix)
            console.print(table)
        else:
            console.print("[green]No supply chain findings.[/green]")
        if bom_path:
            console.print(f"[green]AI-BOM written:[/green] {bom_path}")

    if record_agent:
        from iris_core.evidence.index import EvidenceIndexer
        from iris_core.evidence.locate import resolve_vault_id
        from iris_core.evidence.store import EvidenceStore

        vault_root = Path.home() / ".iris" / "evidence"
        store = EvidenceStore(resolve_vault_id(record_agent, gov, vault_root), vault_dir=vault_root)
        event = store.append_event(
            event_type="supply_chain_scan", agent_name=record_agent, environment="production",
            payload={"components": len(report.components), "models": report.summary["models"],
                     "mcp_servers": report.summary["mcp_servers"], "findings_high": report.summary["HIGH"],
                     "findings_total": len(report.findings), "bom_sha256": bom_hash(bom)},
        )
        EvidenceIndexer(store).index_event(event)
        if fmt == "table":
            console.print(f"[dim]Recorded as signed evidence for {record_agent}.[/dim]")

    worst = max([{"HIGH": 3, "MEDIUM": 2, "LOW": 1}[f.severity] for f in report.findings] or [0])
    sys.exit(1 if worst >= {"none": 99, "medium": 2, "high": 3}[fail_on] else 0)
