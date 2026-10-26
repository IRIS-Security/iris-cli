"""iris trust — local trust-state visibility (observation-only, free tier)."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from iris_core.entitlements import Feature
from iris_core.models.passport import AgentPassport
from iris_core.trust.state import TrustState, compute_trust_state

console = Console()


def _gov_dir(governance_dir: Path | None) -> Path:
    return governance_dir or Path.cwd() / "governance" / "agents"


def _discover_passports(governance_dir: Path) -> dict[str, AgentPassport]:
    agents: dict[str, AgentPassport] = {}
    if not governance_dir.exists():
        return agents
    for passport_file in sorted(governance_dir.rglob("passport.yaml")):
        try:
            passport = AgentPassport.from_yaml(passport_file.read_text())
            if passport.name:
                agents[passport.name] = passport
        except Exception:
            continue
    return agents


def _quarantine_label(passport: AgentPassport, state: TrustState) -> str:
    config = passport.trust_state_config
    on_quarantine = config.on_quarantine if config else "off"
    if on_quarantine == "off" or state == TrustState.TRUSTED:
        return "—"
    if not passport.has_feature(Feature.TRUST_QUARANTINE):
        return "Pro required"
    return f"ENFORCED ({on_quarantine})"


def _push_trust_state(passport: AgentPassport, result) -> None:
    import os

    api_key = os.environ.get("IRIS_API_KEY") or os.environ.get("IRIS_CLOUD_API_KEY")
    base_url = os.environ.get("IRIS_API_URL", "http://localhost:8000")
    if not api_key:
        console.print("[yellow]Set IRIS_API_KEY to push trust-state evidence to cloud.[/yellow]")
        return
    import httpx

    quarantine_label = _quarantine_label(passport, result.state)
    payload = {
        "agent_id": passport.agent_id,
        "agent_name": passport.name,
        "trust_state": result.state.value,
        "reason": result.reason,
        "violation_count": result.violation_count,
        "hitl_denial_count": result.hitl_denial_count,
        "quarantined": result.state != TrustState.TRUSTED,
        "quarantine_decision": quarantine_label if quarantine_label.startswith("ENFORCED") else None,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }
    response = httpx.post(
        f"{base_url.rstrip('/')}/trust/push",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json=payload,
        timeout=30,
    )
    if response.status_code >= 400:
        console.print(f"[red]Push failed ({response.status_code}): {response.text}[/red]")
        return
    console.print(f"[green]Trust state pushed to IRIS Cloud for {passport.name}.[/green]")


@click.group()
def trust():
    """Local trust-state visibility — governance signals, not threat detection."""
    pass


@trust.command("status")
@click.argument("agent", required=False)
@click.option("--dir", "governance_dir", type=click.Path(path_type=Path), default=None)
@click.option("--format", "output_format", default="table", type=click.Choice(["table", "json"]))
@click.option("--push", "push", is_flag=True, help="POST trust-state evidence to IRIS Cloud when IRIS_API_KEY is set")
def trust_status(
    agent: Optional[str], governance_dir: Optional[Path], output_format: str, push: bool
) -> None:
    """Show the computed trust state for one or all agents.

    Trust state is a rolling-window read on already-recorded governance
    signals (violations, HITL denials) — observation-only, it never blocks
    a call. Requires `trust.enabled: true` in the agent's passport.yaml.
    """
    passports = _discover_passports(_gov_dir(governance_dir))
    if agent:
        passports = {k: v for k, v in passports.items() if k == agent}
        if not passports:
            console.print(f"[yellow]No agent named '{agent}' found under governance/.[/yellow]")
            sys.exit(1)

    configured = {
        name: p for name, p in passports.items()
        if p.trust_state_config and p.trust_state_config.enabled
    }
    if not configured:
        console.print("[yellow]No agents have trust tracking enabled.[/yellow]")
        console.print("Add `trust: {enabled: true}` to an agent's passport.yaml to enable it.")
        return

    results = {
        name: compute_trust_state(p.agent_id, p.trust_state_config)
        for name, p in configured.items()
    }

    if push:
        for name, result in results.items():
            _push_trust_state(configured[name], result)

    if output_format == "json":
        payload = [
            {
                "agent_name": name,
                "trust_state": result.state.value,
                "reason": result.reason,
                "violation_count": result.violation_count,
                "hitl_denial_count": result.hitl_denial_count,
                "quarantine": _quarantine_label(configured[name], result.state),
            }
            for name, result in results.items()
        ]
        click.echo(json.dumps(payload, indent=2))
        return

    table = Table(title="IRIS Trust State")
    table.add_column("Agent")
    table.add_column("State")
    table.add_column("Quarantine")
    table.add_column("Reason")

    state_style = {"trusted": "green", "degraded": "yellow", "suspect": "red"}
    for name, result in sorted(results.items()):
        style = state_style.get(result.state.value, "white")
        quarantine = _quarantine_label(configured[name], result.state)
        table.add_row(
            name,
            f"[{style}]{result.state.value.upper()}[/{style}]",
            quarantine,
            result.reason,
        )

    console.print(table)
