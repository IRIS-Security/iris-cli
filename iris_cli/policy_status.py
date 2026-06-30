# Copyright 2024-2025 Gilbert Martin / IRIS Security, Inc.
# All Rights Reserved. Proprietary and Confidential.
# Author:

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

from iris_cli.policy_cache import draft_paths, load_draft_meta

console = Console()


def _agent_dir(agent: str, governance_dir: Optional[Path]) -> Path:
    if governance_dir and (governance_dir / "passport.yaml").exists():
        return governance_dir
    return governance_dir or Path.cwd() / "governance" / "agents" / agent


def build_policy_status(agent: str, governance_dir: Optional[Path]) -> dict:
    gov_dir = _agent_dir(agent, governance_dir)
    passport_file = gov_dir / "passport.yaml"
    cedar_file = gov_dir / "policy.cedar"
    intent_file = gov_dir / "policy-intent.md"
    draft_file, _ = draft_paths(gov_dir)

    registered = passport_file.exists()
    policy_bound = cedar_file.exists()
    has_intent = intent_file.exists()
    policy_stale = False

    if policy_bound and has_intent:
        policy_stale = intent_file.stat().st_mtime > cedar_file.stat().st_mtime

    meta = load_draft_meta(gov_dir)
    has_draft = draft_file.exists()
    draft_backend = meta.compiler_backend if meta else None
    draft_model = meta.compiler_model if meta else None

    cedar_preview = None
    if policy_bound:
        cedar_preview = "\n".join(cedar_file.read_text().splitlines()[:8])

    next_action = None
    if not registered:
        next_action = f"Run: iris declare --name {agent}"
    elif not policy_bound:
        next_action = f"Run: iris policy compile --agent {agent}"
    elif policy_stale:
        next_action = f"Run: iris policy compile --agent {agent} (re-compile)"
    else:
        next_action = "✓ Agent is fully governed"

    return {
        "agent": agent,
        "registered": registered,
        "policy_bound": policy_bound,
        "has_intent": has_intent,
        "policy_stale": policy_stale,
        "has_draft": has_draft,
        "draft_backend": draft_backend,
        "draft_model": draft_model,
        "next_action": next_action,
        "cedar_preview": cedar_preview,
    }


def _print_status_table(status: dict) -> None:
    agent = status["agent"]
    lines = []

    if status["registered"]:
        lines.append("[green]✓ Registered[/green]          passport.yaml found")
    else:
        lines.append("[red]✗ Registered[/red]          passport.yaml missing")

    if status["policy_bound"]:
        lines.append("[green]✓ Policy bound[/green]       policy.cedar found")
    else:
        lines.append("[red]✗ Policy bound[/red]       policy.cedar missing")

    if status["has_intent"]:
        lines.append("[green]✓ Intent file[/green]        policy-intent.md found")
    else:
        lines.append("[red]✗ Intent file[/red]        policy-intent.md missing")

    if status["policy_stale"]:
        lines.append(
            "[yellow]⚠ Policy stale[/yellow]       "
            "intent is newer than cedar (run iris policy compile)"
        )

    if status["has_draft"] and status["draft_backend"]:
        lines.append(
            f"[green]✓ Draft available[/green]     "
            f"cached from {status['draft_backend']}/{status['draft_model']}"
        )
    elif status["has_draft"]:
        lines.append("[green]✓ Draft available[/green]     policy-draft.cedar cached")

    console.print(Panel("\n".join(lines), title=f"Policy Status: {agent}", style="blue"))

    if status["cedar_preview"]:
        console.print(
            Panel(
                Syntax(status["cedar_preview"], "javascript", theme="monokai", line_numbers=False),
                title="Cedar Policy Preview",
                style="dim",
            )
        )

    console.print(f"\n{status['next_action']}")


@click.command("status")
@click.option("--agent", required=True, help="Agent name")
@click.option("--dir", "governance_dir", type=Path, default=None)
@click.option(
    "--format",
    "output_format",
    default="table",
    type=click.Choice(["table", "json"]),
)
def policy_status(agent, governance_dir, output_format):
    """
    Show the current policy status for an agent.

    Answers: Is this agent governed? What policy is bound?
    Is the policy current or stale vs the intent file?

    Examples:
      iris policy status --agent payment-agent
      iris policy status --agent payment-agent --format json
    """
    status = build_policy_status(agent, governance_dir)

    if output_format == "json":
        click.echo(json.dumps(status, indent=2))
    else:
        _print_status_table(status)
