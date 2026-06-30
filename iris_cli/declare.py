"""iris declare — register an agent with optional interactive wizard."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel

from iris_core.cli_timing.instrument import timed_cli_command

console = Console()

_DATA_CLASSIFICATIONS = {
    "none": "internal",
    "internal": "internal",
    "pii": "pii",
    "phi": "phi",
    "financial": "confidential",
}


def _run_framework_suggest(agent_name: str) -> None:
    console.print(f"[dim]Run: iris framework suggest --agent {agent_name}[/dim]")


def _write_agent_files(
    name: str,
    owner: str,
    team: str,
    env: tuple[str, ...],
    high_risk: bool,
    compliance_list: list[str],
    output: Path,
    description: str = "",
) -> None:
    from iris import IrisAgent, DataClassification, ComplianceTag

    data_class = DataClassification.INTERNAL
    agent = IrisAgent(
        name=name,
        owner=owner,
        team=team,
        compliance=compliance_list,
        environments=list(env),
        is_high_risk_ai=high_risk,
        policy_dir=output,
    )
    if description:
        agent.passport.description = description

    output.mkdir(parents=True, exist_ok=True)
    (output / "passport.yaml").write_text(agent.passport.to_yaml())

    intent_template = f"""# Policy Intent — {name}

> Edit this file to describe what your agent is allowed to do.
> Then run: iris compile --agent {name}

## What this agent does
{description or "[Describe the agent's purpose here]"}

## What it is allowed to access
[List the tools, APIs, and data sources this agent needs]

## What it must never do
[List explicit prohibitions]

## Compliance notes
[Any compliance-specific context]
"""
    (output / "policy-intent.md").write_text(intent_template)


def _interactive_wizard(output_dir: Optional[Path]) -> None:
    console.print(Panel("[bold]IRIS Agent Declaration[/bold]", style="blue"))

    name = click.prompt("What is this agent's name?", type=str).strip()
    description = click.prompt("What does this agent do? (plain English)", type=str).strip()
    owner = click.prompt("Who owns it? (email)", type=str).strip()
    team = click.prompt("Which team?", type=str).strip()
    high_risk = click.confirm("Does it make consequential decisions?", default=False)

    console.print("What data does it access?")
    console.print("  1. None  2. Internal only  3. PII  4. PHI  5. Financial")
    data_choice = click.prompt("Choice", type=click.IntRange(1, 5), default=2)
    data_keys = ["none", "internal", "pii", "phi", "financial"]
    data_key = data_keys[data_choice - 1]

    output = output_dir or (Path.cwd() / "governance" / "agents" / name)
    compliance_list = ["colorado-ai-act"]

    if not click.confirm(f"Write agent files to {output}?", default=True):
        console.print("[yellow]Cancelled.[/yellow]")
        return

    _write_agent_files(
        name=name,
        owner=owner,
        team=team,
        env=("dev",),
        high_risk=high_risk,
        compliance_list=compliance_list,
        output=output,
        description=description,
    )

    console.print("\n[bold]Recommended compliance tags:[/bold]")
    _run_framework_suggest(name)

    console.print(Panel(
        f"[bold green]✓ Agent declared[/bold green]\n\n"
        f"Name: [cyan]{name}[/cyan]\n"
        f"Data: {_DATA_CLASSIFICATIONS.get(data_key, 'internal')}\n"
        f"Passport: {output / 'passport.yaml'}\n\n"
        f"Next: Edit [bold]{output / 'policy-intent.md'}[/bold]\n"
        f"Then:  [bold]iris compile --agent {name}[/bold]",
        style="green",
    ))


@click.command("declare")
@click.option("--name", default=None, help="Agent identifier (kebab-case)")
@click.option("--owner", default=None, help="Owner email address")
@click.option("--team", default=None, help="Team or squad name")
@click.option("--env", multiple=True, default=None, help="Environments (repeatable)")
@click.option("--high-risk", is_flag=True, default=False, help="Flag as high-risk AI")
@click.option("--compliance", "-c", multiple=True, help="Compliance frameworks to tag")
@click.option("--dir", "output_dir", type=click.Path(path_type=Path), default=None)
@timed_cli_command("iris declare")
def declare(
    name: Optional[str],
    owner: Optional[str],
    team: Optional[str],
    env: Optional[tuple[str, ...]],
    high_risk: bool,
    compliance: tuple[str, ...],
    output_dir: Optional[Path],
) -> None:
    """
    Declare what an agent is allowed to do — creates passport.yaml and intent template.

    Run without flags for the interactive declaration wizard.

    Example:
      iris declare
      iris declare --name payment-agent --owner alice@co.com --team platform
    """
    if name is None and owner is None and team is None:
        _interactive_wizard(output_dir)
        return

    resolved_name = name or click.prompt("Agent name")
    resolved_owner = owner or click.prompt("Owner email")
    resolved_team = team or click.prompt("Team name")
    compliance_list = list(compliance) or ["colorado-ai-act"]
    env_list = tuple(env) if env else ("dev",)
    output = output_dir or (Path.cwd() / "governance" / "agents" / resolved_name)

    _write_agent_files(
        name=resolved_name,
        owner=resolved_owner,
        team=resolved_team,
        env=env_list,
        high_risk=high_risk,
        compliance_list=compliance_list,
        output=output,
    )

    console.print(Panel(
        f"[bold green]✓ Agent declared[/bold green]\n\n"
        f"Name: [cyan]{resolved_name}[/cyan]\n"
        f"Passport: {output / 'passport.yaml'}\n"
        f"Intent template: {output / 'policy-intent.md'}\n\n"
        f"Next step: Edit [bold]{output / 'policy-intent.md'}[/bold]\n"
        f"Then run:  [bold]iris compile --agent {resolved_name}[/bold]",
        style="green",
    ))
