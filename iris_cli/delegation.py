"""iris delegation — user delegation configuration, testing, and audit log."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from iris_core.engine.cedar import CedarEngine, EvaluationContext
from iris_core.evidence.vault import EvidenceVault
from iris_core.models.passport import AgentPassport, Environment, UserContext

console = Console()


def _agent_dir(governance_dir: Path, agent: str) -> Path:
    return governance_dir / agent


def _load_passport(governance_dir: Path, agent: str) -> AgentPassport:
    passport_file = _agent_dir(governance_dir, agent) / "passport.yaml"
    if not passport_file.exists():
        console.print(f"[red]Passport not found for agent '{agent}'[/red]")
        raise SystemExit(1)
    return AgentPassport.from_yaml(passport_file.read_text())


def _load_policy(engine: CedarEngine, passport: AgentPassport, agent_dir: Path) -> None:
    policy_file = agent_dir / "policy.cedar"
    if policy_file.exists():
        engine.load_policy_file(passport.agent_id, policy_file)
    else:
        engine.load_policy(passport.agent_id, "permit(principal, action, resource);")


@click.group()
def delegation():
    """User delegation configuration and audit commands."""
    pass


@delegation.command("status")
@click.option("--agent", required=True, help="Agent name")
@click.option("--dir", "governance_dir", type=click.Path(path_type=Path), default=None)
def delegation_status(agent: str, governance_dir: Optional[Path]) -> None:
    """Show delegation configuration for an agent."""
    gov_dir = governance_dir or Path.cwd() / "governance" / "agents"
    passport = _load_passport(gov_dir, agent)

    enabled = passport.user_delegation_enabled
    scopes = passport.allowed_delegation_scopes or ["any scope permitted"]
    consent = "yes" if passport.require_user_consent_for_delegation else "no"

    lines = [
        f"Agent:           {passport.name}",
        f"Delegation:      {'enabled' if enabled else 'disabled'}",
        f"Allowed scopes:  {', '.join(scopes) if isinstance(scopes, list) else scopes}",
        f"Consent required:{consent}",
        f"Audit:           per-call (Evidence Vault)",
    ]
    console.print(Panel("\n".join(lines), title=f"Delegation — {agent}", style="blue"))


@delegation.command("test")
@click.option("--agent", required=True, help="Agent name")
@click.option("--user-id", required=True, help="Test user identifier")
@click.option("--scopes", default="", help="Comma-separated delegated scopes")
@click.option("--tool", default="crm-api", help="Tool to test against")
@click.option("--action", default="read", help="Action to test")
@click.option("--consent/--no-consent", default=True, help="Simulate user consent")
@click.option("--env", default="production", type=click.Choice(["dev", "test", "staging", "production"]))
@click.option("--dir", "governance_dir", type=click.Path(path_type=Path), default=None)
def delegation_test(
    agent: str,
    user_id: str,
    scopes: str,
    tool: str,
    action: str,
    consent: bool,
    env: str,
    governance_dir: Optional[Path],
) -> None:
    """Test a delegation scenario without executing a real call."""
    gov_dir = governance_dir or Path.cwd() / "governance" / "agents"
    agent_dir = _agent_dir(gov_dir, agent)
    passport = _load_passport(gov_dir, agent)
    engine = CedarEngine()
    _load_policy(engine, passport, agent_dir)

    delegated = [s.strip() for s in scopes.split(",") if s.strip()]
    user_ctx = UserContext(
        user_id=user_id,
        delegated_scopes=delegated,
        consent_logged=consent,
        session_id="test-session",
        idp_provider="test",
    )
    ctx = EvaluationContext(
        agent_id=passport.agent_id,
        action=action,
        resource=tool,
        resource_type="tool",
        environment=Environment(env),
        user_context=user_ctx,
        **user_ctx.evaluation_fields(),
    )
    result = engine.evaluate(passport, ctx)

    color = "green" if result.decision in ("PERMIT", "PERMIT_WITH_WARNINGS") else "red"
    console.print(
        Panel(
            f"Decision: [bold {color}]{result.decision}[/bold {color}]\n"
            f"User:     {user_id}\n"
            f"Scopes:   {delegated or ['none']}\n"
            f"Action:   {action} on {tool}\n"
            f"Env:      {env}",
            title=f"Delegation test — {agent}",
        )
    )
    for violation in result.violations:
        console.print(f"  [yellow]{violation.rule_id}[/yellow]: {violation.message}")


@delegation.command("log")
@click.option("--agent", required=True, help="Agent name")
@click.option("--user-id", default=None, help="Filter by acting user")
@click.option("--limit", default=20, show_default=True)
@click.option("--format", "output_format", default="table", type=click.Choice(["table", "json"]))
@click.option("--dir", "governance_dir", type=click.Path(path_type=Path), default=None)
@click.option("--vault-dir", type=click.Path(path_type=Path), default=None)
def delegation_log(
    agent: str,
    user_id: Optional[str],
    limit: int,
    output_format: str,
    governance_dir: Optional[Path],
    vault_dir: Optional[Path],
) -> None:
    """Show Evidence Vault entries for delegated agent actions."""
    gov_dir = governance_dir or Path.cwd() / "governance" / "agents"
    passport = _load_passport(gov_dir, agent)
    vault = EvidenceVault(agent_id=passport.agent_id, vault_dir=vault_dir)
    events = vault.get_delegation_events(limit=limit, user_id=user_id)

    if output_format == "json":
        click.echo(json.dumps(events, indent=2))
        return

    if not events:
        console.print("[yellow]No delegation events found.[/yellow]")
        return

    table = Table(title=f"Delegation log — {agent}")
    table.add_column("Timestamp")
    table.add_column("User")
    table.add_column("Tool")
    table.add_column("Action")
    table.add_column("Decision")
    for event in events:
        table.add_row(
            event.get("timestamp", "")[:19],
            event.get("acting_for_user", ""),
            event.get("tool", event.get("resource", "")),
            event.get("action", ""),
            event.get("decision", ""),
        )
    console.print(table)
