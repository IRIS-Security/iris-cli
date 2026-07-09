"""iris hitl — human-in-the-loop review commands."""

from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
import yaml
from rich.console import Console
from rich.table import Table

from iris import AgentPassport
from iris_core.hitl.models import HITLConfig, HITLConditionRule, HITLStatus
from iris_core.hitl.notifier import HITLNotifier
from iris_core.hitl.queue import HITLQueue

console = Console()


def _reviewer() -> str:
    return os.environ.get("IRIS_USER_EMAIL", "local-reviewer")


def _gov_dir() -> Path:
    return Path.cwd() / "governance" / "agents"


def _load_passport(agent: str) -> AgentPassport:
    path = _gov_dir() / agent / "passport.yaml"
    if not path.exists():
        raise click.ClickException(f"No passport found for agent '{agent}' at {path}")
    return AgentPassport.from_yaml(path.read_text())


def _save_hitl_config(agent: str, config: HITLConfig) -> Path:
    path = _gov_dir() / agent / "passport.yaml"
    data = yaml.safe_load(path.read_text())
    data.setdefault("spec", {})["hitl"] = config.to_dict()
    path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))
    return path


def _time_remaining(expires_at: str) -> str:
    try:
        expiry = datetime.fromisoformat(expires_at.replace("Z", ""))
        delta = expiry - datetime.utcnow()
        seconds = int(delta.total_seconds())
        if seconds <= 0:
            return "expired"
        minutes, secs = divmod(seconds, 60)
        return f"{minutes}m {secs}s"
    except ValueError:
        return "unknown"


@click.group()
def hitl():
    """Human-in-the-loop review commands."""
    pass


@hitl.command("list")
@click.option("--agent", default=None, help="Filter by agent name")
@click.option("--status", default="pending", type=click.Choice(["pending", "all"]))
def hitl_list(agent: Optional[str], status: str):
    """List pending HITL reviews."""
    queue = HITLQueue()
    if status == "pending":
        reviews = queue.list_pending(agent_name=agent)
    else:
        reviews = queue.list_all(agent_name=agent)

    console.print(
        "┌─ IRIS Pending Reviews ────────────────────────────────────────┐"
    )
    console.print(
        f"│ {len(reviews)} review(s) awaiting human decision"
        f"{' ' * max(0, 44 - len(str(len(reviews))))}│"
    )
    console.print(
        "└───────────────────────────────────────────────────────────────┘"
    )

    if not reviews:
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("ID")
    table.add_column("Agent")
    table.add_column("Risk")
    table.add_column("Action")
    table.add_column("Expires")
    for review in reviews:
        table.add_row(
            review.review_id[:14],
            review.agent_name[:20],
            review.risk_level,
            f"{review.tool_name[:12]}-{review.action[:8]}",
            _time_remaining(review.expires_at),
        )
    console.print(table)


@hitl.command("approve")
@click.argument("review_id")
@click.option("--note", default=None, help="Approval reason")
def hitl_approve(review_id: str, note: Optional[str]):
    """Approve a pending review."""
    queue = HITLQueue()
    reviewer = _reviewer()
    review = queue.resolve(review_id, HITLStatus.APPROVED, reviewer, reviewer_note=note)
    console.print(f"[green]✓[/green] Review {review_id} approved by {reviewer}")
    if note:
        console.print(f"  Note: \"{note}\"")
    if review.approval_token:
        console.print(f"  Approval token: {review.approval_token[:32]}...")
    console.print("  Logged to Evidence Vault.")
    console.print("  The waiting agent call will now proceed.")


@hitl.command("reject")
@click.argument("review_id")
@click.option("--reason", default=None, help="Rejection reason")
def hitl_reject(review_id: str, reason: Optional[str]):
    """Reject a pending review."""
    queue = HITLQueue()
    reviewer = _reviewer()
    queue.resolve(review_id, HITLStatus.REJECTED, reviewer, reviewer_note=reason)
    console.print(f"[red]✗[/red] Review {review_id} rejected by {reviewer}")
    if reason:
        console.print(f"  Reason: \"{reason}\"")
    console.print("  The waiting agent call will raise IrisViolationError.")
    console.print("  Logged to Evidence Vault.")


@hitl.command("escalate")
@click.argument("review_id")
@click.option("--to", "escalate_to", default=None, help="Escalate to email")
@click.option("--note", default=None, help="Escalation reason")
def hitl_escalate(review_id: str, escalate_to: Optional[str], note: Optional[str]):
    """Escalate a review to a senior reviewer."""
    queue = HITLQueue()
    reviewer = _reviewer()
    review = queue.resolve(
        review_id,
        HITLStatus.ESCALATED,
        reviewer,
        reviewer_note=note or f"Escalated to {escalate_to or 'senior reviewer'}",
    )
    console.print(f"[yellow]⬆[/yellow] Review {review_id} escalated by {reviewer}")
    if note:
        console.print(f"  Note: \"{note}\"")


@hitl.command("show")
@click.argument("review_id")
def hitl_show(review_id: str):
    """Show full detail for a review."""
    queue = HITLQueue()
    review = queue.get(review_id)
    if not review:
        raise click.ClickException(f"Review not found: {review_id}")
    for key, value in review.to_dict().items():
        console.print(f"[bold]{key}:[/bold] {value}")


@hitl.command("config")
@click.option("--agent", required=True)
def hitl_config(agent: str):
    """Show HITL configuration for an agent."""
    passport = _load_passport(agent)
    config = passport.hitl_config or HITLConfig()
    console.print(f"HITL for [cyan]{agent}[/cyan]: enabled={config.enabled}")
    console.print(f"  Timeout: {config.timeout_seconds}s · Policy: {config.timeout_policy}")
    console.print(f"  Condition rules: {len(config.condition_rules)}")


@hitl.command("setup")
@click.option("--agent", required=True)
def hitl_setup(agent: str):
    """Interactive wizard to configure HITL for an agent."""
    passport = _load_passport(agent)
    config = passport.hitl_config or HITLConfig()

    enabled = click.confirm(f"Enable HITL for {agent}?", default=True)
    config.enabled = enabled
    config.timeout_seconds = click.prompt("Timeout if no response (seconds)", default=300, type=int)
    config.timeout_policy = click.prompt(
        "On timeout — deny or approve?",
        default="deny",
        type=click.Choice(["deny", "approve", "escalate"]),
    )
    config.escalation_seconds = click.prompt(
        "Escalate after how many seconds?", default=180, type=int
    )

    console.print(
        "\nDeclare which specific actions require human review.\n"
        "HITL only fires when one of these rules matches.\n"
    )
    rules: list[HITLConditionRule] = []
    while click.confirm("Add a condition rule?", default=len(rules) == 0):
        condition = click.prompt("Condition (e.g. loan_amount > 50000)")
        reason = click.prompt("Reason shown to reviewer")
        channel = click.prompt(
            "Notification channel",
            default="all",
            type=click.Choice(["slack", "email", "pagerduty", "all"]),
        )
        rules.append(HITLConditionRule(condition=condition, reason=reason, notify_channel=channel))
    config.condition_rules = rules

    console.print(
        "\nRisk tiers — gate the clearly-irreversible, auto-allow the routine.\n"
        "Leave any of these blank to skip; an empty list never triggers HITL.\n"
    )
    if click.confirm("Require HITL for specific violation severities?", default=False):
        levels = click.prompt(
            "Severities (comma-separated, e.g. CRITICAL,HIGH)", default="CRITICAL"
        )
        config.required_for_risk_levels = [
            lvl.strip().upper() for lvl in levels.split(",") if lvl.strip()
        ]
    if click.confirm(
        "Require HITL for specific actions in staging/production (e.g. write, delete)?",
        default=False,
    ):
        actions = click.prompt("Actions (comma-separated)", default="write,delete")
        config.step_up_actions = [a.strip() for a in actions.split(",") if a.strip()]
    if click.confirm(
        "Require HITL for specific data classifications (e.g. phi, pii)?", default=False
    ):
        classes = click.prompt("Data classifications (comma-separated)", default="phi,pii")
        config.sensitive_data_classifications = [
            c.strip() for c in classes.split(",") if c.strip()
        ]
    config.step_up_on_intent_drift = click.confirm(
        "Require HITL when an action drifts outside the agent's declared intent?",
        default=False,
    )

    if click.confirm("Configure Slack webhook URL (Pro)?", default=False):
        config.slack_webhook_url = click.prompt("Slack webhook URL", default="")
    if click.confirm("Configure email recipients (Pro)?", default=False):
        emails = click.prompt("Email recipients (comma-separated)", default="")
        config.email_recipients = [e.strip() for e in emails.split(",") if e.strip()]

    path = _save_hitl_config(agent, config)
    console.print(f"[green]✓[/green] HITL configured for {agent}")
    console.print(f"[green]✓[/green] {len(rules)} condition rule(s) declared")
    if config.required_for_risk_levels:
        console.print(f"[green]✓[/green] Step-up on severities: {config.required_for_risk_levels}")
    if config.step_up_actions:
        console.print(f"[green]✓[/green] Step-up on actions: {config.step_up_actions}")
    if config.sensitive_data_classifications:
        console.print(f"[green]✓[/green] Step-up on data classifications: {config.sensitive_data_classifications}")
    if config.step_up_on_intent_drift:
        console.print("[green]✓[/green] Step-up on intent drift: enabled")
    console.print("[green]✓[/green] HITL fires ONLY for what you declared above — everything else auto-allows")
    console.print(f"[green]✓[/green] Saved to {path}")


@hitl.command("rules")
@click.option("--agent", required=True)
def hitl_rules(agent: str):
    """Show what will and will not trigger HITL."""
    passport = _load_passport(agent)
    config = passport.hitl_config or HITLConfig()
    console.print(f"┌─ HITL Rules — {agent} ──────────────────────────┐")
    console.print(
        f"│ Status: {'enabled' if config.enabled else 'disabled'} · "
        f"Timeout: {config.timeout_seconds}s · On timeout: {config.timeout_policy}          │"
    )
    console.print("└───────────────────────────────────────────────────────────────┘")

    if config.condition_rules:
        console.print(f"\nWILL trigger HITL — declared condition rules ({len(config.condition_rules)}):")
        for rule in config.condition_rules:
            console.print(f"\n● {rule.condition}")
            console.print(f"  Reason: {rule.reason}")
            console.print(f"  Channel: {rule.notify_channel}")

    cedar_rules = _parse_cedar_hitl_annotations(passport)
    if cedar_rules:
        console.print(f"\nWILL trigger HITL — Cedar annotations ({len(cedar_rules)}):")
        for entry in cedar_rules:
            console.print(f"\n● {entry['summary']}")
            console.print(f"  Reason: {entry['reason']}")
            console.print("  Channel: All channels")

    if config.required_for_risk_levels:
        console.print(
            f"\nWILL trigger HITL — violation severity in "
            f"{config.required_for_risk_levels}:"
        )
        console.print(
            "● Any policy violation at these severities steps up instead of "
            "logging silently or auto-denying"
        )

    if config.step_up_actions:
        console.print(f"\nWILL trigger HITL — declared step-up actions in staging/production:")
        console.print(f"● {config.step_up_actions}")

    if config.sensitive_data_classifications:
        console.print(
            f"\nWILL trigger HITL — sensitive data classifications:"
        )
        console.print(f"● {config.sensitive_data_classifications}")

    if config.step_up_on_intent_drift:
        console.print(
            "\nWILL trigger HITL — action drifts outside the agent's declared "
            "intent (semantic distance > 0.7)"
        )

    console.print("\nWILL NOT trigger HITL — everything else:")
    console.print("✗ Calls with no matching condition rule → automatic")
    if not config.required_for_risk_levels:
        console.print("✗ Risk level alone → never triggers HITL (declare required_for_risk_levels to change this)")
    if not config.sensitive_data_classifications:
        console.print("✗ Data classification alone → never triggers HITL (declare sensitive_data_classifications to change this)")
    console.print("\nRun: iris hitl test --agent {agent} to verify.")


def _parse_cedar_hitl_annotations(passport: AgentPassport) -> list[dict]:
    if not passport.policy_ref:
        return []
    path = Path(passport.policy_ref)
    if not path.is_absolute():
        path = Path.cwd() / path
    if not path.exists():
        return []
    text = path.read_text()
    entries = []
    pattern = re.compile(
        r"permit\s*\((.*?)\).*?annotations\s*\{([^}]*)\}",
        re.DOTALL | re.IGNORECASE,
    )
    for idx, match in enumerate(pattern.finditer(text), start=1):
        header, ann = match.group(1), match.group(2)
        if 'hitl_required' not in ann:
            continue
        reason_match = re.search(r'hitl_reason\s*=\s*"([^"]+)"', ann)
        resource_match = re.search(r'resource\s*==\s*iris::API::"([^"]+)"', header)
        resource = resource_match.group(1) if resource_match else "unknown"
        entries.append(
            {
                "summary": f"policy.cedar line ~{idx}: {resource} › call",
                "reason": reason_match.group(1) if reason_match else "Cedar annotation",
            }
        )
    return entries


@hitl.command("test")
@click.option("--agent", required=True)
def hitl_test(agent: str):
    """Send a test HITL notification (no real pending review)."""
    passport = _load_passport(agent)
    config = passport.hitl_config or HITLConfig(enabled=True)
    notifier = HITLNotifier()
    notifier.send_test(agent, config)
    console.print(f"[green]✓[/green] Test notification sent for {agent}")
