"""iris preview — show risk impact of policy changes before applying."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel

from iris_cli.cedar_parser import CedarDiff
from iris_cli.policy_diff import run_policy_diff

console = Console()

_RISK_LABEL = {
    "DECREASED": ("SAFER", "↓ risk", "green"),
    "INCREASED": ("RISKIER", "↑ risk", "red"),
    "NEUTRAL": ("NEUTRAL", "→ risk", "yellow"),
}

_RISK_SCORE = {
    "DECREASED": -0.12,
    "INCREASED": 0.34,
    "NEUTRAL": 0.0,
}


def _before_after(diff: CedarDiff) -> tuple[str, str]:
    old_rule = diff.old_rule
    new_rule = diff.new_rule
    if diff.status == "ADDED" and new_rule:
        return "No matching rule", new_rule.plain_english
    if diff.status == "REMOVED" and old_rule:
        return old_rule.plain_english, "No access"
    if old_rule and new_rule:
        return old_rule.plain_english, new_rule.plain_english
    return "—", "—"


def _compliance_note(diff: CedarDiff) -> str:
    refs = diff.compliance_affected or []
    if not refs:
        return "Compliance: No framework tags on this rule"
    ref = refs[0]
    label, _, color = _RISK_LABEL.get(diff.risk_delta, _RISK_LABEL["NEUTRAL"])
    if label == "SAFER":
        return f"Compliance: Strengthens {ref}"
    if label == "RISKIER":
        return f"Compliance: Opens {ref} gap if user_consent_logged not set"
    return f"Compliance: Affects {', '.join(refs)}"


def render_preview(result, agent: str) -> None:
    summary = result.summary
    counts = summary.get("counts", {})
    modified = counts.get("MODIFIED", 0)
    added = counts.get("ADDED", 0)
    removed = counts.get("REMOVED", 0)
    change_parts = []
    if modified:
        change_parts.append(f"{modified} rule(s) modified")
    if added:
        change_parts.append(f"{added} rule(s) added")
    if removed:
        change_parts.append(f"{removed} rule(s) removed")
    changes = ", ".join(change_parts) if change_parts else "no changes"

    console.print(Panel(
        f"Comparing: {result.compare_label}\nChanges: {changes}",
        title=f"IRIS Preview — {agent}",
        style="blue",
    ))

    change_num = 0
    for diff in result.diffs:
        if diff.status == "UNCHANGED":
            continue
        change_num += 1
        label, arrow, color = _RISK_LABEL.get(diff.risk_delta, _RISK_LABEL["NEUTRAL"])
        before, after = _before_after(diff)
        score = _RISK_SCORE.get(diff.risk_delta, 0.0)
        sign = "+" if score > 0 else ""

        console.print(f"\n[bold]CHANGE {change_num} — [{color}]{label} {arrow}[/{color}][/bold]")
        console.print("─" * 64)
        console.print(f"Before: {before}")
        console.print(f"After:  {after}")
        console.print(f"\nWhy {label}: {diff.risk_reason}")
        console.print(_compliance_note(diff))
        console.print(f"Risk delta: {sign}{score:.2f} (lower is safer)")

    if change_num:
        console.print("\n[bold]RECOMMENDATION:[/bold]")
        console.print("Before applying this change:")
        console.print("  1. Add user_consent_logged=True to consequential tool calls")
        console.print(f"  2. Run: iris certify --framework colorado-ai-act --agent {agent}")
        console.print(f"\nApply: [bold]iris compile --agent {agent}[/bold]")


@click.command("preview")
@click.option("--agent", required=True, help="Agent name")
@click.option("--dir", "governance_dir", type=click.Path(path_type=Path), default=None)
@click.option("--compile", is_flag=True, help="Regenerate draft via LLM before preview")
@click.option("--verbose", is_flag=True, help="Include unchanged rules")
def preview(
    agent: str,
    governance_dir: Optional[Path],
    compile: bool,
    verbose: bool,
) -> None:
    """
    Show risk impact of policy changes before applying.

    Alias: iris policy diff
    """
    try:
        result = run_policy_diff(
            agent,
            governance_dir=governance_dir,
            verbose=verbose,
            compile=compile,
        )
    except FileNotFoundError as exc:
        raise click.ClickException(str(exc)) from exc

    render_preview(result, agent)
