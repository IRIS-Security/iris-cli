"""Interactive compliance remediation — IRIS governance assistant."""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.panel import Panel

from iris import AgentPassport
from iris_core.compliance.framework_check import FrameworkCheckResult, run_framework_check
from iris_core.compliance.remediation import (
    FixResult,
    FixableIssue,
    apply_fix,
    collect_fixable_issues,
)

console = Console()


def _is_interactive() -> bool:
    return click.get_text_stream("stdin").isatty()


def _print_fixable_summary(agent_name: str, issues: List[FixableIssue]) -> None:
    lines = [
        f"[bold]IRIS found {len(issues)} fixable issue"
        f"{'s' if len(issues) != 1 else ''} for [cyan]{agent_name}[/cyan][/bold]\n"
    ]
    for issue in issues:
        lines.append(f"  [yellow]•[/yellow] [{issue.rule_id}] {issue.preview}")
    lines.append(
        "\n[dim]IRIS can apply safe passport and policy updates automatically. "
        "Review each change before applying.[/dim]"
    )
    console.print(Panel("\n".join(lines), title="IRIS Governance Assistant", style="blue"))


def offer_remediation(
    passport: AgentPassport,
    framework: str,
    result: FrameworkCheckResult,
    governance_dir: Path,
    *,
    auto_fix: bool = False,
    yes: bool = False,
    no_fix: bool = False,
) -> List[FixResult]:
    """
    Offer to apply fixable remediations after a compliance check.

  Returns applied fix results (may be empty).
    """
    if no_fix or result.preview_only:
        return []

    issues = collect_fixable_issues(passport, framework, result)
    if not issues:
        return []

    agent_dir = governance_dir / passport.name
    passport_file = agent_dir / "passport.yaml"

    if auto_fix or yes:
        return _apply_all(issues, passport_file, framework, passport.name)

    if not _is_interactive():
        console.print(
            "[dim]Fixable issues detected. Re-run with --fix to apply automatically.[/dim]"
        )
        return []

    _print_fixable_summary(passport.name, issues)
    if not click.confirm(
        f"\nWould you like IRIS to fix these {len(issues)} issue"
        f"{'s' if len(issues) != 1 else ''} for {passport.name}?",
        default=True,
    ):
        console.print("[dim]Skipped automatic fixes. Apply remediations manually when ready.[/dim]")
        return []

    return _apply_interactive(issues, passport_file, framework, passport.name)


def _apply_all(
    issues: List[FixableIssue],
    passport_file: Path,
    framework: str,
    agent_name: str,
) -> List[FixResult]:
    results: List[FixResult] = []
    for issue in issues:
        result = apply_fix(issue, passport_file, framework)
        results.append(result)
        _print_fix_result(agent_name, issue, result)
    if results:
        console.print(
            Panel(
                f"[bold green]✓ IRIS applied {sum(1 for r in results if r.applied)} fix"
                f"{'es' if sum(1 for r in results if r.applied) != 1 else ''}[/bold green]\n\n"
                f"Re-run: [bold]iris compliance check --agent {agent_name} "
                f"--framework {framework}[/bold]",
                style="green",
            )
        )
    return results


def _apply_interactive(
    issues: List[FixableIssue],
    passport_file: Path,
    framework: str,
    agent_name: str,
) -> List[FixResult]:
    results: List[FixResult] = []
    apply_all = False

    for issue in issues:
        if apply_all:
            result = apply_fix(issue, passport_file, framework)
            results.append(result)
            _print_fix_result(agent_name, issue, result)
            continue

        console.print(
            f"\n[bold]IRIS can fix[/bold] [{issue.rule_id}] {issue.preview}\n"
            f"[dim]{issue.message}[/dim]"
        )
        console.print("Apply this fix? ([yes]/no/skip/all)")
        choice = click.prompt("", default="no", show_default=False).strip().lower()

        if choice in ("yes", "y"):
            result = apply_fix(issue, passport_file, framework)
            results.append(result)
            _print_fix_result(agent_name, issue, result)
        elif choice == "all":
            apply_all = True
            result = apply_fix(issue, passport_file, framework)
            results.append(result)
            _print_fix_result(agent_name, issue, result)
        elif choice == "skip":
            console.print("[dim]Skipped.[/dim]")
        else:
            console.print("[dim]Not applied — fix manually when ready.[/dim]")

    applied_count = sum(1 for r in results if r.applied)
    if applied_count:
        console.print(
            Panel(
                f"[bold green]✓ IRIS applied {applied_count} fix"
                f"{'es' if applied_count != 1 else ''}[/bold green]\n\n"
                f"Re-run: [bold]iris compliance check --agent {agent_name} "
                f"--framework {framework}[/bold]",
                style="green",
            )
        )
    return results


def _print_fix_result(agent_name: str, issue: FixableIssue, result: FixResult) -> None:
    if result.applied:
        change_text = "\n".join(f"  [dim]• {change}[/dim]" for change in result.changes)
        console.print(f"[green]✓ Applied[/green] [{issue.rule_id}]\n{change_text}")
        return
    if result.skipped_reason:
        console.print(
            f"[yellow]⚠ Skipped[/yellow] [{issue.rule_id}]: {result.skipped_reason}"
        )


def recheck_after_fixes(
    passport: AgentPassport,
    framework: str,
    governance_dir: Path,
    applied: List[FixResult],
) -> Optional[FrameworkCheckResult]:
    """Re-run check and show delta when fixes were applied."""
    if not any(result.applied for result in applied):
        return None

    passport_file = governance_dir / passport.name / "passport.yaml"
    if not passport_file.exists():
        return None

    updated = AgentPassport.from_yaml(passport_file.read_text())
    result = run_framework_check(updated, framework)
    remaining = collect_fixable_issues(updated, framework, result)
    fail_count = sum(1 for rule in result.rule_results if rule.status == "FAIL")
    fail_count += len(result.violations)

    console.print(
        Panel(
            f"[bold]Re-check: {updated.name}[/bold]\n"
            f"Remaining failures: {fail_count}\n"
            f"Auto-fixable remaining: {len(remaining)}",
            style="cyan",
        )
    )
    return result
