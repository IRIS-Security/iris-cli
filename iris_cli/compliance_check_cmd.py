"""iris compliance check — framework compliance with Pro preview."""

# Copyright 2024-2025 Gilbert Martin / IRIS Security, Inc.
# All Rights Reserved.
# Author: Gilbert Martin <gilbert@iris-security.io>
# IRIS CLI — Policy as Code for AI Agents

from __future__ import annotations

import dataclasses
import os
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from iris import AgentPassport
from iris_core.compliance.framework_check import load_bundle_data, run_framework_check
from iris_core.compliance.results import ComplianceCheckStatus
from iris_core.compliance.full_eval import FullEvalResult, render_full_eval_text, run_full_eval
from iris_core.entitlements import Entitlements, Feature

from iris_cli.compliance_fix import offer_remediation, recheck_after_fixes
from iris_core.compliance.remediation import collect_fixable_issues
from iris_core.entitlements.display import build_pro_preview_box

console = Console()

_FULL_EVAL_FRAMEWORKS = frozenset({
    "aiuc-1", "aarm-core", "aarm-extended", "soc2-cc",
    "hipaa", "soc2", "nist-ai-rmf", "gdpr", "fedramp-moderate",
    "colorado-ai-act", "colorado-ai-act-original",
})


def _discover_passports(
    gov_dir: Path,
    agent: Optional[str],
) -> list[AgentPassport]:
    passports: list[AgentPassport] = []
    if agent:
        passport_file = gov_dir / agent / "passport.yaml"
        if passport_file.exists():
            passports.append(AgentPassport.from_yaml(passport_file.read_text()))
        return passports

    for passport_file in gov_dir.rglob("passport.yaml"):
        try:
            passports.append(AgentPassport.from_yaml(passport_file.read_text()))
        except Exception:
            continue
    return passports


def _render_result(
    passport: AgentPassport,
    framework: str,
    result,
) -> bool:
    """Print one agent's check result. Returns False if failures were found."""
    if result.preview_only:
        preview_lines = [
            f"{rule.rule_id}  {rule.severity}  {rule.name}  [{rule.status}]"
            for rule in result.rule_results
        ]
        console.print(
            build_pro_preview_box(
                framework,
                result.framework_name,
                result.total_controls,
                preview_lines,
            )
        )
        return False

    has_failures = any(
        rule.status == "FAIL" for rule in result.rule_results
    ) or bool(result.violations)
    status = "[bold green]PASS[/bold green]" if not has_failures else "[bold red]FAIL[/bold red]"
    console.print(f"\nAgent: [cyan]{passport.name}[/cyan] — {status}")

    if result.rule_results:
        bundle_rules = []
        if framework == "aiuc-1":
            try:
                bundle_rules = load_bundle_data(framework).get("rules", [])
            except ValueError:
                bundle_rules = []
        table = Table(title=f"{result.framework_name}", show_header=True, header_style="bold")
        table.add_column("Rule", style="cyan")
        table.add_column("Severity")
        table.add_column("Status")
        if framework == "aiuc-1":
            table.add_column("Coverage")
        table.add_column("Response")
        table.add_column("Notes")
        for rule in result.rule_results:
            if rule.status == "PASS":
                status_icon = "[green]✓ PASS[/green]"
            elif rule.status == "OUT_OF_SCOPE":
                status_icon = "[dim]— OUT OF SCOPE[/dim]"
            else:
                status_icon = "[red]✗ FAIL[/red]"
            notes = rule.message if rule.status == "FAIL" else ""
            if rule.status == "OUT_OF_SCOPE":
                notes = rule.message
            row = [rule.rule_id, rule.severity, status_icon]
            if framework == "aiuc-1":
                bundle_rule = next(
                    (
                        r
                        for r in bundle_rules
                        if r.get("rule_id") == rule.rule_id
                    ),
                    {},
                )
                row.append(bundle_rule.get("coverage", ""))
            row.extend([rule.response, notes[:80] + ("..." if len(notes) > 80 else "")])
            table.add_row(*row)
        console.print(table)
        console.print(
            "\n[dim]RESPONSE KEY: INFORM — log and proceed | "
            "HITL — human review required | BLOCK — unconditional block[/dim]"
        )

    if result.violations:
        for violation in result.violations:
            if any(r.rule_id == violation.rule_id for r in result.rule_results):
                continue
            console.print(f"  [red]✗[/red] [{violation.rule_id}] {violation.message}")
            if violation.remediation:
                console.print(f"     [yellow]→[/yellow] {violation.remediation}")

    if not result.violations and not any(r.status == "FAIL" for r in result.rule_results):
        console.print(f"  [green]✓[/green] All {framework} rules satisfied")

    for guidance in result.guidance:
        if guidance.status == ComplianceCheckStatus.GUIDANCE:
            console.print(f"  [blue]ℹ[/blue] [{guidance.rule_id}] {guidance.message}")
            if guidance.remediation:
                console.print(f"     [yellow]→[/yellow] {guidance.remediation}")
        elif guidance.status == ComplianceCheckStatus.PRO_REQUIRED:
            console.print(f"  [yellow]⚠[/yellow] [{guidance.rule_id}] {guidance.message}")
            if guidance.remediation:
                console.print(f"     [yellow]→[/yellow] {guidance.remediation}")

    for note in result.check_notes:
        console.print(f"  [dim]ℹ {note}[/dim]")

    return not has_failures


def _push_full_eval(result: FullEvalResult) -> None:
    api_key = os.environ.get("IRIS_API_KEY") or os.environ.get("IRIS_CLOUD_API_KEY")
    base_url = os.environ.get("IRIS_API_URL", "http://localhost:8000")
    if not api_key:
        console.print("[yellow]Set IRIS_API_KEY to push full-eval result to cloud.[/yellow]")
        return
    import httpx

    payload = {
        "agent_name": result.agent_name,
        "framework": result.framework,
        "control_results": [dataclasses.asdict(c) for c in result.control_results],
        "gap_summary": result.gap_summary,
        "ranked_actions": result.ranked_actions,
        "estimated_closure": result.estimated_closure,
    }
    response = httpx.post(
        f"{base_url.rstrip('/')}/intelligence/full-eval/push",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json=payload,
        timeout=30,
    )
    if response.status_code >= 400:
        console.print(f"[red]Push failed ({response.status_code}): {response.text}[/red]")
        return
    console.print("[green]Full-eval result pushed to IRIS Cloud.[/green]")


@click.command("check")
@click.option("--agent", default=None, help="Specific agent to check (or all)")
@click.option("--framework", "-f", default="colorado-ai-act")
@click.option("--dir", "governance_dir", type=click.Path(path_type=Path), default=None)
@click.option(
    "--fix",
    is_flag=True,
    help="Apply all auto-fixable remediations without per-issue prompts",
)
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    help="Apply auto-fixes without confirmation (use with --fix)",
)
@click.option(
    "--no-fix",
    is_flag=True,
    help="Show remediations only — never offer to apply fixes",
)
@click.option(
    "--full",
    is_flag=True,
    help="Full evaluation: control-by-control evidence mapping and gap analysis",
)
@click.option(
    "--push",
    is_flag=True,
    help="POST full-eval result to IRIS Cloud when IRIS_API_KEY is set (requires --full)",
)
def compliance_check_cmd(
    agent: Optional[str],
    framework: str,
    governance_dir: Optional[Path],
    fix: bool,
    yes: bool,
    no_fix: bool,
    full: bool,
    push: bool,
) -> None:
    """
    Check an agent against a compliance framework.

    Shows a detailed breakdown of which rules pass and fail,
    with plain-English remediation guidance for each failure.
    When run interactively, IRIS offers to apply safe fixes automatically.

    Example:
      iris compliance check --framework colorado-ai-act
      iris compliance check --agent payment-agent --framework hipaa
      iris compliance check --agent payment-agent --framework hipaa --fix -y
      iris compliance check --agent payment-agent --framework aiuc-1 --full
      iris compliance check --agent payment-agent --framework colorado-ai-act --full --push
    """
    if push and not full:
        raise click.ClickException("--push requires --full")

    if full:
        Entitlements().require(
            Feature.CLI_TEST_FULL_REPORT,
            context="compliance check --full",
        )

    gov_dir = governance_dir or Path.cwd() / "governance" / "agents"
    passports = _discover_passports(gov_dir, agent)
    if not passports:
        console.print("[yellow]No agent passports found.[/yellow]")
        sys.exit(0)

    all_pass = True
    offer_fixes = bool(agent) or len(passports) == 1
    for passport in passports:
        result = run_framework_check(passport, framework)
        agent_passed = _render_result(passport, framework, result)
        if not agent_passed:
            all_pass = False

        if full and framework in _FULL_EVAL_FRAMEWORKS:
            try:
                full_result = run_full_eval(
                    passport,
                    framework,
                    governance_dir=gov_dir,
                )
                console.print(render_full_eval_text(full_result))
                if push:
                    _push_full_eval(full_result)
            except PermissionError as exc:
                console.print(f"[yellow]{exc}[/yellow]")
                sys.exit(1)
        elif push:
            console.print(
                f"[yellow]--push skipped: {framework} is not a full-eval framework.[/yellow]"
            )

        if offer_fixes:
            applied = offer_remediation(
                passport,
                framework,
                result,
                gov_dir,
                auto_fix=fix,
                yes=yes,
                no_fix=no_fix,
            )
            recheck_after_fixes(passport, framework, gov_dir, applied)
        elif not no_fix and not agent_passed and collect_fixable_issues(
            passport, framework, result
        ):
            console.print(
                f"[dim]Fixable issues for {passport.name}. "
                f"Re-run with --agent {passport.name} to let IRIS apply fixes.[/dim]"
            )

    sys.exit(0 if all_pass else 1)
