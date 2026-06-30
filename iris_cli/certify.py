"""iris certify — prove compliance readiness to any regulatory framework."""

# Copyright 2024-2025 Gilbert Martin / IRIS Security, Inc.
# All Rights Reserved.
# Author: Gilbert Martin <gilbert@iris-security.io>
# IRIS CLI — Policy as Code for AI Agents

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from iris_core.compliance.dynamic_loader import ComplianceRule, DynamicBundleLoader
from iris_core.compliance.full_eval import render_full_eval_text, run_full_eval
from iris_core.compliance.exporters.aiuc1_export import AIUC1EvidenceExporter
from iris_core.compliance.framework_check import load_bundle_data, run_framework_check
from iris_core.compliance.bundles.iso42001 import (
    ISO42001_BUNDLE,
    ISO42001_CLAUSES,
    coverage_breakdown,
    stale_crosswalk_warning,
)
from iris_core.entitlements import Entitlements, Feature
from iris_core.models.passport import AgentPassport

from iris_cli.framework_test import (
    _build_result,
    _framework_name,
    _load_previous_score,
    _render_json,
    _render_markdown,
    _render_table,
    _save_result,
)

console = Console()

_CERTIFY_FRAMEWORKS = sorted([
    "colorado-ai-act", "nist-ai-rmf", "fedramp-moderate", "hipaa", "soc2", "gdpr",
    "nyc-ll144", "illinois-ai-video", "eu-ai-act", "ccpa-admt", "china-pipl",
    "aiuc-1", "iso-42001", "aarm-core", "aarm-extended", "soc2-cc",
])


def _evaluate_custom_rule(rule: ComplianceRule, passport: AgentPassport) -> str:
    safe_globals = {"__builtins__": {}}
    safe_locals = {
        "passport": passport,
        "hitl_config": getattr(passport, "hitl_config", None),
        "cost_config": getattr(passport, "cost_config", None),
        "bool": bool,
        "len": len,
    }
    try:
        value = eval(rule.check_expression, safe_globals, safe_locals)
    except Exception:
        return "FAIL"
    return "PASS" if value else "FAIL"


def _rule_source_label(loader: DynamicBundleLoader) -> str:
    info = loader.registry_info()
    if info.source == "live":
        return "Live registry"
    if info.source == "cache":
        hours = info.cache_age_hours
        if hours is not None and hours < 1:
            return "Live registry (updated recently)"
        if hours is not None:
            return f"Live registry (updated {int(hours)} hours ago)"
        return "Cached registry"
    return "Bundled fallback"


def _render_certification_header(
    framework: str,
    agent_name: str,
    result,
    *,
    loader: DynamicBundleLoader,
    custom_rule_count: int,
) -> None:
    bundle = loader.load_bundle(framework)
    info = loader.registry_info()
    framework_label = _framework_name(framework)
    if framework == "colorado-ai-act":
        framework_label = "Colorado AI Act (SB 26-189)"

    version = bundle.metadata.get("current_version", info.registry_version)
    law_name = bundle.metadata.get("law_name", framework_label)

    console.print(Panel(
        f"Agent:        {agent_name}\n"
        f"Framework:    {law_name} v{version}\n"
        f"Rule source:  {_rule_source_label(loader)}\n"
        f"Custom rules: {custom_rule_count} organization rule{'s' if custom_rule_count != 1 else ''} evaluated\n"
        f"Generated:    {datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}\n"
        f"Attested:     IRIS · Commit: local",
        title=f"IRIS Certification — {framework}",
        style="blue",
    ))

    evaluated = result.passed_controls + result.failed_controls + result.partial_controls
    pct = result.score_percent
    filled = int((pct / 100) * 20)
    bar = "█" * filled + "░" * (20 - filled)
    readiness = "READY" if pct >= 95 else result.readiness_level

    console.print(f"\n[bold]CERTIFICATION RESULT: {readiness}[/bold]")
    console.print(f"{bar}  {result.passed_controls} / {result.total_controls} controls  {pct}%")

    if framework == "colorado-ai-act" and pct >= 95:
        console.print(
            f"\nThis agent is certification-ready for Colorado AI Act (SB 26-189).\n"
            f"Effective date: January 1, 2027\n\n"
            f"Evidence package: iris evidence report --agent {agent_name}\n"
            f"Auditor note: Present this output alongside the Evidence Vault report "
            f"to demonstrate compliance readiness."
        )


def _render_custom_rules_section(
    custom_rules: list[ComplianceRule],
    passport: AgentPassport,
) -> None:
    if not custom_rules:
        return
    console.print("\n[bold]ORGANIZATION POLICY[/bold]")
    console.print("─" * 65)
    for rule in custom_rules:
        status = _evaluate_custom_rule(rule, passport)
        icon = "[green]✓[/green]" if status == "PASS" else "[red]✗[/red]"
        console.print(f"{icon} {rule.rule_id:<14} {rule.name}")
        if status != "PASS" and rule.remediation_command:
            console.print(f"   Fix: {rule.remediation_command}")


def _render_iso42001_certification(agent_name: str) -> None:
    crosswalk_date = ISO42001_BUNDLE["source_crosswalk_date"]
    console.print(Panel(
        f"Derived from AIUC-1 crosswalk ({crosswalk_date}) + IRIS evidence",
        title=f"ISO 42001 Coverage — {agent_name}",
        style="blue",
    ))

    warning = stale_crosswalk_warning()
    if warning:
        console.print(f"\n[yellow]⚠ {warning}[/yellow]")

    counts = coverage_breakdown()
    console.print(
        f"\n[green]FULL[/green] coverage (IRIS evidence satisfies the clause):"
        f"    {counts['FULL']} clauses"
    )
    console.print(
        f"[yellow]PARTIAL[/yellow] coverage (IRIS evidence + org action needed):"
        f"  {counts['PARTIAL']} clauses"
    )
    console.print(
        f"[dim]NOT APPLICABLE[/dim] (organizational/human activity only):"
        f"   {counts['NOT_APPLICABLE']} clauses"
    )
    if counts.get("NONE", 0):
        console.print(
            f"[red]NONE[/red] (IRIS inherits AIUC-1 gap — no technical evidence):"
            f"     {counts['NONE']} clauses"
        )

    for tier, style in (
        ("FULL", "green"),
        ("PARTIAL", "yellow"),
        ("NOT_APPLICABLE", "dim"),
        ("NONE", "red"),
    ):
        section = [c for c in ISO42001_CLAUSES if c.get("iris_coverage") == tier]
        if not section:
            continue
        console.print(f"\n[bold {style}]{tier}[/bold {style}] ({len(section)} clauses)")
        table = Table(show_header=True, header_style="bold")
        table.add_column("Clause")
        table.add_column("Title")
        table.add_column("AIUC-1 Gap")
        table.add_column("Evidence / Gap note", overflow="fold")
        for clause in section:
            note = clause.get("iris_evidence") or clause.get("gap_note") or "—"
            table.add_row(
                clause["clause"],
                clause["title"],
                clause["aiuc1_gap"],
                note,
            )
        console.print(table)


def _render_aarm_certification(
    framework: str,
    agent_name: str,
    passport: AgentPassport,
    *,
    governance_dir: Path,
) -> None:
    bundle = load_bundle_data(framework)
    result = run_framework_check(passport, framework)
    console.print(Panel(
        f"Agent: {agent_name}\n"
        f"Framework: {bundle.get('full_name', framework)}\n"
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}",
        title=f"IRIS Certification — {framework}",
        style="blue",
    ))
    table = Table(show_header=True, header_style="bold")
    table.add_column("Requirement")
    table.add_column("Status")
    table.add_column("AIUC-1 refs")
    table.add_column("Notes", overflow="fold")
    rules = bundle.get("rules", [])
    for rule_result in result.rule_results:
        bundle_rule = next(
            (r for r in rules if r["rule_id"] == rule_result.rule_id),
            {},
        )
        refs = ", ".join(bundle_rule.get("aiuc1_refs", []))
        if rule_result.status == "PASS":
            status = "[green]PASS[/green]"
            note = ""
        else:
            status = "[red]FAIL[/red]"
            note = rule_result.message
        table.add_row(
            f"{bundle_rule.get('requirement', '')} {bundle_rule.get('name', rule_result.name)}",
            status,
            refs,
            note,
        )
    console.print(table)
    try:
        full_eval = run_full_eval(
            passport, framework, governance_dir=governance_dir / "agents"
        )
        console.print(render_full_eval_text(full_eval))
    except PermissionError:
        pass
    console.print(
        "\n[dim]Export auditor package: "
        f"iris evidence export --agent {agent_name} --output report.html --format pdf[/dim]"
    )


def _render_aiuc1_certification(agent_name: str, passport: AgentPassport, *, governance_dir: Path) -> None:
    result = run_framework_check(passport, "aiuc-1")
    bundle = load_bundle_data("aiuc-1")
    console.print(Panel(
        f"Agent: {agent_name}\n"
        f"Framework: {bundle.get('full_name', 'AIUC-1')}\n"
        f"Source crosswalk: {bundle.get('source_crosswalk_date', '2025-09-18')}\n"
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}",
        title="IRIS Certification — aiuc-1",
        style="blue",
    ))
    table = Table(show_header=True, header_style="bold")
    table.add_column("Control")
    table.add_column("Coverage")
    table.add_column("Status")
    table.add_column("Notes", overflow="fold")
    for rule_result in result.rule_results:
        bundle_rule = next(
            (r for r in bundle.get("rules", []) if r["rule_id"] == rule_result.rule_id),
            {},
        )
        coverage = bundle_rule.get("coverage", "")
        if rule_result.status == "OUT_OF_SCOPE":
            status = "[dim]OUT OF SCOPE[/dim]"
            note = bundle_rule.get("gap_note", "")
        elif rule_result.status == "PASS":
            status = "[green]PASS[/green]"
            note = bundle_rule.get("gap_note", "") if coverage == "PARTIAL" else ""
        else:
            status = "[red]FAIL[/red]"
            note = rule_result.message
        table.add_row(rule_result.rule_id, coverage, status, note)
    console.print(table)
    try:
        full_eval = run_full_eval(
            passport, "aiuc-1", governance_dir=governance_dir / "agents"
        )
        console.print(render_full_eval_text(full_eval))
    except PermissionError:
        pass
    console.print(
        "\n[dim]Export auditor-ready evidence: "
        f"iris evidence export --agent {agent_name} --output report.html --format pdf "
        f"or iris certify --framework aiuc-1 --agent {agent_name} "
        "--format aiuc1-export[/dim]"
    )


@click.command("certify")
@click.option(
    "--framework",
    required=True,
    type=click.Choice(_CERTIFY_FRAMEWORKS),
)
@click.option("--agent", "agent_name", required=True, help="Agent name under governance/agents")
@click.option(
    "--format",
    "output_format",
    default="table",
    type=click.Choice(["table", "json", "markdown", "aiuc1-export"]),
)
@click.option(
    "--registry-version",
    default=None,
    help="Pin to a specific registry version for reproducible certifications",
)
@click.option("--dir", "governance_dir", type=click.Path(path_type=Path), default=None)
@click.option("--offline", is_flag=True, help="Use bundled registry only (no network refresh)")
def certify_cmd(
    framework: str,
    agent_name: str,
    output_format: str,
    registry_version: Optional[str],
    governance_dir: Optional[Path],
    offline: bool,
) -> None:
    """
    Certify compliance readiness against a regulatory framework.

    Alias: iris test
    """
    gov_dir = governance_dir or Path.cwd() / "governance"
    passport_path = gov_dir / "agents" / agent_name / "passport.yaml"
    if not passport_path.exists():
        raise click.ClickException(f"Passport not found: {passport_path}")
    passport = AgentPassport.from_yaml(passport_path.read_text())

    if framework == "iso-42001":
        Entitlements().require(Feature.BUNDLE_ISO42001, context="iso-42001 certification")
        if output_format == "json":
            click.echo(
                json.dumps(
                    {
                        "framework": "iso-42001",
                        "agent": agent_name,
                        "source_crosswalk_date": ISO42001_BUNDLE["source_crosswalk_date"],
                        "coverage_breakdown": coverage_breakdown(),
                        "clauses": ISO42001_CLAUSES,
                        "stale_warning": stale_crosswalk_warning(),
                    },
                    indent=2,
                )
            )
        else:
            _render_iso42001_certification(agent_name)
        return

    if framework == "aiuc-1":
        Entitlements().require(Feature.BUNDLE_AIUC1, context="aiuc-1 certification")
        if output_format == "aiuc1-export":
            exporter = AIUC1EvidenceExporter(passport, gov_dir)
            click.echo(json.dumps(exporter.export_full_package(agent_name), indent=2))
            return
        if output_format in ("json", "markdown"):
            result = run_framework_check(passport, "aiuc-1")
            payload = {
                "framework": "aiuc-1",
                "agent": agent_name,
                "rules": [
                    {
                        "rule_id": r.rule_id,
                        "status": r.status,
                        "message": r.message,
                    }
                    for r in result.rule_results
                ],
            }
            click.echo(json.dumps(payload, indent=2) if output_format == "json" else str(payload))
            return
        _render_aiuc1_certification(agent_name, passport, governance_dir=gov_dir)
        return

    if framework in ("aarm-core", "aarm-extended", "soc2-cc"):
        feature = Feature.BUNDLE_AIUC1 if framework.startswith("aarm") else Feature.BUNDLE_SOC2
        Entitlements().require(feature, context=f"{framework} certification")
        if output_format == "json":
            result = run_framework_check(passport, framework)
            click.echo(json.dumps({
                "framework": framework,
                "agent": agent_name,
                "rules": [
                    {"rule_id": r.rule_id, "status": r.status, "message": r.message}
                    for r in result.rule_results
                ],
            }, indent=2))
            return
        _render_aarm_certification(framework, agent_name, passport, governance_dir=gov_dir)
        return

    loader = DynamicBundleLoader(pinned_version=registry_version)

    if not offline and not registry_version:
        if not loader.is_cache_fresh():
            console.print("[dim]Checking for regulatory updates...[/dim]")
            updated = loader.refresh_registry()
            if updated:
                console.print("[green]✓ Regulatory intelligence updated[/green]")
                console.print("[dim]  Run: iris regulatory check for change summary[/dim]")

    custom_rules = loader.load_custom_rules(gov_dir)
    loader.get_effective_rules(framework, gov_dir)

    ents = Entitlements()
    has_pro = ents.has(Feature.CLI_TEST_FULL_REPORT)

    result = _build_result(framework, agent_name, passport)
    previous = _load_previous_score(agent_name, framework)
    if previous is not None and has_pro:
        result.progress_delta_percent = result.score_percent - previous

    _save_result(result)

    if output_format == "json":
        click.echo(_render_json(result, has_pro))
    elif output_format == "markdown":
        click.echo(_render_markdown(result, has_pro))
    else:
        _render_certification_header(
            framework, agent_name, result,
            loader=loader,
            custom_rule_count=len(custom_rules),
        )
        _render_table(result, has_pro)
        _render_custom_rules_section(custom_rules, passport)
        _render_response_configuration(framework, passport, loader=loader)


def _render_response_configuration(
    framework: str,
    passport: AgentPassport,
    *,
    loader: Optional[DynamicBundleLoader] = None,
) -> None:
    from iris_core.compliance.violation_response import (
        get_effective_response,
        rule_response_label,
        ViolationResponse,
    )

    try:
        if loader:
            bundle = loader.load_bundle(framework).to_dict()
        else:
            from iris_core.compliance.framework_check import load_bundle_data
            bundle = load_bundle_data(framework)
    except ValueError:
        return
    rules = bundle.get("rules", [])
    if not rules:
        return

    console.print("\n[bold]RESPONSE CONFIGURATION[/bold]")
    console.print("─" * 65)
    overrides = passport.compliance_response_overrides or {}
    for rule in rules:
        rule_id = rule.get("rule_id", "")
        default = rule.get("violation_response", "inform").upper()
        effective = rule_response_label(rule, overrides)
        line = f"{rule_id:<12} {effective:<8}"
        if rule.get("violation_response"):
            base = ViolationResponse(rule["violation_response"])
            if base == ViolationResponse.BLOCK:
                line += " (unconditional — cannot be overridden)"
            elif effective != default:
                line += " (override active)"
            else:
                line += " (default)"
        console.print(line)

    if overrides:
        console.print("\n[dim]Active overrides in passport.yaml:[/dim]")
        for rule_id, cfg in overrides.items():
            console.print(f"  {rule_id}: {cfg.get('response', 'inform')} — {cfg.get('reason', '')}")
    else:
        console.print(
            "\n[dim]Override example (add to passport.yaml if needed):[/dim]\n"
            "  compliance_response_overrides:\n"
            "    CO-003:\n"
            "      response: inform\n"
            "      reason: Pre-production — not serving CO consumers yet"
        )


# Legacy alias: iris test → iris certify
test = certify_cmd
