"""Rich terminal rendering for enhanced iris scan results."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from iris_core.compliance.registry import ComplianceRegistry
from iris_core.discovery.scanner import ScanResult, UngovernedFinding
from iris_core.models.passport import AgentPassport


def _compliance_label(passport: AgentPassport) -> str:
    if passport.compliance_tags:
        return passport.compliance_tags[0].value
    return "colorado-ai-act"


def _agent_status(
    passport: AgentPassport,
    registry: ComplianceRegistry,
    framework: Optional[str],
) -> str:
    violations = registry.check_passport(passport, framework)
    return "PASS" if not violations else "FAIL"


def render_discover_scan(
    console: Console,
    result: ScanResult,
    scan_dir: Path,
    framework: Optional[str] = None,
    auto_register: bool = False,
    drafts_written: Optional[List[Path]] = None,
) -> None:
    """Render governed agents, ungoverned findings, and scan summary."""
    registry = ComplianceRegistry()
    drafts_written = drafts_written or []

    console.print(
        Panel(
            f"[bold]IRIS Governance Scan[/bold]\n"
            f"Directory: {scan_dir}\n"
            f"Framework: {framework or 'all active bundles'}\n"
            f"Files scanned: {result.files_scanned:,}  |  "
            f"Lines scanned: {result.lines_scanned:,}",
            style="blue",
        )
    )

    governed = result.governed_agents
    console.print(f"\n[bold]GOVERNED AGENTS ({len(governed)})[/bold]")
    if governed:
        for passport in governed:
            compliance = _compliance_label(passport)
            status = _agent_status(passport, registry, framework)
            status_style = "green" if status == "PASS" else "red"
            console.print(
                f"[green]✓[/green] {passport.name:<20} "
                f"{compliance:<18} [{status_style}]{status}[/{status_style}]"
            )
    else:
        console.print("[dim]No passport.yaml files found.[/dim]")

    findings = result.ungoverned_findings
    console.print(f"\n[bold]UNGOVERNED AGENTS DETECTED ({len(findings)})[/bold]")
    if findings:
        for finding in findings:
            _print_finding(console, finding)
        if not auto_register:
            console.print(
                '\n[dim]Run "iris scan --discover --auto-register" to generate '
                "passport drafts for all findings.[/dim]"
            )
    else:
        console.print("[green]No ungoverned AI patterns detected in source files.[/green]")

    if result.shadow_agents:
        console.print(f"\n[bold]SHADOW AGENTS ({len(result.shadow_agents)})[/bold]")
        for shadow in result.shadow_agents:
            console.print(
                f"[yellow]⚠[/yellow] {shadow.resource_path} "
                f"({shadow.resource_name} @ {shadow.namespace})\n"
                f"  {shadow.reason}"
            )

    if drafts_written:
        console.print(f"\n[bold green]Passport drafts written ({len(drafts_written)})[/bold green]")
        for draft in drafts_written:
            console.print(f"  [cyan]{draft}[/cyan]")


def _print_finding(console: Console, finding: UngovernedFinding) -> None:
    risk_style = {
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
    }.get(finding.risk_level, "white")
    console.print(
        f"\n[yellow]⚠[/yellow] {finding.file_path}:{finding.line_number}\n"
        f"Pattern: {finding.pattern_matched}\n"
        f"Framework: {_display_framework(finding.framework_detected)}\n"
        f"Risk: [{risk_style}]{finding.risk_level}[/{risk_style}] — {finding.risk_reason}\n"
        f"Fix: [bold cyan]{finding.suggested_command}[/bold cyan]"
    )


def _display_framework(framework: str) -> str:
    labels: Dict[str, str] = {
        "langchain": "LangChain",
        "crewai": "CrewAI",
        "openai": "OpenAI",
        "anthropic": "Anthropic SDK",
        "generic": "Generic",
    }
    return labels.get(framework, framework)


def render_violations_table(console: Console, violations: list) -> None:
    """Render compliance violations table (existing scan behavior)."""
    table = Table(title=f"Violations ({len(violations)} found)")
    table.add_column("Rule", style="cyan", no_wrap=True)
    table.add_column("Severity", style="red")
    table.add_column("Message")
    table.add_column("Remediation", style="yellow")
    for v in violations:
        severity_color = {
            "CRITICAL": "red",
            "HIGH": "orange3",
            "MEDIUM": "yellow",
            "LOW": "green",
        }.get(v.severity.value, "white")
        remediation = v.remediation
        if len(remediation) > 80:
            remediation = remediation[:80] + "..."
        table.add_row(
            v.rule_id,
            f"[{severity_color}]{v.severity.value}[/{severity_color}]",
            v.message,
            remediation,
        )
    console.print(table)
