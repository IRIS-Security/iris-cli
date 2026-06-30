"""iris dlp — scan files and test prompts against DLP rules."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def _line_number_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _load_passport_for_agent(agent_name: str, governance_dir: Path):
    from iris_core.models.passport import AgentPassport

    passport_path = governance_dir / agent_name / "passport.yaml"
    if not passport_path.exists():
        for candidate in governance_dir.rglob("passport.yaml"):
            passport = AgentPassport.from_yaml(candidate.read_text())
            if passport.name == agent_name or candidate.parent.name == agent_name:
                return passport
        console.print(f"[red]Agent passport not found for '{agent_name}'.[/red]")
        console.print(f"Expected: {governance_dir / agent_name / 'passport.yaml'}")
        sys.exit(1)
    return AgentPassport.from_yaml(passport_path.read_text())


@click.group()
def dlp():
    """Data Loss Prevention scanning commands."""
    pass


@dlp.command("scan")
@click.option("--file", "file_path", type=click.Path(exists=True, dir_okay=False), required=True)
def dlp_scan(file_path: str):
    """
    Scan a file for sensitive data patterns.

    Shows findings with line numbers and severity — useful for checking test fixtures.

    Example:
      iris dlp scan --file tests/fixtures/patient_record.txt
    """
    from iris_core.dlp import DLPScanner
    from iris_core.models.passport import AgentPassport, DataClassification

    text = Path(file_path).read_text()
    passport = AgentPassport(
        name="dlp-scan",
        data_classification=DataClassification.PHI,
    )
    scanner = DLPScanner(passport)
    result = scanner.scan(text, direction="prompt")

    if not result.findings:
        console.print(Panel("[bold green]✓ No sensitive data patterns detected[/bold green]", style="green"))
        sys.exit(0)

    table = Table(title=f"DLP findings — {file_path}")
    table.add_column("Line", style="cyan")
    table.add_column("Pattern", style="magenta")
    table.add_column("Severity", style="yellow")
    table.add_column("Rule", style="dim")
    table.add_column("Message")

    for finding in result.findings:
        line = _line_number_for_offset(text, finding.match_start)
        table.add_row(
            str(line),
            finding.pattern_id,
            finding.severity.value,
            finding.rule_id,
            finding.message,
        )

    console.print(table)
    console.print(
        f"\n[dim]Scan completed in {result.scan_duration_ms:.2f}ms "
        f"({len(result.findings)} finding(s))[/dim]"
    )
    sys.exit(1 if result.should_block else 0)


@dlp.command("test")
@click.option("--agent", required=True, help="Agent name from governance/agents/")
@click.option("--prompt", required=True, help="Prompt text to test against the agent's DLP rules")
@click.option("--dir", "governance_dir", type=click.Path(file_okay=False), default=None)
def dlp_test(agent: str, prompt: str, governance_dir: str | None):
    """
    Test a prompt against an agent's DLP rules.

    Shows what IRIS would do with that prompt in the current environment.

    Example:
      iris dlp test --agent payment-agent --prompt "Process SSN 123-45-6789"
    """
    from iris_core.dlp import DLPScanner
    from iris_core.dlp.enforcement import dlp_policy_result
    from iris_core.models.passport import Environment

    gov_dir = Path(governance_dir) if governance_dir else Path.cwd() / "governance" / "agents"
    passport = _load_passport_for_agent(agent, gov_dir)
    env = Environment(os.environ.get("IRIS_ENV", "dev"))
    scanner = DLPScanner(passport)
    result = scanner.scan_prompt(prompt)

    console.print(
        Panel(
            f"[bold]Agent:[/bold] {passport.name}\n"
            f"[bold]Classification:[/bold] {passport.data_classification.value}\n"
            f"[bold]Environment:[/bold] {env.value}",
            title="IRIS DLP Test",
            style="blue",
        )
    )

    if not result.findings:
        console.print("\n[bold green]✓ No DLP findings — prompt would be allowed[/bold green]")
        sys.exit(0)

    for finding in result.findings:
        console.print(
            f"\n[yellow]• {finding.pattern_id}[/yellow] "
            f"({finding.severity.value}) — {finding.message}"
        )
        console.print(f"  Rule: {finding.rule_id}")
        console.print(f"  Position: {finding.match_start}-{finding.match_end}")

    if result.should_block:
        action = "BLOCK (raise IrisViolationError)"
    elif result.has_high:
        action = (
            "BLOCK in production"
            if env in (Environment.PRODUCTION, Environment.STAGING)
            else "WARN and continue in dev/test"
        )
    else:
        action = "ALLOW with informational findings"

    console.print(f"\n[bold]IRIS action:[/bold] {action}")
    if result.redacted_text and result.redacted_text != prompt:
        console.print("\n[bold]Redacted preview:[/bold]")
        console.print(result.redacted_text)

    policy = dlp_policy_result(result, passport, env, direction="prompt")
    if policy.violations:
        console.print(f"\n[dim]Primary violation: {policy.violations[0].rule_id}[/dim]")

    sys.exit(1 if result.should_block or (
        result.has_high and env in (Environment.PRODUCTION, Environment.STAGING)
    ) else 0)
