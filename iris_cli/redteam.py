"""iris red-team — adversarial policy bypass testing."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from iris_core.entitlements import Entitlements, Feature
from iris_core.engine.cedar import CedarEngine
from iris_core.models.passport import AgentPassport
from iris_core.redteam.runner import RedTeamRunner
from iris_core.redteam.types import RedTeamFinding, RedTeamResult

console = Console()


def _gov_dir(governance_dir: Path | None) -> Path:
    return governance_dir or Path.cwd() / "governance" / "agents"


def _is_pro_tier() -> bool:
    return Entitlements().has(Feature.RED_TEAM_FULL_FINDINGS)


def _load_agent(agent: str, governance_dir: Path | None) -> tuple[AgentPassport, Path]:
    agent_dir = _gov_dir(governance_dir) / agent
    passport_path = agent_dir / "passport.yaml"
    if not passport_path.exists():
        console.print(f"[red]Agent not found:[/red] {passport_path}")
        console.print(f"Run: iris register --name {agent}")
        sys.exit(1)
    passport = AgentPassport.from_yaml(passport_path.read_text())
    if not passport.policy_ref:
        passport.policy_ref = str(agent_dir / "policy.cedar")
    if not passport.intent_ref:
        passport.intent_ref = str(agent_dir / "policy-intent.md")
    return passport, agent_dir


def _free_tier_panel(result: RedTeamResult) -> Panel:
    body = (
        f"Tests run: {result.tests_run}  │  "
        f"Bypasses found: {result.tests_failed}  │  "
        f"Risk: {result.risk_score}\n\n"
        "IRIS Pro required to see bypass details and remediation.\n"
        "iris license activate <your-key>"
    )
    title = f"Red Team Results: {result.agent_name}"
    return Panel(body, title=title, border_style="red" if result.tests_failed else "green")


def _render_findings_table(findings: list[RedTeamFinding]) -> None:
    table = Table(title="Bypass Paths Found", show_lines=True)
    table.add_column("ID", style="bold")
    table.add_column("Category")
    table.add_column("Severity")
    table.add_column("Attack")
    table.add_column("Remediation")

    for finding in findings:
        sev_style = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "dim",
        }.get(finding.severity.upper(), "white")
        table.add_row(
            finding.test_id,
            finding.category,
            f"[{sev_style}]{finding.severity}[/{sev_style}]",
            finding.attack_vector[:80],
            finding.remediation[:100],
        )
    console.print(table)


def _pro_summary_panel(result: RedTeamResult) -> Panel:
    body = (
        f"Tests run: {result.tests_run}  │  "
        f"Passed: {result.tests_passed}  │  "
        f"Bypasses found: {result.tests_failed}  │  "
        f"Risk: {result.risk_score}"
    )
    return Panel(body, title=f"Red Team Results: {result.agent_name}", border_style="red" if result.tests_failed else "green")


def _render_pro_output(result: RedTeamResult, verbose: bool) -> None:
    console.print(_pro_summary_panel(result))
    if not result.bypass_paths_found:
        console.print(f"\n[dim]{result.summary}[/dim]")
        return

    _render_findings_table(result.bypass_paths_found)

    if verbose:
        console.print("\n[bold]Detailed findings[/bold]")
        for finding in result.bypass_paths_found:
            console.print(
                f"\n[bold]{finding.test_id}[/bold] — {finding.description}\n"
                f"  Category: {finding.category}\n"
                f"  Attack: {finding.attack_vector}\n"
                f"  Expected: {finding.expected_result}\n"
                f"  Actual: {finding.actual_result}\n"
                f"  Remediation: {finding.remediation}"
            )
    else:
        console.print(f"\n[dim]{result.summary}[/dim]")


def format_redteam_result(result: RedTeamResult, *, pro: bool, verbose: bool = False) -> str:
    """Format red team output for CLI or tests."""
    if not pro:
        panel = _free_tier_panel(result)
        with console.capture() as capture:
            console.print(panel)
        return capture.get()

    with console.capture() as capture:
        _render_pro_output(result, verbose)
    return capture.get()


@click.command("red-team")
@click.option("--agent", required=True, help="Agent name to red-team")
@click.option(
    "--suite",
    "test_suite",
    type=click.Choice(["prompt", "permission", "data_exfil", "cross_region", "policy", "full"]),
    default="full",
    show_default=True,
)
@click.option("--format", "output_format", type=click.Choice(["table", "json"]), default="table")
@click.option("--verbose", is_flag=True, help="Show full attack vectors and remediation (Pro)")
@click.option("--dir", "governance_dir", type=click.Path(path_type=Path), default=None)
def red_team(
    agent: str,
    test_suite: str,
    output_format: str,
    verbose: bool,
    governance_dir: Optional[Path],
) -> None:
    """
    Adversarially test an agent's governance policy for bypass paths.

    Free tier: summary counts and risk score.
    Pro tier: full findings with attack vectors and remediation steps.

    Examples:
      iris red-team --agent payment-agent
      iris red-team --agent payment-agent --suite prompt
      iris red-team --agent payment-agent --format json
    """
    passport, _ = _load_agent(agent, governance_dir)
    engine = CedarEngine()
    runner = RedTeamRunner(passport, engine)
    result = runner.run(test_suite=test_suite)
    pro = _is_pro_tier()

    if output_format == "json":
        payload = result.to_dict()
        if not pro:
            payload["bypass_paths_found"] = []
            payload["pro_required"] = True
        click.echo(json.dumps(payload, indent=2))
    elif pro:
        _render_pro_output(result, verbose)
    else:
        console.print(_free_tier_panel(result))

    if result.tests_failed > 0:
        sys.exit(1)
    sys.exit(0)
