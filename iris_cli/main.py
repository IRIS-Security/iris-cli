"""
IRIS CLI — runtime governance for AI agents.

Command vocabulary (what runs, not what deploys):
  iris declare                 — declare what an agent is allowed to do
  iris compile                 — natural language → Cedar policy
  iris preview                 — show risk impact before applying changes
  iris enforce                 — verify runtime enforcement is active
  iris witness                 — live attested feed of every decision
  iris certify                 — prove compliance to any framework
  iris sentinel                — continuous governance monitoring
  iris scan                    — discover ungoverned agents

Every iris scan or iris certify is a weekly active developer event.
"""

import click
import sys
from pathlib import Path
from typing import Any
from rich.console import Console
from rich.panel import Panel

from iris_core.cli_timing.instrument import timed_cli_command

console = Console()


class IrisCLI(click.Group):
    """Click group that records daily aggregated CLI usage after each command."""

    def invoke(self, ctx: click.Context) -> Any:
        result = super().invoke(ctx)
        if not ctx.resilient_parsing:
            command = self._resolved_command(ctx)
            if command:
                from iris._telemetry import maybe_record_cli_usage

                maybe_record_cli_usage(command)
        return result

    @staticmethod
    def _resolved_command(ctx: click.Context) -> str | None:
        if ctx.invoked_subcommand is None:
            return None
        if ctx.command_path:
            return " ".join(ctx.command_path)
        return ctx.invoked_subcommand


@click.group(cls=IrisCLI)
@click.version_option(
    version="0.2.16",
    prog_name="iris",
    message="%(prog)s %(version)s · AARM Core conformant (R1–R6) · "
            "AIUC-1 Q1 2026 aligned · https://iris-security.io",
)
def cli():
    """
    IRIS — Policy as Code for AI Agents

    Declare, enforce, witness, and certify AI agent governance.

    Core commands:
      declare    Declare what an agent is allowed to do
      compile    Compile plain English intent to Cedar policy
      preview    Show risk impact of policy changes before applying
      enforce    Verify runtime enforcement is active
      witness    Live feed of every policy decision
      certify    Prove compliance to any regulatory framework
      sentinel   Continuous governance monitoring and alerting

    Discovery:
      quickstart  Get started in 2 minutes with no API key
      scan        Find ungoverned agents in any codebase

    Visibility:
      list        List all governed agents (alias: agents)
      status      Compliance dashboard for all governed agents
      evidence    Audit trail and regulator-ready reports
        list      List recent vault events
        query     Filter vault by agent, decision, regulation, risk
        report    Full audit report for one agent
        export    Export for auditors (JSON, CSV, AIUC-1, OTel)
        stats     Aggregate stats across all agents
      cost        Token cost tracking per agent, tool, and model

    Intelligence:
      framework   Get an opinionated compliance action plan
      regulatory  Track AI law changes across frameworks

    Security:
      red-team    Adversarial policy bypass testing (Pro)
      dlp         Prompt and response content inspection
    """
    from iris._telemetry import maybe_fire_first_run

    maybe_fire_first_run()


# ── iris scan ─────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--dir", "scan_dir", type=Path, default=Path.cwd(), help="Directory to scan")
@click.option("--framework", "-f", default=None, help="Compliance framework (e.g. colorado-ai-act)")
@click.option("--format", "output_format", default="table", type=click.Choice(["table", "json", "markdown"]))
@click.option("--fail-on", default="critical", type=click.Choice(["critical", "high", "any"]))
@click.option(
    "--discover",
    is_flag=True,
    help="Scan Python/TypeScript source files for ungoverned AI agent patterns",
)
@click.option(
    "--auto-register",
    is_flag=True,
    help="Write passport.yaml drafts for each ungoverned finding (does not register)",
)
@click.option(
    "--govern",
    is_flag=True,
    help="Register discovered agents and show one-line IRIS governance changes",
)
@click.option(
    "--no-auto-apply",
    is_flag=True,
    help="With --govern, show changes without applying them to source files",
)
@click.option(
    "--compliance",
    "govern_compliance",
    default="colorado-ai-act",
    help="Compliance framework for --govern registration (default: colorado-ai-act)",
)
@click.option(
    "--yes",
    "-y",
    "govern_yes",
    is_flag=True,
    help="With --govern, skip confirmation and proceed automatically",
)
def scan(
    scan_dir: Path,
    framework: str,
    output_format: str,
    fail_on: str,
    discover: bool,
    auto_register: bool,
    govern: bool,
    no_auto_apply: bool,
    govern_compliance: str,
    govern_yes: bool,
):
    """
    Scan governance directory for policy violations.

    Finds all passport.yaml files and checks them against the
    configured compliance frameworks. Exits with code 1 if violations
    above the --fail-on threshold are found (for CI integration).

    With --discover, also crawls Python and TypeScript files for ungoverned
    LLM/agent patterns (LangChain, OpenAI, Anthropic, CrewAI, etc.).

    Examples:
      iris scan
      iris scan --framework colorado-ai-act
      iris scan --discover
      iris scan --discover --auto-register
      iris scan --format json | jq '.violations[]'
    """
    from iris import iris_scan
    from iris_core.models.policy import Severity

    if discover:
        from iris_core.discovery.scanner import CodebaseScanner
        from iris_core.models.passport import AgentPassport, ComplianceTag, DataClassification
        from iris_cli.scan_report import render_discover_scan

        scanner = CodebaseScanner()
        discover_result = scanner.scan_directory(scan_dir)
        drafts_written = []

        if auto_register:
            gov_root = scan_dir / "governance" / "agents"
            for finding in discover_result.ungoverned_findings:
                agent_dir = gov_root / finding.agent_name_hint
                passport_path = agent_dir / "passport.yaml"
                if passport_path.exists():
                    continue
                agent_dir.mkdir(parents=True, exist_ok=True)
                draft = AgentPassport(
                    name=finding.agent_name_hint,
                    owner="CHANGE_ME@company.com",
                    team="CHANGE_ME",
                    compliance_tags=[ComplianceTag.COLORADO_AI_ACT],
                    data_classification=DataClassification.INTERNAL,
                    is_high_risk_ai="--high-risk" in finding.suggested_command,
                    description=(
                        f"Auto-drafted from ungoverned scan finding in "
                        f"{finding.file_path}:{finding.line_number}"
                    ),
                )
                passport_path.write_text(draft.to_yaml())
                drafts_written.append(passport_path)

        if output_format == "json":
            import json

            payload = {
                "scan_timestamp": discover_result.scan_timestamp,
                "files_scanned": discover_result.files_scanned,
                "lines_scanned": discover_result.lines_scanned,
                "governed_agents": [p.name for p in discover_result.governed_agents],
                "ungoverned_findings": [
                    {
                        "file_path": f.file_path,
                        "line_number": f.line_number,
                        "pattern_matched": f.pattern_matched,
                        "framework_detected": f.framework_detected,
                        "agent_name_hint": f.agent_name_hint,
                        "suggested_command": f.suggested_command,
                        "risk_level": f.risk_level,
                        "risk_reason": f.risk_reason,
                    }
                    for f in discover_result.ungoverned_findings
                ],
                "shadow_agents": [
                    {
                        "resource_path": s.resource_path,
                        "resource_name": s.resource_name,
                        "namespace": s.namespace,
                        "reason": s.reason,
                    }
                    for s in discover_result.shadow_agents
                ],
            }
            click.echo(json.dumps(payload, indent=2))
        else:
            render_discover_scan(
                console,
                discover_result,
                scan_dir,
                framework=framework,
                auto_register=auto_register,
                drafts_written=drafts_written,
            )

        if govern and discover_result.ungoverned_findings:
            from iris_cli.scan_govern import run_govern_flow

            run_govern_flow(
                discover_result.ungoverned_findings,
                scan_dir,
                govern_compliance,
                no_auto_apply,
                govern_yes,
                console,
            )
            sys.exit(0)

        if discover_result.ungoverned_findings:
            sys.exit(1)
        sys.exit(0)

    console.print(Panel(
        f"[bold]IRIS Governance Scan[/bold]\n"
        f"Directory: {scan_dir}\n"
        f"Framework: {framework or 'all active bundles'}",
        style="blue"
    ))

    violations = iris_scan(directory=scan_dir, framework=framework)

    if not violations:
        console.print("\n[bold green]✓ All agents passed compliance check[/bold green]")
        sys.exit(0)

    if output_format == "table":
        from iris_cli.scan_report import render_violations_table

        render_violations_table(console, violations)

    elif output_format == "json":
        import json
        output = [{"rule_id": v.rule_id, "severity": v.severity.value, "message": v.message, "remediation": v.remediation, "compliance_refs": v.compliance_refs} for v in violations]
        click.echo(json.dumps(output, indent=2))

    threshold_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "any": Severity.LOW}
    threshold = threshold_map[fail_on]
    blocking = [v for v in violations if v.severity.value >= threshold.value]
    if blocking:
        sys.exit(1)


# ── iris declare (primary) / iris register (legacy alias) ─────────────────────

from iris_cli.declare import declare

cli.add_command(declare)
cli.add_command(declare, name="register")


# ── iris compile (alias for policy compile) ───────────────────────────────────

@cli.group()
def policy():
    """
    Policy management commands.

    policy
      compile     Compile intent to Cedar (alias: iris compile)
      status      Check policy binding and staleness
      commit      Apply compiled draft to governance directory
      diff        Show diff between draft and current policy
    """
    pass


@policy.command("compile")
@click.option("--agent", required=True, help="Agent name")
@click.option("--intent", type=Path, default=None, help="Path to policy-intent.md")
@click.option("--dir", "governance_dir", type=Path, default=None)
@click.option("--dry-run", is_flag=True, help="Show generated Cedar without writing to disk")
@click.option(
    "--backend",
    default=None,
    type=click.Choice([
        "anthropic", "openai", "google",
        "mistral", "groq", "ollama", "together",
    ]),
    help="LLM backend. Auto-detected from API keys if not set.",
)
@click.option(
    "--litellm-model",
    default=None,
    help="Any LiteLLM model string e.g. ollama/llama3.2, bedrock/claude-3-5-sonnet",
)
@click.option("--model", default=None, help="Model name override for the chosen backend.")
def policy_compile(agent, intent, governance_dir, dry_run, backend, litellm_model, model):
    """
    Compile policy-intent.md to Cedar using any LLM.

    Auto-detects your API key, or specify explicitly:

      iris policy compile --agent my-agent
      iris policy compile --agent my-agent --backend openai
      iris policy compile --agent my-agent --litellm-model ollama/llama3.2
      iris policy compile --agent my-agent --litellm-model bedrock/claude-3-5-sonnet
    """
    from pathlib import Path

    from iris_core.models.passport import AgentPassport

    from iris_cli.compiler_config import compiler_info, create_policy_compiler
    from iris_cli.policy_cache import save_policy_draft

    gov_dir = governance_dir or Path.cwd() / "governance" / "agents" / agent
    passport_file = gov_dir / "passport.yaml"
    intent_file = intent or gov_dir / "policy-intent.md"

    if not passport_file.exists():
        console.print(f"[red]Passport not found: {passport_file}[/red]")
        console.print(f"Run: iris register --name {agent}")
        sys.exit(1)

    if not intent_file.exists():
        console.print(f"[red]Intent file not found: {intent_file}[/red]")
        sys.exit(1)

    passport = AgentPassport.from_yaml(passport_file.read_text())
    intent_text = intent_file.read_text()

    with console.status(f"[bold blue]Compiling policy for {agent}...[/bold blue]"):
        compiler = create_policy_compiler(
            llm_backend=backend,
            model=model,
            litellm_model=litellm_model,
        )
        result = compiler.compile(intent_text, passport)

    if result.has_blocking_violations():
        console.print("\n[bold red]Policy compilation blocked[/bold red]")
        for v in result.violations:
            console.print(f"\n[red]✗ {v.rule_id}[/red]: {v.message}")
            console.print(f"  [yellow]Remediation:[/yellow] {v.remediation}")
        console.print("\n[yellow]Contact your security engineer to resolve these violations.[/yellow]")
        sys.exit(1)

    backend, model = compiler_info(compiler)
    draft_path = save_policy_draft(
        gov_dir, intent_text, result.cedar_policy, backend, model
    )

    if dry_run:
        console.print("\n[bold]Generated Cedar policy (dry run):[/bold]")
        console.print(result.cedar_policy)
        console.print(f"\n[dim]Draft cached: {draft_path}[/dim]")
        console.print(f"[dim]Run: iris policy diff --agent {agent}[/dim]")
    else:
        (gov_dir / "policy.cedar").write_text(result.cedar_policy)
        console.print(f"[bold green]✓ Policy compiled: {gov_dir / 'policy.cedar'}[/bold green]")
        console.print(f"[dim]Draft cached: {draft_path}[/dim]")

    if result.warnings:
        for w in result.warnings:
            console.print(f"[yellow]Warning:[/yellow] {w}")


from iris_cli.policy_diff import policy_diff
policy.add_command(policy_diff)

from iris_cli.policy_status import policy_status
policy.add_command(policy_status)

from iris_cli.policy_commit import policy_commit
policy.add_command(policy_commit)

from iris_cli.preview import preview

cli.add_command(preview)

@cli.command("compile")
@click.option("--agent", required=True, help="Agent name")
@click.option("--intent", type=Path, default=None, help="Path to policy-intent.md")
@click.option("--dir", "governance_dir", type=Path, default=None)
@click.option("--dry-run", is_flag=True, help="Show generated Cedar without writing to disk")
@click.option(
    "--backend",
    default=None,
    type=click.Choice([
        "anthropic", "openai", "google",
        "mistral", "groq", "ollama", "together",
    ]),
    help="LLM backend. Auto-detected from API keys if not set.",
)
@click.option(
    "--litellm-model",
    default=None,
    help="Any LiteLLM model string e.g. ollama/llama3.2, bedrock/claude-3-5-sonnet",
)
@click.option("--model", default=None, help="Model name override for the chosen backend.")
@timed_cli_command("iris compile")
def compile_cmd(agent, intent, governance_dir, dry_run, backend, litellm_model, model):
    """Compile policy-intent.md to Cedar (alias: iris policy compile)."""
    ctx = click.get_current_context()
    ctx.invoke(
        policy_compile,
        agent=agent,
        intent=intent,
        governance_dir=governance_dir,
        dry_run=dry_run,
        backend=backend,
        litellm_model=litellm_model,
        model=model,
    )


cli.add_command(policy)


# ── iris license ───────────────────────────────────────────────────────────────

from iris_cli.license_cmd import license

cli.add_command(license)


# ── iris compliance ────────────────────────────────────────────────────────────

@cli.group()
def compliance():
    """Compliance checking and reporting commands."""
    pass


@cli.group()
def framework():
    """Framework discovery and recommendation commands."""
    pass


from iris_cli.framework_suggest import framework_suggest
framework.add_command(framework_suggest, name="suggest")

# Wire in the assess command
from iris_cli.assess import compliance_assess
compliance.add_command(compliance_assess)

# Wire in evidence commands
from iris_cli.evidence import evidence
cli.add_command(evidence)

from iris_cli.vault import vault
cli.add_command(vault)

from iris_cli.framework_test import test as framework_test_cmd_legacy
# framework_test kept for internal imports; certify is the primary command

from iris_cli.scm import scm
cli.add_command(scm)

from iris_cli.discover import discover
cli.add_command(discover)

from iris_cli.explain import explain_cmd
cli.add_command(explain_cmd, name="explain")

from iris_cli.witness import witness_cmd
cli.add_command(witness_cmd, name="witness")
cli.add_command(witness_cmd, name="watch")  # legacy alias

from iris_cli.enforce import enforce
cli.add_command(enforce)

from iris_cli.sentinel import sentinel
cli.add_command(sentinel)

from iris_cli.certify import certify_cmd, test as certify_test_alias
cli.add_command(certify_cmd, name="certify")
cli.add_command(certify_test_alias, name="test")  # legacy alias

from iris_cli.status_cmd import status_cmd
cli.add_command(status_cmd, name="status")

from iris_cli.list_cmd import list_cmd
cli.add_command(list_cmd, name="list")
cli.add_command(list_cmd, name="agents")

from iris_cli.quickstart import quickstart_cmd
cli.add_command(quickstart_cmd, name="quickstart")

from iris_cli.onboarding_report import onboarding_report
cli.add_command(onboarding_report, name="onboarding-report")

from iris_cli.entitlements_cmd import entitlements_cmd
cli.add_command(entitlements_cmd, name="entitlements")

from iris_cli.dlp_cmd import dlp
cli.add_command(dlp)

from iris_cli.drift import drift
cli.add_command(drift)

from iris_cli.redteam import red_team
cli.add_command(red_team)

from iris_cli.users import users
cli.add_command(users)

from iris_cli.cost import cost
cli.add_command(cost)

from iris_cli.models_cmd import models
cli.add_command(models)

from iris_cli.regulatory import regulatory
cli.add_command(regulatory)

from iris_cli.delegation import delegation
cli.add_command(delegation)

from iris_cli.hitl import hitl
cli.add_command(hitl)

from iris_cli.org_policy import org_policy
cli.add_command(org_policy, name="org-policy")

from iris_cli.audit_log import audit_log
cli.add_command(audit_log, name="audit-log")


@cli.command("ping", hidden=True)
def ping():
    """Internal telemetry verification (hidden)."""
    from iris._telemetry import send_ping, telemetry_enabled

    if not telemetry_enabled():
        return

    send_ping()
    click.echo("Telemetry ping sent. Opt-out status: enabled")


from iris_cli.compliance_check_cmd import compliance_check_cmd
compliance.add_command(compliance_check_cmd, name="check")

from iris_cli.compliance_scan_cmd import compliance_scan_cmd
compliance.add_command(compliance_scan_cmd, name="scan")

cli.add_command(compliance)
cli.add_command(framework)


if __name__ == "__main__":
    cli()


@cli.group()
def mcp():
    """MCP server commands for Cursor IDE integration."""
    pass


@mcp.command("start")
def mcp_start():
    """
    Start the IRIS MCP server for Cursor IDE.

    Cursor connects to this server to get real-time compliance
    feedback as you write agent code.

    Example:
      iris mcp start
    """
    from iris_cli.mcp_server import start
    console.print("[bold blue]IRIS MCP server starting on stdio...[/bold blue]")
    console.print("[dim]Cursor is now connected to IRIS governance.[/dim]")
    start()


cli.add_command(mcp)
