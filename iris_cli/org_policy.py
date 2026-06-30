"""iris org-policy — hybrid organizational security policy commands."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from iris_core.org_policy.enforcement import ABSOLUTE_BLOCKS, EnforcementLevel
from iris_core.org_policy.loader import OrgPolicyLoader
from iris_core.org_policy.models import OrgPolicy, ResolvedPolicy
from iris_core.org_policy.validator import HybridPolicyValidator

console = Console()

ORG_TEMPLATE = """# iris-security.yaml — organizational baseline
version: "1.0"
schema: "iris-org-policy/v1"
organization: "Your Organization"
enforced_by: "security-team@your-org.com"
contact: "security@your-org.com"
last_reviewed: "{today}"
review_cadence: quarterly

environments:
  default:
    enforcement_level: warn
    frameworks: []
    vault_retention_days: 30
    hitl_enabled: false
    description: "Fallback for any undeclared environment"

  dev:
    enforcement_level: warn
    frameworks: []
    vault_retention_days: 7
    hitl_enabled: false
    description: "Local developer machines and feature branches"

  ci:
    enforcement_level: observe
    frameworks:
      - colorado-ai-act
    vault_retention_days: 7
    hitl_enabled: false
    description: "CI pipeline runs — observed, not enforced"

  staging:
    enforcement_level: warn
    frameworks:
      - colorado-ai-act
      - nist-ai-rmf
    vault_retention_days: 30
    hitl_enabled: false
    description: "Pre-production validation environment"

  production:
    enforcement_level: enforce
    frameworks:
      - colorado-ai-act
      - nist-ai-rmf
    vault_retention_days: 1095
    hitl_enabled: true
    description: "Production — full enforcement"

mandatory_compliance_tags:
  - colorado-ai-act

forbidden_regions_always:
  - cn-north-1
  - cn-northwest-1

agent_standards:
  owner_must_be_team_email: true
  team_required: true
  description_minimum_length: 50
  allow_unclassified_in_production: false

high_risk_requirements:
  require_impact_assessment: true
  require_non_discrimination_review: true
  minimum_vault_retention_days: 1095

security_logging:
  format: opentelemetry
  destination: splunk
  endpoint: ${{IRIS_SIEM_ENDPOINT}}
  api_key_env: IRIS_SIEM_API_KEY
  minimum_event_level: WARN
  pii_redaction: true
  send_for_environments:
    - production

hitl_baseline:
  timeout_policy: deny
  escalation_seconds: 300
  notify_channels:
    slack_webhook: ${{IRIS_SLACK_WEBHOOK}}
    email: security-alerts@your-org.com
"""

PROJECT_TEMPLATE = """# .iris-security — project-specific restrictions (inherits org baseline)
version: "1.0"
schema: "iris-project-policy/v1"

extends:
  url: ${{IRIS_SECURITY_POLICY_URL}}
  path: iris-security.yaml

project: "your-project-name"
team: "your-team@your-org.com"

environment_overrides:
  production:
    additional_frameworks: []
    # vault_retention_days: 2190  # increase only — cannot decrease org minimum
"""


def _format_cache_age(hours: float) -> str:
    if hours < 1:
        return f"{int(hours * 60)} minutes ago"
    return f"{int(hours)} hours ago"


def _render_resolution_box(policy: ResolvedPolicy, errors: list) -> None:
    baseline = policy.source_url or policy.org_baseline.source_path or "builtin default"
    override = "—"
    if policy.project_override:
        override = (
            f"{policy.project_override.source_path} "
            f"({policy.project_override.project or 'project override'})"
        )
    cached = ""
    if policy.cache_age_hours > 0:
        remaining = max(0, OrgPolicyLoader.DEFAULT_CACHE_TTL_HOURS - policy.cache_age_hours)
        cached = (
            f"\n│ Cached:        {_format_cache_age(policy.cache_age_hours)} "
            f"(valid for {int(remaining)} more hours)"
        )
    status = "VALID — no relaxation violations" if not errors else f"INVALID — {len(errors)} issue(s)"
    console.print(
        Panel(
            f"Org baseline:  {baseline}{cached}\n"
            f"Local override: {override}\n"
            f"Status:        {status}",
            title="IRIS Policy Resolution",
            border_style="green" if not errors else "red",
        )
    )


def _render_environments_table(policy: ResolvedPolicy) -> None:
    table = Table(title=f"ENVIRONMENTS ({len(policy.environment_names())} defined)", show_header=True)
    table.add_column("Environment")
    table.add_column("Enforcement")
    table.add_column("Frameworks")
    table.add_column("Retention")
    for name in policy.environment_names():
        env = policy.get_environment(name)
        frameworks = policy.get_effective_frameworks(name)
        fw_display = ", ".join(frameworks) if frameworks else "none"
        marker = ""
        if policy.project_override and name in policy.project_override.environment_overrides:
            marker = "*"
        table.add_row(
            name,
            f"{policy.get_enforcement_level(name).value}{marker}",
            fw_display,
            f"{env.vault_retention_days} days",
        )
    console.print(table)
    if policy.project_override:
        console.print("[dim]* project override applied[/dim]")


@click.group()
def org_policy():
    """Organizational security policy — hybrid baseline + project overrides."""
    pass


@org_policy.command("init")
@click.option("--type", "policy_type", type=click.Choice(["org", "project"]), default="org")
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file path")
def org_policy_init(policy_type: str, output: Optional[str]):
    """Create a starter org baseline or project override file."""
    today = datetime.now(timezone.utc).date().isoformat()
    if policy_type == "org":
        content = ORG_TEMPLATE.format(today=today)
        path = Path(output or "iris-security.yaml")
    else:
        content = PROJECT_TEMPLATE
        path = Path(output or ".iris-security")
    path.write_text(content)
    console.print(f"[green]✓[/green] Created {path}")


@org_policy.command("validate")
@click.option("--file", "policy_file", type=click.Path(exists=True), default=None)
@click.option("--env", "environment", default=None, help="Show effective config for one environment")
@click.option("--check-agents", is_flag=True, help="Check agent impact (summary)")
@click.option("--strict", is_flag=True)
@click.option(
    "--fail-on",
    default="",
    help="Comma-separated: relaxation,schema,unknown-framework",
)
def org_policy_validate(
    policy_file: Optional[str],
    environment: Optional[str],
    check_agents: bool,
    strict: bool,
    fail_on: str,
):
    """Validate policy files and show effective configuration."""
    root = Path.cwd()
    loader = OrgPolicyLoader(root)
    if policy_file:
        text = Path(policy_file).read_text()
        policy = OrgPolicy.from_yaml(text, source_path=policy_file)
        if policy.schema == "iris-org-policy/v1":
            resolved = ResolvedPolicy(org_baseline=policy, is_default=False)
        else:
            baseline = loader.load_fallback()
            resolved = ResolvedPolicy(org_baseline=baseline, project_override=policy, is_default=False)
    else:
        resolved = loader.load(root)

    errors = []
    if resolved.project_override:
        errors = HybridPolicyValidator().validate_project_override(
            resolved.project_override, resolved.org_baseline
        )

    _render_resolution_box(resolved, errors)
    _render_environments_table(resolved)

    console.print("\n[bold]ABSOLUTE BLOCKS (all environments):[/bold]")
    console.print("✓ " + ", ".join(sorted(ABSOLUTE_BLOCKS)))

    if environment:
        ctx = click.get_current_context()
        ctx.invoke(org_policy_show, env=environment)

    fail_modes = {m.strip() for m in fail_on.split(",") if m.strip()}
    if strict and not fail_modes:
        fail_modes = {"relaxation", "schema"}

    if errors and ("relaxation" in fail_modes or strict):
        for err in errors:
            console.print(f"[red]✗[/red] {err.message}")
        sys.exit(1)

    if check_agents:
        console.print("\n[dim]Run: iris org-policy diff to see agent impact[/dim]")


@org_policy.command("show")
@click.option("--env", "environment", required=True, help="Environment name to display")
def org_policy_show(environment: str):
    """Show complete effective policy for one environment."""
    resolved = OrgPolicyLoader().load()
    org_env = resolved.org_baseline.environments.get(environment)
    proj_env = (
        resolved.project_override.environment_overrides.get(environment)
        if resolved.project_override
        else None
    )
    effective = resolved.get_environment(environment)
    frameworks = resolved.get_effective_frameworks(environment)

    table = Table(title=f"Effective Policy: {environment}", show_header=True)
    table.add_column("")
    table.add_column("Org Baseline")
    table.add_column("Project Override")
    table.add_column("Effective")

    org_level = org_env.enforcement_level.value if org_env else "—"
    proj_level = proj_env.enforcement_level.value if proj_env else "—"
    table.add_row(
        "enforcement_level",
        org_level,
        proj_level if proj_env else "—",
        effective.enforcement_level.value,
    )

    org_fw = ", ".join(org_env.frameworks) if org_env and org_env.frameworks else "—"
    proj_fw = "—"
    if proj_env and proj_env.additional_frameworks:
        proj_fw = "+" + ", +".join(proj_env.additional_frameworks)
    table.add_row("frameworks", org_fw, proj_fw, f"[{len(frameworks)} total]")

    org_ret = f"{org_env.vault_retention_days} days" if org_env else "—"
    proj_ret = f"{proj_env.vault_retention_days} days" if proj_env and proj_env.vault_retention_days else "—"
    table.add_row("vault_retention", org_ret, proj_ret, f"{effective.vault_retention_days} days")
    table.add_row(
        "hitl_enabled",
        str(org_env.hitl_enabled) if org_env else "—",
        str(proj_env.hitl_enabled) if proj_env else "—",
        str(effective.hitl_enabled),
    )
    console.print(table)
    if frameworks:
        console.print(f"Frameworks: {', '.join(frameworks)}")


@org_policy.command("diff")
@click.option("--base", default="main", help="Git base branch for comparison")
@click.option("--format", "output_format", default="text", type=click.Choice(["text", "markdown"]))
def org_policy_diff(base: str, output_format: str):
    """Show policy changes vs base branch and agent impact."""
    console.print(f"[bold]POLICY CHANGES — comparing current branch to {base}[/bold]\n")
    try:
        result = subprocess.run(
            ["git", "diff", f"{base}...HEAD", "--", ".iris-security", "iris-security.yaml"],
            capture_output=True,
            text=True,
            check=False,
        )
        diff_text = result.stdout.strip()
        if diff_text:
            console.print(diff_text)
        else:
            console.print("[dim]No policy file changes detected.[/dim]")
    except FileNotFoundError:
        console.print("[yellow]Git not available — showing current policy only.[/yellow]")

    gov = Path.cwd() / "governance" / "agents"
    affected = 0
    if gov.exists():
        for passport in gov.rglob("passport.yaml"):
            affected += 1
    console.print(f"\n[bold]AGENT IMPACT:[/bold]")
    if affected:
        console.print(f"{affected} agent(s) would be affected by this change.")
    else:
        console.print("[dim]No agents found under governance/agents/[/dim]")
    console.print("Run: [cyan]iris certify --env staging[/cyan] to see updated compliance status.")


@org_policy.command("cache")
@click.option("--clear", "do_clear", is_flag=True)
@click.option("--refresh", "do_refresh", is_flag=True)
def org_policy_cache(do_clear: bool, do_refresh: bool):
    """Manage the local org policy cache."""
    loader = OrgPolicyLoader()
    if do_clear:
        count = loader.clear_cache()
        console.print(f"[green]✓[/green] Cleared {count} cached policy file(s)")
        return
    if do_refresh:
        try:
            policy = loader.refresh_cache()
            console.print(f"[green]✓[/green] Refreshed policy: {policy.organization or policy.project}")
        except ValueError as exc:
            console.print(f"[red]{exc}[/red]")
            sys.exit(1)
        return
    cache_dir = loader.CACHE_DIR
    if cache_dir.exists():
        files = list(cache_dir.glob("*.json"))
        console.print(f"Cache directory: {cache_dir} ({len(files)} file(s))")
    else:
        console.print("Policy cache is empty.")


@org_policy.command("audit")
@click.option("--days", default=90, help="Days of Git history to scan")
def org_policy_audit(days: int):
    """Show policy changes from Git history."""
    since = f"{days} days ago"
    try:
        result = subprocess.run(
            [
                "git", "log", f"--since={since}", "--pretty=format:%h %an %ad %s",
                "--", ".iris-security", "iris-security.yaml",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.stdout.strip():
            console.print(result.stdout)
        else:
            console.print(f"[dim]No policy changes in the last {days} days.[/dim]")
    except FileNotFoundError:
        console.print("[red]Git is required for audit.[/red]")
        sys.exit(1)
