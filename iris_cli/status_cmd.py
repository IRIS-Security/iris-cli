"""iris status — git status for compliance."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.panel import Panel

from iris import AgentPassport
from iris_cli.action_plan import compliance_score, progress_bar
from iris_core.compliance.registry import ComplianceRegistry
from iris_core.cost.tracker import discover_agent_trackers
from iris_core.entitlements.display import build_status_tier_footer

console = Console()


def _discover_agents(governance_dir: Path) -> List[tuple[str, Path]]:
    agents: list[tuple[str, Path]] = []
    if not governance_dir.exists():
        return agents
    for passport_file in sorted(governance_dir.rglob("passport.yaml")):
        try:
            passport = AgentPassport.from_yaml(passport_file.read_text())
            agents.append((passport.name, passport_file.parent))
        except Exception:
            continue
    return agents


def _next_action(passport: AgentPassport, agent_dir: Path) -> Optional[str]:
    registry = ComplianceRegistry()
    violations = registry.check_passport(passport, "colorado-ai-act")
    if violations:
        return violations[0].remediation
    if not (agent_dir / "policy.cedar").exists():
        return f"iris policy compile --agent {passport.name}"
    return None


def _status_label(score: float, violations: bool) -> str:
    if score >= 1.0 and not violations:
        return "PROD READY"
    if score >= 0.6:
        return f"{int((1 - score) * 10)} actions needed"
    if score > 0:
        return f"{int((1 - score) * 10)} actions needed"
    return "NOT REGISTERED"


def _monthly_cost_by_agent(days: int = 30) -> dict[str, float]:
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    costs: dict[str, float] = {}
    for tracker in discover_agent_trackers():
        summary = tracker.get_summary(since=since)
        costs[tracker.agent_name] = summary.estimated_monthly_cost
        costs[tracker.agent_id] = summary.estimated_monthly_cost
    return costs


@click.command("status")
@click.option("--agent", default=None, help="Show status for a specific agent")
@click.option("--dir", "governance_dir", type=click.Path(path_type=Path), default=None)
@click.option("--include-demo", is_flag=True, help="Also scan demo/governance/agents")
def status_cmd(agent: Optional[str], governance_dir: Optional[Path], include_demo: bool) -> None:
    """Single-pane view of agent compliance scores and next actions."""
    dirs: List[Path] = []
    if governance_dir:
        dirs.append(governance_dir)
    else:
        dirs.append(Path.cwd() / "governance" / "agents")
    demo_dir = Path.cwd() / "demo" / "governance" / "agents"
    if (include_demo or demo_dir.exists()) and demo_dir not in dirs:
        if demo_dir.exists():
            dirs.append(demo_dir)

    all_agents: dict[str, Path] = {}
    for d in dirs:
        for name, agent_dir in _discover_agents(d):
            if agent not in (None, name):
                continue
            all_agents[name] = agent_dir

    if not all_agents:
        console.print("[yellow]No agents registered.[/yellow]")
        console.print("Run: [cyan]iris register --name my-agent --compliance colorado-ai-act[/cyan]")
        return

    lines = [f"Agents governed: {len(all_agents)}", ""]
    registry = ComplianceRegistry()
    next_global: Optional[str] = None
    lowest_score = 2.0
    monthly_costs = _monthly_cost_by_agent()

    for name in sorted(all_agents):
        agent_dir = all_agents[name]
        passport = AgentPassport.from_yaml((agent_dir / "passport.yaml").read_text())
        score = compliance_score(passport, agent_dir, "colorado-ai-act")
        violations = registry.check_passport(passport, "colorado-ai-act")
        bar = progress_bar(score)
        pct = int(score * 100)
        label = _status_label(score, bool(violations))
        if score < 1.0 and score < lowest_score:
            lowest_score = score
            next_global = _next_action(passport, agent_dir)

        color = "green" if score >= 1.0 else "yellow" if score >= 0.4 else "red"
        cost = monthly_costs.get(name) or monthly_costs.get(passport.agent_id)
        cost_str = f"  ${cost:.2f}/mo" if cost else ""
        lines.append(
            f"  [{color}]{name:<24}[/{color}]  {bar} {pct:>3}%  {label}{cost_str}"
        )
        if passport.user_delegation_enabled:
            scopes = passport.allowed_delegation_scopes or ["any scope permitted"]
            scope_str = ", ".join(scopes) if isinstance(scopes, list) else str(scopes)
            consent = "yes" if passport.require_user_consent_for_delegation else "no"
            lines.append(
                f"    └─ Delegation: enabled · scopes: {scope_str}"
            )
            lines.append(
                f"       Consent required: {consent} · Audit: per-call"
            )

    lines.append("")
    if next_global:
        lines.append("Next action:")
        lines.append(f"  {next_global}")
    else:
        lines.append("All registered agents are production-ready.")

    lines.append(build_status_tier_footer())

    console.print(Panel("\n".join(lines), title="IRIS Status", style="blue"))
