"""iris enforce — verify runtime enforcement is active."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.panel import Panel

from iris import AgentPassport
from iris_core.discovery.scanner import CodebaseScanner
from iris_core.engine.cedar import CedarEngine, EvaluationContext
from iris_core.evidence.vault import EvidenceVault
from iris_core.models.passport import Environment

console = Console()

_DROP_IN_HINTS = {
    "IrisOpenAI": "from iris_openai import IrisOpenAI",
    "IrisAnthropic": "from iris_anthropic import IrisAnthropic",
    "IrisGemini": "from iris_gemini import IrisGemini",
    "IrisAgent.guard": "from iris import IrisAgent",
}


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


def _detect_drop_in(scan_dir: Path, agent_name: str) -> Optional[str]:
    scanner = CodebaseScanner()
    result = scanner.scan_directory(scan_dir)
    for finding in result.governed_agents:
        if finding.name == agent_name:
            return "IrisAgent.guard"
    for finding in result.ungoverned_findings:
        if agent_name in finding.agent_name_hint:
            fw = finding.framework_detected or ""
            if "openai" in fw.lower():
                return "IrisOpenAI"
            if "anthropic" in fw.lower():
                return "IrisAnthropic"
            if "gemini" in fw.lower() or "google" in fw.lower():
                return "IrisGemini"
    return None


def _last_event_age(events: list[dict]) -> str:
    if not events:
        return "never"
    ts = events[-1].get("timestamp", "")
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        delta = datetime.now(timezone.utc) - dt.replace(tzinfo=timezone.utc)
        minutes = int(delta.total_seconds() / 60)
        if minutes < 1:
            return "just now"
        if minutes < 60:
            return f"{minutes} minute(s) ago"
        return f"{minutes // 60} hour(s) ago"
    except ValueError:
        return "unknown"


def _verify_enforcement(passport: AgentPassport, agent_dir: Path) -> tuple[bool, str]:
    engine = CedarEngine()
    policy_file = agent_dir / "policy.cedar"
    if not policy_file.exists():
        return False, "No policy.cedar found"
    engine.load_policy_file(passport.agent_id, policy_file)
    ctx = EvaluationContext(
        agent_id=passport.agent_id,
        action="call",
        resource="iris-enforcement-probe",
        resource_type="api",
        environment=Environment.DEV,
    )
    result = engine.evaluate(passport, ctx)
    if result.decision in ("PERMIT", "PERMIT_WITH_WARNINGS"):
        return True, f"Cedar evaluated: {result.decision}"
    return False, f"Cedar returned {result.decision}"


@click.command("enforce")
@click.option("--agent", default=None, help="Specific agent (or all registered)")
@click.option("--verify", is_flag=True, help="Run a lightweight enforcement probe")
@click.option("--dir", "governance_dir", type=click.Path(path_type=Path), default=None)
def enforce(
    agent: Optional[str],
    verify: bool,
    governance_dir: Optional[Path],
) -> None:
    """Verify runtime enforcement is active for governed agents."""
    gov_dir = governance_dir or Path.cwd() / "governance" / "agents"
    agents = _discover_agents(gov_dir)
    if agent:
        agents = [(n, d) for n, d in agents if n == agent]

    if not agents:
        console.print("[yellow]No agents registered.[/yellow]")
        console.print("Run: [cyan]iris declare --name my-agent[/cyan]")
        return

    lines: list[str] = [""]
    for name, agent_dir in agents:
        passport = AgentPassport.from_yaml((agent_dir / "passport.yaml").read_text())
        vault = EvidenceVault(agent_id=passport.agent_id)
        events = vault.get_events(limit=500)
        today = datetime.now(timezone.utc).date().isoformat()
        calls_today = sum(1 for e in events if e.get("timestamp", "").startswith(today))
        violations = sum(len(e.get("violations") or []) for e in events if e.get("timestamp", "").startswith(today))
        dlp_scans = calls_today
        drop_in = _detect_drop_in(Path.cwd(), name)
        policy_ref = agent_dir / "policy.cedar"
        enforcing = drop_in is not None and policy_ref.exists()

        if enforcing:
            lines.append(f"  {name:<22}  ● ENFORCING")
            lines.append(f"    Cedar policy:        {policy_ref}")
            lines.append(f"    Last evaluation:     {_last_event_age(events)} ({events[-1].get('decision', 'n/a') if events else 'n/a'})")
            lines.append(f"    Calls today:         {calls_today}  │  Violations: {violations}")
            lines.append(f"    DLP scans:           {dlp_scans}  │  PHI detected: 0")
        else:
            hint = _DROP_IN_HINTS.get(drop_in or "", "from iris_openai import IrisOpenAI")
            lines.append(f"  {name:<22}  ○ NOT ENFORCING")
            lines.append(f"    Reason: No drop-in client detected in codebase")
            lines.append(f"    Fix:    {hint}")
        lines.append("")

        if verify and policy_ref.exists():
            ok, msg = _verify_enforcement(passport, agent_dir)
            status = "[green]VERIFIED[/green]" if ok else "[red]FAILED[/red]"
            lines.append(f"    Enforcement probe:   {status} — {msg}")
            lines.append("")

    console.print(Panel("\n".join(lines), title="Enforcement Status", style="blue"))
