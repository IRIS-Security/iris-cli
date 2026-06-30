"""Opinionated compliance action plan and score calculation."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from iris_core.models.passport import AgentPassport


@dataclass
class Action:
    priority: int
    command: str
    why: str
    time_estimate: str
    rule_id: str
    urgency: str  # "before deployment" | "this month"


@dataclass
class ActionPlan:
    immediate_actions: list[Action] = field(default_factory=list)
    next_30_days: list[Action] = field(default_factory=list)
    current_scores: dict[str, float] = field(default_factory=dict)
    estimated_time_to_compliant: str = "about 2 weeks"
    one_liner: str = ""


def progress_bar(score: float, width: int = 10) -> str:
    filled = int(round(score * width))
    filled = max(0, min(width, filled))
    return "█" * filled + "░" * (width - filled)


def _gov_dir(agent_name: str, base: Path | None = None) -> Path:
    root = base or Path.cwd() / "governance" / "agents"
    return root / agent_name


def colorado_controls_passed(passport: AgentPassport, agent_dir: Path) -> tuple[int, int]:
    """Return (satisfied, total) for Colorado AI Act controls."""
    checks = [
        bool(passport.is_high_risk_ai and passport.agent_id),
        bool(passport.evidence_vault_id),
        bool(passport.intent_ref),
        (agent_dir / "policy.cedar").exists(),
        bool(passport.last_reviewed_at),
        (agent_dir / "impact-assessment.md").exists(),
    ]
    return sum(1 for c in checks if c), 6


def nist_controls_passed(passport: AgentPassport, agent_dir: Path) -> tuple[int, int]:
    """NIST AI RMF — 0 until iris test is run; stub for advisor display."""
    test_file = agent_dir / "nist-ai-rmf-results.json"
    if test_file.exists():
        return 24, 24
    return 0, 24


def compliance_score(passport: AgentPassport, agent_dir: Path, framework: str) -> float:
    if framework == "colorado-ai-act":
        satisfied, total = colorado_controls_passed(passport, agent_dir)
        return satisfied / total if total else 0.0
    if framework == "nist-ai-rmf":
        satisfied, total = nist_controls_passed(passport, agent_dir)
        return satisfied / total if total else 0.0
    return 0.0


def detect_one_liner(answers: dict[str, Any]) -> str:
    q4 = answers.get("q4", "")
    if "health" in str(q4).lower() or "medical" in str(q4).lower():
        return (
            "from iris_anthropic import IrisAnthropic\n"
            "client = IrisAnthropic(passport=your_passport)"
        )
    return (
        "from iris_openai import IrisOpenAI\n"
        "client = IrisOpenAI(passport=your_passport)"
    )


def build_action_plan(
    agent_name: str | None,
    answers: dict[str, Any],
    recommendations: list[Any],
    passport: dict[str, Any] | None = None,
    governance_base: Path | None = None,
) -> ActionPlan:
    plan = ActionPlan()
    name = agent_name or "my-agent"
    spec = (passport or {}).get("spec", {})
    agent_dir = _gov_dir(name, governance_base)
    passport_exists = (agent_dir / "passport.yaml").exists()
    has_assessment = bool(spec.get("evidence_vault_id")) or (agent_dir / "impact-assessment.md").exists()
    has_policy = (agent_dir / "policy.cedar").exists()
    is_high_risk = spec.get("is_high_risk_ai", False)
    q2 = answers.get("q2", "")
    q4 = answers.get("q4", "")
    q6 = bool(answers.get("q6"))
    q7 = set(answers.get("q7", []))

    plan.one_liner = detect_one_liner(answers)
    priority = 1

    if not passport_exists:
        risk_flag = " --high-risk" if answers.get("q5") or is_high_risk else ""
        plan.immediate_actions.append(
            Action(
                priority=priority,
                command=f"iris register --name {name} --compliance colorado-ai-act{risk_flag}",
                why=(
                    "Your agent needs an identity contract before production. "
                    "The Colorado AI Act requires high-risk systems to be inventoried."
                ),
                time_estimate="2 minutes",
                rule_id="CO-001",
                urgency="before deployment",
            )
        )
        priority += 1

    if is_high_risk or answers.get("q5"):
        if not has_assessment:
            plan.immediate_actions.append(
                Action(
                    priority=priority,
                    command=f"iris compliance assess --agent {name}",
                    why=(
                        "This generates the CO-002 impact assessment document. "
                        "Without it, production deployment is blocked."
                    ),
                    time_estimate="5 minutes",
                    rule_id="CO-002",
                    urgency="before deployment",
                )
            )
            priority += 1

    plan.immediate_actions.append(
        Action(
            priority=priority,
            command=plan.one_liner.split("\n")[0] + "\n     " + plan.one_liner.split("\n")[1],
            why=(
                "Runtime enforcement. IRIS blocks unapproved tool calls "
                "and logs every decision to your local Evidence Vault."
            ),
            time_estimate="1 minute",
            rule_id="CO-004",
            urgency="before deployment",
        )
    )
    priority += 1

    if not has_policy:
        plan.immediate_actions.append(
            Action(
                priority=priority,
                command=f"iris policy compile --agent {name}",
                why=(
                    "Compiles your policy-intent.md to Cedar. "
                    "Required for transparency (CO-003) and runtime gates."
                ),
                time_estimate="3 minutes",
                rule_id="CO-003",
                urgency="before deployment",
            )
        )

    if q6 or "FedRAMP" in q7:
        plan.next_30_days.append(
            Action(
                priority=1,
                command="iris test --framework nist-ai-rmf",
                why=(
                    "Your federal deployment requires NIST AI RMF alignment. "
                    "You are currently at 0 of 24 controls."
                ),
                time_estimate="ongoing — ~3 controls/week",
                rule_id="NIST-001",
                urgency="this month",
            )
        )

    if "health" in str(q4).lower() or "HIPAA" in q7:
        plan.next_30_days.append(
            Action(
                priority=2,
                command="iris test --framework hipaa",
                why="Health data handling requires HIPAA safeguards and audit controls.",
                time_estimate="1-2 weeks",
                rule_id="HIPAA-001",
                urgency="this month",
            )
        )

    if "financial" in str(q2).lower() or "financial" in str(q4).lower():
        plan.next_30_days.append(
            Action(
                priority=3,
                command="# Review CFPB fair lending controls with your compliance team",
                why=(
                    "Financial agents must document fair lending practices "
                    "and non-discrimination review (CO-005)."
                ),
                time_estimate="this month",
                rule_id="CO-005",
                urgency="this month",
            )
        )

    if "Outside the US" in set(answers.get("q8", [])):
        plan.next_30_days.append(
            Action(
                priority=4,
                command="iris test --framework gdpr",
                why="EU users require GDPR data processing documentation and controls.",
                time_estimate="2-3 weeks",
                rule_id="GDPR-001",
                urgency="this month",
            )
        )

    if passport_exists:
        from iris import AgentPassport

        p = AgentPassport.from_yaml((agent_dir / "passport.yaml").read_text())
        plan.current_scores["colorado-ai-act"] = compliance_score(p, agent_dir, "colorado-ai-act")
    else:
        plan.current_scores["colorado-ai-act"] = 0.0

    plan.current_scores["nist-ai-rmf"] = 0.0
    if agent_dir.exists() and (agent_dir / "passport.yaml").exists():
        from iris import AgentPassport

        p = AgentPassport.from_yaml((agent_dir / "passport.yaml").read_text())
        plan.current_scores["nist-ai-rmf"] = compliance_score(p, agent_dir, "nist-ai-rmf")

    remaining = sum(1 for a in plan.immediate_actions if a.command.startswith("iris"))
    if remaining <= 1:
        plan.estimated_time_to_compliant = "under 1 day"
    elif remaining <= 3:
        plan.estimated_time_to_compliant = "about 1 week"
    else:
        plan.estimated_time_to_compliant = "about 2 weeks"

    return plan


def render_action_plan(plan: ActionPlan, agent_name: str | None, console) -> None:
    from rich.panel import Panel

    lines = [
        "Based on your answers, here is what to do, in order.",
        "",
        "[bold]THIS WEEK (before you deploy this agent):[/bold]",
        "",
    ]
    for action in plan.immediate_actions:
        lines.append(f"  [cyan]{action.priority}.[/cyan] Run: [bold]{action.command}[/bold]")
        lines.append(f"     Why: {action.why}")
        lines.append(f"     Time: {action.time_estimate}")
        lines.append("")

    if plan.next_30_days:
        lines.append("[bold]NEXT 30 DAYS:[/bold]")
        lines.append("")
        for action in plan.next_30_days:
            lines.append(f"  [cyan]{action.priority}.[/cyan] Run: [bold]{action.command}[/bold]")
            lines.append(f"     Why: {action.why}")
            lines.append(f"     Time: {action.time_estimate}")
            lines.append("")

    lines.append("[bold]CURRENT SCORE:[/bold]")
    agent_dir = _gov_dir(agent_name) if agent_name else Path.cwd() / "governance" / "agents" / "my-agent"
    passport_obj = None
    if agent_name and (agent_dir / "passport.yaml").exists():
        from iris import AgentPassport

        passport_obj = AgentPassport.from_yaml((agent_dir / "passport.yaml").read_text())

    for framework, score in plan.current_scores.items():
        pct = int(score * 100)
        bar = progress_bar(score)
        if passport_obj is not None:
            if framework == "colorado-ai-act":
                satisfied, total = colorado_controls_passed(passport_obj, agent_dir)
            else:
                satisfied, total = nist_controls_passed(passport_obj, agent_dir)
        else:
            satisfied, total = (0, 6 if framework == "colorado-ai-act" else 24)
        label = "Colorado AI Act" if framework == "colorado-ai-act" else "NIST AI RMF"
        lines.append(f"  {label}: {satisfied} of {total} controls  {bar}  {pct}%")
    lines.append("  [dim](Scores update automatically as you complete each step)[/dim]")
    lines.append("")
    lines.append(
        f"Estimated time to compliant: [bold]{plan.estimated_time_to_compliant}[/bold]"
    )
    lines.append("")
    lines.append("Run these commands now and your score changes in minutes.")

    console.print(Panel("\n".join(lines), title="Your Compliance Action Plan", style="green"))
