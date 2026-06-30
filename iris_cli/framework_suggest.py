"""iris framework suggest — interactive framework recommendation engine."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import click
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

MAJOR_CLOUDS = {"Google Cloud (GCP)", "AWS", "Microsoft Azure", "Multiple clouds"}
FREE_FRAMEWORKS = {
    "colorado-ai-act",
    "colorado-chatbot",
    "colorado-health-ai",
    "colorado-mental-health-ai",
}

COLORADO_AI_ACT_NOTE = (
    "Note: Colorado SB 26-189 replaced the original Colorado AI Act on May 14, 2026. "
    "Key changes: impact assessments are no longer legally required (retained as best "
    "practice). Record retention for 3 years is now required. Effective January 1, 2027."
)

MENTAL_HEALTH_KEYWORDS = (
    "therapy",
    "counseling",
    "mental health",
    "psychotherapy",
    "clinician",
)

CONVERSATIONAL_KEYWORDS = (
    "conversational ai",
    "chatbot",
    "chat bot",
)

EMPLOYMENT_KEYWORDS = (
    "hiring",
    "recruiting",
    "recruitment",
    "hr",
    "ats",
    "screening",
    "employment",
    "interview",
    "resume",
    "candidate",
)

VIDEO_KEYWORDS = (
    "video",
    "interview",
    "biometric",
)

HIGH_RISK_CUSTOMER_KEYWORDS = (
    "customer service",
    "customer support",
    "candidate",
    "scoring",
    "interviewer",
    "hiring",
    "recruiting",
    "loan",
    "underwriting",
)

Q1_CHOICES = [
    "Makes decisions that affect individual people (hiring, loans, medical, etc.)",
    "Automates business processes (summarization, classification, routing)",
    "Generates content (writing, code, images, reports)",
    "Answers questions or provides information",
    "Controls systems or takes actions (RPA, tool use, autonomous tasks)",
    "Multiple of the above",
]

Q2_CHOICES = [
    "US federal government employees or contractors",
    "US state or local government",
    "Healthcare patients or providers",
    "Financial services customers (banking, insurance, lending)",
    "General consumers (B2C)",
    "Businesses (B2B, not regulated industries)",
    "Internal employees only",
]

Q3_CHOICES = [
    "Google Cloud (GCP)",
    "AWS",
    "Microsoft Azure",
    "On-premises / private cloud",
    "Multiple clouds",
    "Not decided yet",
]

Q4_CHOICES = [
    "Yes — health or medical data (PHI)",
    "Yes — financial data (account numbers, transactions)",
    "Yes — general personal data (name, email, address)",
    "Yes — biometric or sensitive data",
    "No — only processes internal/business data",
]

Q7_CHOICES = [
    "HIPAA (healthcare)",
    "SOC 2 (SaaS / enterprise)",
    "PCI DSS (payment cards)",
    "FedRAMP (federal government contracts)",
    "None of the above",
    "Not sure",
]

Q8_CHOICES = [
    "Colorado",
    "California",
    "Texas",
    "New York",
    "Other / multiple states",
    "Outside the US",
]


@dataclass
class Recommendation:
    framework: str
    tier: str
    status: str
    reason: str
    command: str | None


def _load_passport(agent: str) -> dict[str, Any] | None:
    passport_path = Path.cwd() / "governance" / "agents" / agent / "passport.yaml"
    if not passport_path.exists():
        return None
    return yaml.safe_load(passport_path.read_text()) or {}


def _prefill_answers(passport: dict[str, Any] | None) -> dict[str, Any]:
    if not passport:
        return {}

    spec = passport.get("spec", {})
    compliance_tags = set(spec.get("compliance_tags") or [])
    prefill: dict[str, Any] = {}

    if spec.get("is_high_risk_ai") is True:
        prefill["q5"] = True
        prefill["q1"] = Q1_CHOICES[0]

    data_classification = str(spec.get("data_classification", "")).lower()
    if "phi" in data_classification or "health" in data_classification:
        prefill["q4"] = Q4_CHOICES[0]
    elif "financial" in data_classification:
        prefill["q4"] = Q4_CHOICES[1]
    elif "pii" in data_classification:
        prefill["q4"] = Q4_CHOICES[2]

    if "hipaa" in compliance_tags:
        prefill.setdefault("q7", []).append("HIPAA (healthcare)")
    if "soc2" in compliance_tags:
        prefill.setdefault("q7", []).append("SOC 2 (SaaS / enterprise)")
    if "fedramp" in compliance_tags or "fedramp-moderate" in compliance_tags:
        prefill.setdefault("q7", []).append("FedRAMP (federal government contracts)")
        prefill["q6"] = True
        prefill["q2"] = Q2_CHOICES[0]

    description = str(spec.get("description", "")).strip()
    if description:
        prefill["agent_description"] = description

    return prefill


def _ask_choice(question: str, choices: list[str], default: str | None = None) -> str:
    console.print(f"[bold]{question}[/bold]")
    for i, choice in enumerate(choices, 1):
        console.print(f"  [dim]{i}.[/dim] {choice}")
    if default:
        console.print(f"[dim]Prefilled from passport: {default}[/dim]")
        return default
    while True:
        raw = click.prompt("Enter number")
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(choices):
                return choices[idx]
        except ValueError:
            pass
        console.print("[red]Please enter a valid number.[/red]")


def _ask_multi(question: str, choices: list[str], default: list[str] | None = None) -> list[str]:
    console.print(f"[bold]{question}[/bold]")
    console.print("[dim]Enter numbers separated by commas (e.g. 1,3)[/dim]")
    for i, choice in enumerate(choices, 1):
        console.print(f"  [dim]{i}.[/dim] {choice}")
    if default:
        console.print(f"[dim]Prefilled from passport: {', '.join(default)}[/dim]")
        return default
    raw = click.prompt("Enter numbers")
    selected: list[str] = []
    for part in raw.split(","):
        try:
            idx = int(part.strip()) - 1
            if 0 <= idx < len(choices):
                selected.append(choices[idx])
        except ValueError:
            pass
    return selected


def _ask_confirm(question: str, default: bool | None = None) -> bool:
    if default is not None:
        console.print(f"[bold]{question}[/bold]")
        console.print(f"[dim]Prefilled from passport: {'yes' if default else 'no'}[/dim]")
        return default
    return click.confirm(question, default=False)


def run_questionnaire(prefill: dict[str, Any]) -> dict[str, Any]:
    console.print(
        Panel(
            "[bold]Framework Suggestions[/bold]\n"
            "Describe your agent in plain English and IRIS will recommend"
            " the right compliance frameworks.",
            style="blue",
        )
    )

    answers: dict[str, Any] = {}
    answers["q1"] = _ask_choice("Q1: What does your agent do?", Q1_CHOICES, prefill.get("q1"))
    answers["q2"] = _ask_choice("Q2: Who are your end users?", Q2_CHOICES, prefill.get("q2"))
    answers["q3"] = _ask_choice("Q3: Where will this agent be deployed?", Q3_CHOICES, prefill.get("q3"))
    answers["q4"] = _ask_choice("Q4: Does this agent process personal data?", Q4_CHOICES, prefill.get("q4"))
    answers["q5"] = _ask_confirm(
        "Q5: Is this agent making or substantially assisting in decisions that significantly affect people?",
        prefill.get("q5"),
    )
    answers["q6"] = _ask_confirm(
        "Q6: Will this agent be used by or on behalf of a US federal government agency?",
        prefill.get("q6"),
    )
    answers["q7"] = _ask_multi("Q7: Is your organization subject to any of these?", Q7_CHOICES, prefill.get("q7"))
    answers["q8"] = _ask_multi("Q8: What US states are your users primarily in?", Q8_CHOICES, prefill.get("q8"))
    return answers


def build_recommendations(answers: dict[str, Any]) -> list[Recommendation]:
    q1 = answers.get("q1", "")
    q2 = answers.get("q2", "")
    q3 = answers.get("q3", "")
    q4 = answers.get("q4", "")
    q5 = bool(answers.get("q5"))
    q6 = bool(answers.get("q6"))
    q7 = set(answers.get("q7", []))
    q8 = set(answers.get("q8", []))
    agent_description = str(answers.get("agent_description", "")).lower()

    colorado = (
        (q5 and "Colorado" in q8)
        or (q1 == Q1_CHOICES[0] and "Colorado" in q8)
    )
    conversational = (
        any(kw in q1.lower() for kw in CONVERSATIONAL_KEYWORDS)
        or any(kw in agent_description for kw in CONVERSATIONAL_KEYWORDS)
        or q1 == Q1_CHOICES[3]
    )
    consumer_facing = q2 in {Q2_CHOICES[4], Q2_CHOICES[2]} or "minor" in agent_description
    chatbot = conversational and consumer_facing and "Colorado" in q8

    health_data = q4 == Q4_CHOICES[0] or "health" in str(q4).lower() or "medical" in str(q4).lower()
    health_insurance = (
        "HIPAA (healthcare)" in q7
        or q2 == Q2_CHOICES[3]
        or "health insurance" in agent_description
    )
    health_ai = (health_data or health_insurance) and "Colorado" in q8

    mental_health = any(kw in agent_description for kw in MENTAL_HEALTH_KEYWORDS)

    nist = q6 or "FedRAMP (federal government contracts)" in q7 or q2 == Q2_CHOICES[0]
    fedramp = (
        (q6 or "FedRAMP (federal government contracts)" in q7 or q2 in {Q2_CHOICES[0], Q2_CHOICES[1]})
        and (q3 in MAJOR_CLOUDS)
    )
    hipaa = q4 == Q4_CHOICES[0] or "HIPAA (healthcare)" in q7
    soc2 = q2 == Q2_CHOICES[5] or "SOC 2 (SaaS / enterprise)" in q7
    gdpr = "Outside the US" in q8 or "Other / multiple states" in q8

    ccpa_admt = (
        "California" in q8
        and q5
        and (
            q1 == Q1_CHOICES[0]
            or q2 in {Q2_CHOICES[2], Q2_CHOICES[3]}
        )
    )
    china_pipl = (
        "Outside the US" in q8
        or "china" in agent_description
        or "asia" in agent_description
        or (q2 == Q2_CHOICES[4] and "Outside the US" in q8)
    )

    employment_domain = (
        q1 == Q1_CHOICES[0]
        or any(kw in q1.lower() for kw in EMPLOYMENT_KEYWORDS)
        or any(kw in agent_description for kw in EMPLOYMENT_KEYWORDS)
        or q2 in {Q2_CHOICES[4], Q2_CHOICES[6]}
    )
    illinois_video = (
        employment_domain
        and (
            "Illinois" in q8
            or "Other / multiple states" in q8
        )
        and (
            any(kw in agent_description for kw in VIDEO_KEYWORDS)
            or q4 == Q4_CHOICES[3]
            or "video" in q1.lower()
            or "interview" in q1.lower()
        )
    )
    nyc_ll144 = (
        employment_domain
        and (
            "New York" in q8
            or "Other / multiple states" in q8
        )
    )
    aiuc1 = (
        q5
        or q1 == Q1_CHOICES[0]
        or any(kw in agent_description for kw in HIGH_RISK_CUSTOMER_KEYWORDS)
        or any(kw in q1.lower() for kw in HIGH_RISK_CUSTOMER_KEYWORDS)
    )

    colorado_reason = (
        "Your agent makes consequential decisions for Colorado users. "
        "SB 26-189 applies (replaces SB 24-205, effective Jan. 1, 2027). "
        f"{COLORADO_AI_ACT_NOTE}"
        if colorado
        else "No Colorado consequential decision scope detected."
    )

    recommendations = [
        Recommendation(
            framework="colorado-ai-act",
            tier="FREE",
            status="REQUIRED" if colorado else "NOT APPLICABLE",
            reason=colorado_reason,
            command="iris compliance check --framework colorado-ai-act" if colorado else None,
        ),
        Recommendation(
            framework="colorado-chatbot",
            tier="FREE",
            status="REQUIRED" if chatbot else "NOT APPLICABLE",
            reason=(
                "Conversational AI serving Colorado consumers requires HB 26-1263 "
                "chatbot safety controls (effective Jan. 1, 2027)."
                if chatbot
                else "No conversational AI + consumer audience trigger detected."
            ),
            command="iris compliance check --framework colorado-chatbot" if chatbot else None,
        ),
        Recommendation(
            framework="colorado-health-ai",
            tier="FREE",
            status="REQUIRED" if health_ai else "NOT APPLICABLE",
            reason=(
                "Health or insurance data handling in Colorado requires HB 26-1139 "
                "AI in health insurance controls (effective Jan. 1, 2027)."
                if health_ai
                else "No Colorado health insurance AI trigger detected."
            ),
            command="iris compliance check --framework colorado-health-ai" if health_ai else None,
        ),
        Recommendation(
            framework="colorado-mental-health-ai",
            tier="FREE",
            status="REQUIRED" if mental_health else "NOT APPLICABLE",
            reason=(
                "Mental health services agent detected. HB 26-1195 applies "
                "(effective Aug. 12, 2026 — two months from now)."
                if mental_health
                else "No mental health services scope detected."
            ),
            command=(
                "iris compliance check --framework colorado-mental-health-ai"
                if mental_health
                else None
            ),
        ),
        Recommendation(
            framework="nist-ai-rmf",
            tier="PRO",
            status="REQUIRED" if nist else "RECOMMENDED",
            reason=(
                "Required for federal AI deployments, recommended best practice for all high-risk AI systems."
                if nist
                else "Recommended best practice for high-risk AI systems."
            ),
            command="iris test --framework nist-ai-rmf",
        ),
        Recommendation(
            framework="fedramp",
            tier="PRO",
            status="REQUIRED" if fedramp else "NOT APPLICABLE",
            reason=(
                "Federal government use on a major cloud provider requires FedRAMP authorization."
                if fedramp
                else "No federal + major cloud deployment trigger detected."
            ),
            command="iris test --framework fedramp-moderate" if fedramp else None,
        ),
        Recommendation(
            framework="hipaa",
            tier="PRO",
            status="REQUIRED" if hipaa else "NOT APPLICABLE",
            reason=(
                "Health data handling requires HIPAA safeguards and audit controls."
                if hipaa
                else "No health data handling indicated."
            ),
            command="iris test --framework hipaa" if hipaa else None,
        ),
        Recommendation(
            framework="soc2",
            tier="PRO",
            status="RECOMMENDED" if soc2 else "NOT APPLICABLE",
            reason=(
                "B2B enterprise customers will typically ask for SOC 2 Type II evidence."
                if soc2
                else "No B2B enterprise assurance trigger detected."
            ),
            command="iris test --framework soc2" if soc2 else None,
        ),
        Recommendation(
            framework="gdpr",
            tier="PRO",
            status="REQUIRED" if gdpr else "NOT APPLICABLE",
            reason=(
                "Required for EU users and cross-border personal data processing."
                if gdpr
                else "No EU or non-US user footprint detected."
            ),
            command="iris test --framework gdpr" if gdpr else None,
        ),
        Recommendation(
            framework="ccpa-admt",
            tier="PRO",
            status="REQUIRED" if ccpa_admt else "NOT APPLICABLE",
            reason=(
                "California ADMT regulations (effective Jan. 1, 2026) apply to "
                "automated decisions affecting California consumers in employment, "
                "credit, healthcare, housing, or education."
                if ccpa_admt
                else "No California ADMT scope detected."
            ),
            command="iris compliance check --framework ccpa-admt" if ccpa_admt else None,
        ),
        Recommendation(
            framework="china-pipl",
            tier="PRO",
            status="REQUIRED" if china_pipl else "NOT APPLICABLE",
            reason=(
                "China PIPL applies when processing personal information of "
                "individuals located in China, including automated decision-making "
                "and cross-border transfer restrictions."
                if china_pipl
                else "No China or Asia-Pacific user footprint detected."
            ),
            command="iris compliance check --framework china-pipl" if china_pipl else None,
        ),
        Recommendation(
            framework="illinois-ai-video",
            tier="PRO",
            status="REQUIRED" if illinois_video else "NOT APPLICABLE",
            reason=(
                "Illinois AI Video Interview Act applies to AI analysis of video "
                "interviews for Illinois-based positions. Consent must be logged "
                "before any video analysis (820 ILCS 42)."
                if illinois_video
                else "No Illinois video interview AI scope detected."
            ),
            command=(
                "iris compliance check --framework illinois-ai-video"
                if illinois_video
                else None
            ),
        ),
        Recommendation(
            framework="nyc-ll144",
            tier="PRO",
            status="REQUIRED" if nyc_ll144 else "NOT APPLICABLE",
            reason=(
                "NYC Local Law 144 requires annual independent bias audits, public "
                "disclosure, and candidate notice before using Automated Employment "
                "Decision Tools (AEDTs) for NYC hiring."
                if nyc_ll144
                else "No NYC AEDT hiring scope detected."
            ),
            command="iris compliance check --framework nyc-ll144" if nyc_ll144 else None,
        ),
        Recommendation(
            framework="aiuc-1",
            tier="PRO",
            status="RECOMMENDED" if aiuc1 else "NOT APPLICABLE",
            reason=(
                "AIUC-1 is a voluntary enterprise-trust certification for "
                "customer-facing and high-risk AI agents (customer service, "
                "candidate scoring, interviewer agents). IRIS exports technical "
                "evidence in AIUC-1's B006-format for accredited auditors."
                if aiuc1
                else "No high-risk customer-facing agent scope detected."
            ),
            command=(
                f"iris certify --framework aiuc-1 --agent {answers.get('agent_name', '<agent>')}"
                if aiuc1
                else None
            ),
        ),
    ]
    return recommendations


def _render_table(recommendations: list[Recommendation]) -> None:
    console.print(
        Panel(
            "Based on your answers - generated by IRIS",
            title="Framework Recommendations",
            style="blue",
        )
    )
    ordered = sorted(
        recommendations,
        key=lambda rec: (
            rec.tier != "FREE",
            0 if rec.status == "REQUIRED" else 1 if rec.status == "RECOMMENDED" else 2,
            rec.framework,
        ),
    )

    for status in ("REQUIRED", "RECOMMENDED", "NOT APPLICABLE"):
        section = [rec for rec in ordered if rec.status == status]
        if not section:
            continue
        console.print(f"\n[bold]{status}[/bold]")
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column(" ")
        table.add_column("Framework")
        table.add_column("Tier")
        table.add_column("Reason", overflow="fold")
        for rec in section:
            icon = "✓" if status != "NOT APPLICABLE" else "—"
            table.add_row(icon, rec.framework, rec.tier, rec.reason)
            if rec.command and status != "NOT APPLICABLE":
                table.add_row("", f"[dim]{rec.command}[/dim]", "", "")
        console.print(table)

    free_count = len([r for r in recommendations if r.tier == "FREE" and r.status != "NOT APPLICABLE"])
    pro_count = len([r for r in recommendations if r.tier == "PRO" and r.status != "NOT APPLICABLE"])
    console.print(
        "\n[bold]"
        f"{free_count} free framework{'s' if free_count != 1 else ''} available now.\n"
        f"{pro_count} frameworks require IRIS Pro."
        "[/bold]\n"
        "Get IRIS Pro: [cyan]iris license activate <your-key>[/cyan]\n"
        "Learn more: [cyan]https://iris.ai/pricing[/cyan]"
    )


def _save_recommendations(agent: str | None, answers: dict[str, Any], recommendations: list[Recommendation]) -> Path:
    out_dir = Path.home() / ".iris"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "framework-recommendations.json"
    payload = {
        "generated_at": datetime.utcnow().isoformat(),
        "agent": agent,
        "answers": answers,
        "recommendations": [rec.__dict__ for rec in recommendations],
    }
    out_path.write_text(json.dumps(payload, indent=2))
    return out_path


def _maybe_offer_free_check(recommendations: list[Recommendation]) -> None:
    free_available = [r for r in recommendations if r.framework == "colorado-ai-act" and r.status != "NOT APPLICABLE"]
    console.print("\nRun Colorado AI Act check now? (yes/no)")

    if not free_available:
        console.print("[dim]No free framework triggered from your current answers.[/dim]")
        return

    if click.get_text_stream("stdin").isatty():
        should_run = click.confirm("", default=False)
    else:
        should_run = False
        console.print("[dim]Non-interactive session detected; skipping automatic run.[/dim]")

    if should_run:
        console.print("[bold green]Running:[/bold green] iris compliance check --framework colorado-ai-act")
        ctx = click.get_current_context()
        root = ctx.find_root()
        compliance_group = root.command.commands.get("compliance")
        if compliance_group and "check" in compliance_group.commands:
            try:
                root.invoke(
                    compliance_group.commands["check"],
                    agent=None,
                    framework="colorado-ai-act",
                    governance_dir=None,
                )
            except SystemExit:
                # Keep suggest flow intact even if compliance check exits non-zero.
                pass
        console.print("[dim]Pro frameworks are locked until you activate IRIS Pro.[/dim]")
    else:
        console.print("[dim]You can run it any time:[/dim] iris compliance check --framework colorado-ai-act")


@click.command("framework-suggest")
@click.option("--agent", default=None, help="Agent name to prefill answers from governance/agents/<agent>/passport.yaml")
@click.option("--format", "output_format", default="table", type=click.Choice(["table", "json"]))
def framework_suggest(agent: str | None, output_format: str) -> None:
    """Suggest compliance frameworks with an interactive questionnaire."""
    passport = _load_passport(agent) if agent else None
    if agent and not passport:
        console.print(f"[yellow]No passport found for agent '{agent}'. Asking all questions fresh.[/yellow]")

    prefill = _prefill_answers(passport)
    answers = run_questionnaire(prefill)
    if prefill.get("agent_description"):
        answers["agent_description"] = prefill["agent_description"]
    recommendations = build_recommendations(answers)
    save_path = _save_recommendations(agent, answers, recommendations)

    if output_format == "json":
        click.echo(
            json.dumps(
                {
                    "agent": agent,
                    "answers": answers,
                    "recommendations": [rec.__dict__ for rec in recommendations],
                    "saved_to": str(save_path),
                },
                indent=2,
            )
        )
    else:
        _render_table(recommendations)
        console.print(f"\n[dim]Saved recommendations: {save_path}[/dim]")

        from iris_cli.action_plan import build_action_plan, render_action_plan

        plan = build_action_plan(agent, answers, recommendations, passport)
        render_action_plan(plan, agent, console)

    _maybe_offer_free_check(recommendations)
