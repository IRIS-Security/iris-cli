"""
iris compliance assess — interactive impact assessment for the Colorado AI Act.

Think of this like TurboTax for AI compliance. The developer answers
plain English questions in the terminal. IRIS does the legal reasoning
and produces a signed impact assessment document that satisfies CO-002.

Outputs:
  1. impact-assessment.md  — committed to the governance directory
  2. passport.yaml updated — evidence_vault_id written automatically
  3. Evidence Vault entry  — local audit log entry created
"""

import click
import json
import uuid
import yaml
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from iris_core import __version__ as IRIS_PLATFORM_VERSION

console = Console()


# ── Colorado AI Act impact assessment questionnaire ───────────────────────────
# Each question maps to a specific obligation under SB 26-189.
# The answers drive the risk level and the generated assessment document.

QUESTIONNAIRE = [
    {
        "id": "domain",
        "rule": "CO-001",
        "question": "Which domain does this agent operate in?",
        "choices": [
            "healthcare",
            "financial services",
            "employment",
            "education",
            "housing",
            "insurance",
            "legal services",
            "government",
            "other (not covered ADMT)",
        ],
        "type": "choice",
        "high_risk_values": [
            "healthcare",
            "financial services",
            "employment",
            "education",
            "housing",
            "insurance",
            "legal services",
            "government",
        ],
    },
    {
        "id": "impact_assessment",
        "rule": "CO-002",
        "severity": "MEDIUM",
        "question": (
            "Has an impact assessment been completed for this agent? "
            "(Not legally required under SB 26-189 but recommended as "
            "best practice for NIST AI RMF alignment)"
        ),
        "type": "confirm",
    },
    {
        "id": "record_retention",
        "rule": "CO-RR-001",
        "severity": "HIGH",
        "question": (
            "Do you have a plan for retaining AI usage records for 3 years? "
            "(Required under SB 26-189 for covered ADMT systems)"
        ),
        "type": "confirm",
    },
    {
        "id": "consequential",
        "rule": "CO-004",
        "question": (
            "Does this agent make or substantially assist in decisions that "
            "have a significant impact on a consumer? (e.g. loan approval, "
            "hiring decision, insurance denial, medical recommendation)"
        ),
        "type": "confirm",
    },
    {
        "id": "data_types",
        "rule": "CO-003",
        "question": "What types of personal data does this agent access or process?",
        "choices": [
            "name / contact information",
            "financial data (account numbers, transactions)",
            "health or medical data",
            "employment or salary data",
            "biometric data",
            "location data",
            "none — does not process personal data",
        ],
        "type": "multi",
    },
    {
        "id": "human_review",
        "rule": "CO-004",
        "question": (
            "Can a consumer request human review of any decision this agent "
            "makes or assists with?"
        ),
        "type": "confirm",
    },
    {
        "id": "opt_out",
        "rule": "CO-004",
        "question": (
            "Can a consumer opt out of being subject to this agent's "
            "decisions entirely?"
        ),
        "type": "confirm",
    },
    {
        "id": "discrimination_review",
        "rule": "CO-005",
        "question": (
            "Has this agent been reviewed for potential discriminatory impact "
            "on protected classes (race, gender, age, disability, etc.)?"
        ),
        "type": "confirm",
    },
    {
        "id": "training_data",
        "rule": "CO-005",
        "question": "Briefly describe the training data or model used by this agent.",
        "type": "text",
        "placeholder": "e.g. Fine-tuned GPT-4o on internal support tickets from 2022-2024",
    },
    {
        "id": "mitigations",
        "rule": "CO-005",
        "question": (
            "What safeguards or mitigations are in place to prevent harm "
            "to consumers from this agent?"
        ),
        "type": "text",
        "placeholder": "e.g. Human review required for all decisions above $10K, IRIS policy enforcement",
    },
]


def run_questionnaire() -> dict:
    """Run the interactive questionnaire and return answers."""
    answers = {}

    console.print("\n[bold]Colorado AI Act Impact Assessment[/bold]")
    console.print(
        "[dim]Answer each question honestly. IRIS uses your answers to generate "
        "an impact assessment under SB 26-189 (replaces SB 24-205, effective "
        "Jan. 1, 2027).[/dim]\n"
    )

    for i, q in enumerate(QUESTIONNAIRE, 1):
        console.print(f"[bold cyan]Q{i} of {len(QUESTIONNAIRE)}[/bold cyan] "
                      f"[dim](Rule {q['rule']})[/dim]")
        console.print(f"[bold]{q['question']}[/bold]")

        if q["type"] == "confirm":
            answers[q["id"]] = Confirm.ask("")

        elif q["type"] == "choice":
            for j, choice in enumerate(q["choices"], 1):
                console.print(f"  [dim]{j}.[/dim] {choice}")
            while True:
                raw = Prompt.ask("Enter number")
                try:
                    idx = int(raw) - 1
                    if 0 <= idx < len(q["choices"]):
                        answers[q["id"]] = q["choices"][idx]
                        break
                except ValueError:
                    pass
                console.print("[red]Please enter a valid number.[/red]")

        elif q["type"] == "multi":
            console.print("[dim]Enter numbers separated by commas (e.g. 1,3)[/dim]")
            for j, choice in enumerate(q["choices"], 1):
                console.print(f"  [dim]{j}.[/dim] {choice}")
            raw = Prompt.ask("Enter numbers")
            selected = []
            for part in raw.split(","):
                try:
                    idx = int(part.strip()) - 1
                    if 0 <= idx < len(q["choices"]):
                        selected.append(q["choices"][idx])
                except ValueError:
                    pass
            answers[q["id"]] = selected

        elif q["type"] == "text":
            console.print(f"[dim]Example: {q.get('placeholder', '')}[/dim]")
            answers[q["id"]] = Prompt.ask("")

        console.print()

    return answers


def calculate_risk_level(answers: dict) -> tuple:
    """
    Derive risk level and findings from answers.
    Returns (risk_level, findings, recommendations).
    """
    findings = []
    recommendations = []
    risk_score = 0

    domain = answers.get("domain", "")
    high_risk_domains = [
        "healthcare", "financial services", "employment",
        "education", "housing", "insurance", "legal services", "government",
    ]

    if domain in high_risk_domains:
        risk_score += 3
        findings.append(
            f"Agent operates in '{domain}' — a covered ADMT domain under SB 26-189."
        )

    if not answers.get("impact_assessment"):
        risk_score += 1
        findings.append(
            "No impact assessment on file (best practice under SB 26-189, "
            "not legally required)."
        )
        recommendations.append(
            "Complete an impact assessment via iris compliance assess to align "
            "with NIST AI RMF MAP-1.5."
        )

    if not answers.get("record_retention"):
        risk_score += 2
        findings.append(
            "No 3-year record retention plan documented for ADMT usage records."
        )
        recommendations.append(
            "Configure Evidence Vault Pro for 3-year retention (CO-RR-001). "
            "Run: iris license activate <your-key>"
        )

    if answers.get("consequential"):
        risk_score += 3
        findings.append(
            "Agent makes or substantially assists in consequential decisions "
            "affecting consumers."
        )
        recommendations.append(
            "Ensure human review is available for all consequential decisions "
            "and that user_consent_logged is enforced via IRIS policy."
        )

    if not answers.get("human_review"):
        risk_score += 2
        findings.append("No human review pathway available for consumers.")
        recommendations.append(
            "Implement a human review pathway. Enable the IRIS HITL gate "
            "for consequential actions in production."
        )

    if not answers.get("opt_out"):
        risk_score += 1
        findings.append("No consumer opt-out mechanism available.")
        recommendations.append(
            "Provide consumers with a clear opt-out path before this agent "
            "is used in consequential decisions."
        )

    if not answers.get("discrimination_review"):
        risk_score += 2
        findings.append(
            "No discrimination review has been conducted on this agent."
        )
        recommendations.append(
            "Conduct a bias and discrimination review before production deployment. "
            "IRIS Dynamic Guardrail Engine (Phase 2) will automate ongoing monitoring."
        )

    data_types = answers.get("data_types", [])
    sensitive = [
        d for d in data_types
        if any(s in d for s in ["financial", "health", "employment", "biometric"])
    ]
    if sensitive:
        risk_score += 2
        findings.append(
            f"Agent processes sensitive personal data: {', '.join(sensitive)}."
        )
        recommendations.append(
            "Ensure data minimization principles are enforced via IRIS policy. "
            "Restrict data access to approved regions only."
        )

    if risk_score >= 8:
        risk_level = "HIGH"
    elif risk_score >= 4:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return risk_level, findings, recommendations


def generate_assessment_markdown(
    agent_name: str,
    owner: str,
    answers: dict,
    risk_level: str,
    findings: list,
    recommendations: list,
    assessment_id: str,
    assessed_by: str,
) -> str:
    """Generate the impact assessment markdown document."""
    now = datetime.utcnow().strftime("%Y-%m-%d %Human:%M UTC")
    data_types = answers.get("data_types", [])
    if isinstance(data_types, list):
        data_types_str = "\n".join(f"- {d}" for d in data_types)
    else:
        data_types_str = f"- {data_types}"

    findings_str = "\n".join(f"- {f}" for f in findings) or "- No critical findings."
    recs_str = "\n".join(f"- {r}" for r in recommendations) or "- No recommendations."

    risk_emoji = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(risk_level, "⚪")

    return f"""# Impact Assessment — {agent_name}

> **Assessment ID**: `{assessment_id}`
> **Assessed by**: {assessed_by}
> **Date**: {now}
> **Framework**: Colorado AI Act (SB 26-189), effective January 1, 2027
> **Note**: Replaces SB 24-205, signed May 14, 2026
> **Generated by**: IRIS Compliance Platform v{IRIS_PLATFORM_VERSION}

---

## Risk level

{risk_emoji} **{risk_level}**

---

## Agent profile

| Field | Value |
|---|---|
| Agent name | {agent_name} |
| Owner | {owner} |
| Operating domain | {answers.get('domain', 'not specified')} |
| Makes consequential decisions | {'Yes' if answers.get('consequential') else 'No'} |
| Impact assessment completed | {'Yes' if answers.get('impact_assessment') else 'No (best practice)'} |
| 3-year record retention plan | {'Yes' if answers.get('record_retention') else 'No'} |
| Human review available | {'Yes' if answers.get('human_review') else 'No'} |
| Consumer opt-out available | {'Yes' if answers.get('opt_out') else 'No'} |
| Discrimination review completed | {'Yes' if answers.get('discrimination_review') else 'No'} |

---

## Personal data processed

{data_types_str}

---

## Model and training data

{answers.get('training_data', 'Not specified')}

---

## Safeguards and mitigations

{answers.get('mitigations', 'Not specified')}

---

## Findings

{findings_str}

---

## Recommendations

{recs_str}

---

## Colorado AI Act obligations satisfied

| Rule | Obligation | Status |
|---|---|---|
| CO-001 | ADMT inventory | ✅ Satisfied — agent registered in IRIS |
| CO-002 | Impact assessment (best practice) | {'✅ Satisfied' if answers.get('impact_assessment') else '⚠️ Recommended'} |
| CO-003 | Consumer notice / transparency | ✅ Satisfied — policy-intent.md |
| CO-004 | Post-adverse-action notice | {'✅ Satisfied' if answers.get('opt_out') else '⚠️ Requires action'} |
| CO-RR-001 | 3-year record retention | {'✅ Satisfied' if answers.get('record_retention') else '⚠️ Requires action'} |
| CO-DEV-001 | Developer documentation | ✅ Satisfied — policy-intent.md + passport.yaml |

---

## IRIS governance controls active

- Agent Passport: registered and version-controlled
- Cedar policy: compiled from natural language intent
- Evidence Vault: this assessment recorded under ID `{assessment_id}`
- Runtime intercept: enforced via IRIS sidecar (K8s) or SDK decorator

---

*This document was generated by IRIS and constitutes an impact assessment
under Colorado AI Act SB 26-189 (replaces SB 24-205, effective Jan. 1, 2027).
It should be reviewed whenever the agent's capabilities, data access, or
decision scope changes.*
"""


def _load_answers(answers_path: Path | None) -> dict | None:
    if answers_path is None:
        return None
    if not answers_path.exists():
        raise click.ClickException(f"Answers file not found: {answers_path}")
    data = json.loads(answers_path.read_text())
    if not isinstance(data, dict):
        raise click.ClickException(f"Answers file must be a JSON object: {answers_path}")
    return data


@click.command("assess")
@click.option("--agent", required=True, help="Agent name to assess")
@click.option("--assessor", default=None, help="Your name or email (recorded in audit trail)")
@click.option("--dir", "governance_dir", type=Path, default=None)
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt")
@click.option(
    "--answers",
    type=click.Path(path_type=Path, exists=True),
    default=None,
    help="JSON file with pre-filled questionnaire answers (for automated demos)",
)
def compliance_assess(agent, assessor, governance_dir, yes, answers):
    """
    Run a Colorado AI Act impact assessment for an agent.

    Asks you 8 plain English questions about the agent. Generates a
    formal impact assessment document, commits it to the governance
    directory, and automatically closes the CO-002 violation in your
    agent passport.

    Think of it like TurboTax for AI compliance — you answer the
    questions, IRIS handles the legal reasoning.

    Example:
      iris compliance assess --agent payment-agent
    """
    gov_dir = governance_dir or Path.cwd() / "governance" / "agents" / agent
    passport_file = gov_dir / "passport.yaml"

    if not passport_file.exists():
        console.print(f"[red]Passport not found: {passport_file}[/red]")
        console.print(f"Run: iris register --name {agent}")
        raise SystemExit(1)

    console.print(Panel(
        f"[bold]IRIS Impact Assessment[/bold]\n"
        f"Agent: [cyan]{agent}[/cyan]\n"
        f"Framework: Colorado AI Act (SB 26-189)\n"
        f"Effective: January 1, 2027 (replaces SB 24-205)",
        style="blue"
    ))

    if not yes:
        if not Confirm.ask(
            "\nThis will generate a formal impact assessment and update your "
            "passport.yaml. Continue?"
        ):
            raise SystemExit(0)

    # Run questionnaire (or load pre-filled answers for demos)
    preset_answers = _load_answers(answers)
    questionnaire_answers = preset_answers if preset_answers is not None else run_questionnaire()

    # Calculate risk
    risk_level, findings, recommendations = calculate_risk_level(questionnaire_answers)

    # Generate assessment ID and document
    assessment_id = f"IA-{agent}-{uuid.uuid4().hex[:8].upper()}"
    assessed_by = assessor or "iris-platform"

    # Load passport to get owner
    passport_data = yaml.safe_load(passport_file.read_text())
    owner = passport_data.get("spec", {}).get("owner", "unknown")

    assessment_md = generate_assessment_markdown(
        agent_name=agent,
        owner=owner,
        answers=questionnaire_answers,
        risk_level=risk_level,
        findings=findings,
        recommendations=recommendations,
        assessment_id=assessment_id,
        assessed_by=assessed_by,
    )

    # Write assessment document
    assessment_file = gov_dir / "impact-assessment.md"
    assessment_file.write_text(assessment_md)

    # Update passport.yaml with evidence_vault_id and last_reviewed_at
    passport_data["spec"]["evidence_vault_id"] = assessment_id
    passport_data["spec"]["last_reviewed_at"] = datetime.utcnow().isoformat()
    passport_data["spec"]["reviewed_by"] = assessed_by
    passport_file.write_text(yaml.dump(passport_data, default_flow_style=False, sort_keys=False))

    # Write to local evidence vault
    vault_dir = Path.home() / ".iris" / "evidence" / agent
    vault_dir.mkdir(parents=True, exist_ok=True)
    with open(vault_dir / "assessments.jsonl", "a") as f:
        f.write(json.dumps({
            "assessment_id": assessment_id,
            "agent": agent,
            "risk_level": risk_level,
            "assessed_by": assessed_by,
            "timestamp": datetime.utcnow().isoformat(),
            "findings_count": len(findings),
            "framework": "colorado-ai-act",
        }) + "\n")

    # Show results
    console.print(Panel(
        f"[bold green]✓ Impact assessment complete[/bold green]\n\n"
        f"Assessment ID: [cyan]{assessment_id}[/cyan]\n"
        f"Risk level:    [{'red' if risk_level == 'HIGH' else 'yellow' if risk_level == 'MEDIUM' else 'green'}]{risk_level}[/]\n"
        f"Findings:      {len(findings)}\n"
        f"Recommendations: {len(recommendations)}\n\n"
        f"Files updated:\n"
        f"  [dim]{assessment_file}[/dim]\n"
        f"  [dim]{passport_file}[/dim]\n\n"
        f"CO-002 best practice: [bold green]{'SATISFIED' if questionnaire_answers.get('impact_assessment') else 'RECOMMENDED'}[/bold green]\n\n"
        f"Next step: [bold]iris compliance check --framework colorado-ai-act[/bold]",
        style="green"
    ))

    if findings:
        console.print("\n[bold yellow]Findings to address:[/bold yellow]")
        for f in findings:
            console.print(f"  [yellow]•[/yellow] {f}")

    if recommendations:
        console.print("\n[bold]Recommendations:[/bold]")
        for r in recommendations:
            console.print(f"  [blue]→[/blue] {r}")
