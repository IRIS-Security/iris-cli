"""iris test — framework-based certification readiness scoring."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import click
from rich.console import Console
from rich.panel import Panel

from iris_core.entitlements import Entitlements, Feature
from iris_core.evidence.vault import EvidenceVault
from iris_core.models.passport import AgentPassport, DataClassification

console = Console()

PRO_BUNDLES = {
    "nist-ai-rmf",
    "fedramp-moderate",
    "hipaa",
    "soc2",
    "gdpr",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
MS25_PARTIAL_MISSING = (
    "Free tier provides 30-day local retention. "
    "NIST AI RMF MS-2.5 recommends ongoing risk tracking. "
    "30 days of history partially satisfies this control."
)
MS25_PARTIAL_FIX = (
    "For full satisfaction:\n"
    "iris license activate <key>\n"
    "This enables unlimited Evidence Vault retention so your "
    "complete governance history satisfies MS-2.5."
)
EFFORT_BY_REASON = {
    "infrastructure": "1 week",
    "document": "1 hour",
    "passport": "5 minutes",
    "process": "1 day",
}


@dataclass
class ControlGap:
    rule_id: str
    name: str
    severity: str
    status: str
    what_is_missing: str
    how_to_fix: str
    estimated_effort: str


@dataclass
class FrameworkTestResult:
    framework: str
    agent_name: str
    total_controls: int
    passed_controls: int
    failed_controls: int
    partial_controls: int
    not_applicable: int
    score: float
    score_percent: int
    readiness_level: str
    gaps: List[ControlGap]
    timestamp: str
    progress_delta_percent: Optional[int] = None


def _framework_name(framework: str) -> str:
    mapping = {
        "colorado-ai-act": "Colorado AI Act",
        "nist-ai-rmf": "NIST AI Risk Management Framework",
        "fedramp-moderate": "FedRAMP Moderate",
        "hipaa": "HIPAA Security & Privacy Rule",
        "soc2": "SOC 2 Type II",
        "gdpr": "General Data Protection Regulation (GDPR)",
    }
    return mapping.get(framework, framework)


def _rule(
    rule_id: str,
    name: str,
    severity: str,
    check: str,
    missing: str,
    fix: str,
    effort_reason: str,
) -> Dict[str, str]:
    return {
        "rule_id": rule_id,
        "name": name,
        "severity": severity,
        "check": check,
        "what_is_missing": missing,
        "how_to_fix": fix,
        "estimated_effort": EFFORT_BY_REASON[effort_reason],
    }


def _framework_bundle(framework: str) -> Dict[str, Any]:
    bundles: Dict[str, Dict[str, Any]] = {
        "colorado-ai-act": {
            "bundle_id": "colorado-ai-act",
            "full_name": _framework_name("colorado-ai-act"),
            "rules": [
                _rule(
                    "CO-001",
                    "High-risk AI inventory",
                    "CRITICAL",
                    "passport.is_high_risk_ai and bool(passport.agent_id)",
                    "Agent is not marked as high-risk or missing agent identity.",
                    "Run: iris register --name <agent> --high-risk",
                    "passport",
                ),
                _rule(
                    "CO-002",
                    "Impact assessment required",
                    "CRITICAL",
                    "files['impact_assessment_exists']",
                    "Impact assessment document is missing.",
                    "Run: iris compliance assess --agent <agent>",
                    "document",
                ),
                _rule(
                    "CO-003",
                    "Transparency disclosure",
                    "HIGH",
                    "files['policy_cedar_exists'] and files['policy_cedar_compiled']",
                    "Compiled Cedar policy evidence is missing.",
                    "Run: iris policy compile --agent <agent>",
                    "document",
                ),
                _rule(
                    "CO-006",
                    "Annual review evidence",
                    "MEDIUM",
                    "vault.total_evaluations > 0",
                    "No ongoing governance evidence exists in the vault.",
                    "Run weekly: iris scan --framework colorado-ai-act",
                    "process",
                ),
            ],
        },
        "nist-ai-rmf": {
            "bundle_id": "nist-ai-rmf",
            "full_name": _framework_name("nist-ai-rmf"),
            "rules": [
                _rule(
                    "GV-1.3",
                    "Organizational commitment to AI risk management",
                    "HIGH",
                    "vault.total_evaluations >= 4",
                    "No ongoing monitoring evidence in Evidence Vault.",
                    "Run weekly and store evidence: iris scan --framework nist-ai-rmf",
                    "process",
                ),
                _rule(
                    "MS-2.5",
                    "Risk tracking in organizational systems",
                    "CRITICAL",
                    "vault.total_evaluations >= 30",
                    "Evidence Vault lacks sufficient historical data for risk trending.",
                    "Run: iris license activate <key> and retain 30+ day vault history",
                    "infrastructure",
                ),
                _rule(
                    "MG-2.2",
                    "Mechanisms for AI incident response",
                    "HIGH",
                    "vault.hitl_gates_triggered > 0",
                    "No HITL gate evidence is recorded for incident response.",
                    "Run: iris license activate <key> then configure HITL workflow",
                    "process",
                ),
                _rule(
                    "MG-3.1",
                    "AI risk response policy enforcement",
                    "CRITICAL",
                    "files['policy_cedar_exists'] and files['policy_cedar_compiled']",
                    "Cedar policy is missing or not compiled.",
                    "Run: iris policy compile --agent <agent>",
                    "document",
                ),
                _rule(
                    "MP-1.5",
                    "Context and impact assessments are documented",
                    "CRITICAL",
                    "files['impact_assessment_exists']",
                    "Impact assessment evidence is missing.",
                    "Run: iris compliance assess --agent <agent>",
                    "document",
                ),
            ],
        },
        "hipaa": {
            "bundle_id": "hipaa",
            "full_name": _framework_name("hipaa"),
            "rules": [
                _rule(
                    "HIPAA-001",
                    "PHI data classification",
                    "CRITICAL",
                    "passport.data_classification == DataClassification.PHI",
                    "PHI data classification missing",
                    "Set data_classification=PHI in passport",
                    "passport",
                ),
                _rule(
                    "HIPAA-002",
                    "Evidence Vault PHI audit trail",
                    "HIGH",
                    "vault.total_evaluations > 0",
                    "Evidence Vault not recording PHI",
                    "Ensure IRIS client is wrapping LLM calls",
                    "process",
                ),
                _rule(
                    "HIPAA-003",
                    "Region restriction for PHI",
                    "HIGH",
                    "len(passport.allowed_regions) > 0",
                    "No region restriction declared",
                    "Add allowed_regions to passport",
                    "passport",
                ),
                _rule(
                    "HIPAA-004",
                    "Minimum necessary tool permissions",
                    "HIGH",
                    "len(passport.tool_permissions) > 0",
                    "No minimum-necessary tool permissions declared",
                    "Declare tool_permissions in passport.yaml",
                    "passport",
                ),
                _rule(
                    "HIPAA-005",
                    "Business Associate Agreement evidence",
                    "CRITICAL",
                    "passport.evidence_vault_id is not None",
                    "BAA evidence not linked in Evidence Vault",
                    f"Run: iris evidence init --agent <agent>",
                    "document",
                ),
                _rule(
                    "HIPAA-006",
                    "Breach notification readiness",
                    "CRITICAL",
                    "files['policy_cedar_exists']",
                    "Runtime policy enforcement not configured",
                    "Run: iris policy compile --agent <agent>",
                    "document",
                ),
                _rule(
                    "HIPAA-007",
                    "De-identification policy",
                    "HIGH",
                    "passport.intent_ref is not None",
                    "De-identification policy not declared",
                    "Add policy-intent.md and run iris policy compile",
                    "document",
                ),
            ],
        },
    }

    # Reuse NIST-style checks for paid frameworks until dedicated bundles are added.
    for paid_alias in ("fedramp-moderate", "soc2", "gdpr"):
        alias_bundle = dict(bundles["nist-ai-rmf"])
        alias_bundle["bundle_id"] = paid_alias
        alias_bundle["full_name"] = _framework_name(paid_alias)
        bundles[paid_alias] = alias_bundle

    if framework not in bundles:
        raise click.ClickException(f"Unsupported framework: {framework}")
    return bundles[framework]


def _evaluate_check(check_expr: str, passport: AgentPassport, vault_summary: Any, files: Dict[str, Any]) -> str:
    safe_globals = {"__builtins__": {}}
    safe_locals = {
        "passport": passport,
        "vault": vault_summary,
        "files": files,
        "DataClassification": DataClassification,
        "bool": bool,
        "len": len,
        "all": all,
        "any": any,
    }
    try:
        value = eval(check_expr, safe_globals, safe_locals)
    except Exception:
        return "PARTIAL"
    if value is True:
        return "PASS"
    if value is False:
        return "FAIL"
    return "NOT_APPLICABLE"


def _readiness_level(score_percent: int) -> str:
    if score_percent >= 95:
        return "CERTIFIED_READY"
    if score_percent >= 80:
        return "ADVANCED"
    if score_percent >= 50:
        return "DEVELOPING"
    return "INITIAL"


def _test_results_path(agent: str, framework: str, timestamp: str) -> Path:
    return Path.home() / ".iris" / "test-results" / agent / framework / f"{timestamp}.json"


def _load_previous_score(agent: str, framework: str) -> Optional[int]:
    folder = Path.home() / ".iris" / "test-results" / agent / framework
    if not folder.exists():
        return None
    entries = sorted(folder.glob("*.json"))
    if not entries:
        return None
    if len(entries) >= 2:
        previous = entries[-2]
    else:
        previous = entries[-1]
    try:
        payload = json.loads(previous.read_text())
        return int(payload.get("score_percent", 0))
    except Exception:
        return None


def _save_result(result: FrameworkTestResult) -> Path:
    path = _test_results_path(result.agent_name, result.framework, result.timestamp)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = asdict(result)
    payload["gaps"] = [asdict(gap) for gap in result.gaps]
    path.write_text(json.dumps(payload, indent=2))
    return path


def _build_result(framework: str, agent: str, passport: AgentPassport) -> FrameworkTestResult:
    bundle = _framework_bundle(framework)
    vault = EvidenceVault(agent_id=agent)
    summary = vault.get_summary(last_reviewed_at=passport.last_reviewed_at.isoformat() if passport.last_reviewed_at else None)
    agent_dir = Path.cwd() / "governance" / "agents" / agent
    policy_file = agent_dir / "policy.cedar"
    files = {
        "policy_cedar_exists": policy_file.exists(),
        "policy_cedar_compiled": policy_file.exists() and "permit (" in policy_file.read_text(),
        "impact_assessment_exists": (agent_dir / "impact-assessment.md").exists(),
    }

    gaps: List[ControlGap] = []
    pass_count = fail_count = partial_count = na_count = 0

    for rule in bundle["rules"]:
        status = _evaluate_check(rule["check"], passport, summary, files)
        if (
            rule["rule_id"] == "MS-2.5"
            and status == "FAIL"
            and not Entitlements().has(Feature.VAULT_UNLIMITED_RETENTION)
        ):
            status = "PARTIAL"

        if status == "PASS":
            pass_count += 1
            continue
        if status == "NOT_APPLICABLE":
            na_count += 1
            continue
        if status == "PARTIAL":
            partial_count += 1
        else:
            fail_count += 1
            status = "FAIL"

        what_is_missing = rule["what_is_missing"]
        how_to_fix = rule["how_to_fix"]
        if rule["rule_id"] == "MS-2.5" and status == "PARTIAL":
            what_is_missing = MS25_PARTIAL_MISSING
            how_to_fix = MS25_PARTIAL_FIX

        gaps.append(
            ControlGap(
                rule_id=rule["rule_id"],
                name=rule["name"],
                severity=rule["severity"],
                status=status,
                what_is_missing=what_is_missing,
                how_to_fix=how_to_fix.replace("<agent>", agent),
                estimated_effort=rule["estimated_effort"],
            )
        )

    gaps.sort(key=lambda g: (SEVERITY_ORDER.get(g.severity, 999), g.rule_id))
    denominator = max(1, len(bundle["rules"]) - na_count)
    score = pass_count / denominator
    score_percent = int(score * 100)
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    return FrameworkTestResult(
        framework=framework,
        agent_name=agent,
        total_controls=len(bundle["rules"]),
        passed_controls=pass_count,
        failed_controls=fail_count,
        partial_controls=partial_count,
        not_applicable=na_count,
        score=score,
        score_percent=score_percent,
        readiness_level=_readiness_level(score_percent),
        gaps=gaps,
        timestamp=timestamp,
    )


def _render_free_tier_panel(result: FrameworkTestResult) -> str:
    framework_label = _framework_name(result.framework)
    evaluated = result.passed_controls + result.failed_controls + result.partial_controls
    filled = int((evaluated / max(1, result.total_controls)) * 10)
    bar = f"{'█' * filled}{'░' * (10 - filled)}"
    title = f"{framework_label} Test: {result.agent_name}"
    pad = max(0, 60 - len(title) - 4)
    lines = [
        f"┌─ {title} {'─' * pad}┐",
        "│ Certification Readiness                                     │",
        f"│ {bar}  {evaluated} / {result.total_controls} controls evaluated{' ' * max(0, 22 - len(str(evaluated)) - len(str(result.total_controls)))}│",
        "│ Score: requires Pro for full evaluation                    │",
        "│                                                             │",
        "│ TOP 3 GAPS (free preview)                                  │",
    ]
    for index, gap in enumerate(result.gaps[:3], start=1):
        lines.append(
            f"│ {index}. [{gap.severity}] {gap.rule_id} — {gap.name[:35]:<35} │"
        )
        fix = gap.how_to_fix.split("\n")[0][:48]
        lines.append(f"│    Fix: {fix:<51}│")
        lines.append(f"│    Time: {gap.estimated_effort:<49}│")
        if index < min(3, len(result.gaps)):
            lines.append("│                                                             │")
    total = result.total_controls
    lines.extend(
        [
            "│                                                             │",
            f"│ See all {total} controls + evidence package:{' ' * max(0, 24 - len(str(total)))}│",
            "│ iris license activate <key>                                │",
            "└─────────────────────────────────────────────────────────────┘",
        ]
    )
    return "\n".join(lines)


def _render_table(result: FrameworkTestResult, has_pro: bool) -> None:
    if not has_pro:
        console.print(_render_free_tier_panel(result))
        return

    framework_label = _framework_name(result.framework)
    console.print(
        Panel(
            f"Framework: {framework_label}\nGenerated: {datetime.utcnow().strftime('%Y-%m-%d')}  |  IRIS Pro active",
            title=f"{framework_label} Test — {result.agent_name}",
            style="blue",
        )
    )

    filled = int((result.score_percent / 100) * 20)
    bar = f"{'█' * filled}{'░' * (20 - filled)}"
    console.print("[bold]CERTIFICATION READINESS SCORE[/bold]")
    console.print(
        f"{bar}  {result.passed_controls} / {result.total_controls} controls  ({result.score_percent}%)"
    )
    console.print(f"Level: [bold]{result.readiness_level}[/bold]")
    console.print(
        f"PASSED ({result.passed_controls})   FAILED ({result.failed_controls})   "
        f"PARTIAL ({result.partial_controls})   N/A ({result.not_applicable})"
    )
    if result.progress_delta_percent is not None:
        delta = result.progress_delta_percent
        sign = "+" if delta >= 0 else ""
        console.print(f"Progress since last run: [bold]{sign}{delta}%[/bold]")

    console.print("\n[bold]ALL GAPS[/bold]")
    console.print("─" * 65)
    for gap in result.gaps:
        console.print(f"[{gap.severity}] {gap.rule_id} — {gap.name}")
        console.print(f"Status: {gap.status}")
        console.print(f"Missing: {gap.what_is_missing}")
        console.print(f"Fix: {gap.how_to_fix}")
        console.print(f"Effort: {gap.estimated_effort}\n")


def _render_markdown(result: FrameworkTestResult, has_pro: bool) -> str:
    lines = [
        f"# {_framework_name(result.framework)} Test Report — {result.agent_name}",
        "",
        f"- Framework: {_framework_name(result.framework)}",
        f"- Generated: {datetime.utcnow().strftime('%Y-%m-%d')}",
        f"- Readiness level: {result.readiness_level}",
        f"- Score: {result.passed_controls}/{result.total_controls} ({result.score_percent}%)",
        "",
        "## Control Summary",
        "",
        f"- Passed: {result.passed_controls}",
        f"- Failed: {result.failed_controls}",
        f"- Partial: {result.partial_controls}",
        f"- Not applicable: {result.not_applicable}",
    ]
    if has_pro and result.progress_delta_percent is not None:
        lines.append(f"- Progress since last run: {result.progress_delta_percent:+d}%")

    lines.extend(["", "## Gaps", ""])
    for gap in (result.gaps if has_pro else result.gaps[:3]):
        lines.extend(
            [
                f"### {gap.rule_id} — {gap.name}",
                f"- Severity: {gap.severity}",
                f"- Status: {gap.status}",
                f"- Missing: {gap.what_is_missing}",
                f"- Fix: {gap.how_to_fix}",
                f"- Estimated effort: {gap.estimated_effort}",
                "",
            ]
        )
    if not has_pro and len(result.gaps) > 3:
        lines.extend(
            [
                f"Only top 3 of {len(result.gaps)} gaps are shown on free tier.",
                "",
                "Upgrade to IRIS Pro:",
                "- iris license activate <your-key>",
                "- https://iris.ai/pricing",
            ]
        )
    return "\n".join(lines)


def _render_json(result: FrameworkTestResult, has_pro: bool) -> str:
    payload = asdict(result)
    if not has_pro:
        payload["gaps"] = payload["gaps"][:3]
        payload["hidden_gap_count"] = max(0, len(result.gaps) - 3)
    return json.dumps(payload, indent=2)


@click.command("test")
@click.option("--framework", required=True, type=click.Choice(sorted(["colorado-ai-act", "nist-ai-rmf", "fedramp-moderate", "hipaa", "soc2", "gdpr"])))
@click.option("--agent", "agent_name", required=True, help="Agent name under governance/agents")
@click.option("--format", "output_format", default="table", type=click.Choice(["table", "json", "markdown"]))
@click.option("--export", "export_format", default=None, type=click.Choice(["pdf"]), help="Export report format (paid tier)")
def test(framework: str, agent_name: str, output_format: str, export_format: Optional[str]) -> None:
    """Run certification readiness checks against a framework bundle."""
    passport_path = Path.cwd() / "governance" / "agents" / agent_name / "passport.yaml"
    if not passport_path.exists():
        raise click.ClickException(f"Passport not found: {passport_path}")
    passport = AgentPassport.from_yaml(passport_path.read_text())

    ents = Entitlements()
    has_pro = ents.has(Feature.CLI_TEST_FULL_REPORT)

    result = _build_result(framework, agent_name, passport)
    previous = _load_previous_score(agent_name, framework)
    if previous is not None and has_pro:
        result.progress_delta_percent = result.score_percent - previous

    saved_path = _save_result(result)

    if export_format == "pdf":
        if not ents.has(Feature.CLI_TEST_PDF_EXPORT):
            try:
                ents.require(Feature.CLI_TEST_PDF_EXPORT, context="PDF export")
            except Exception as exc:
                raise click.ClickException(str(exc)) from exc
        pdf_path = saved_path.with_suffix(".pdf")
        pdf_path.write_text("PDF export placeholder. Use IRIS Pro renderer in hosted pipeline.")

    if output_format == "json":
        click.echo(_render_json(result, has_pro))
    elif output_format == "markdown":
        click.echo(_render_markdown(result, has_pro))
    else:
        _render_table(result, has_pro)
