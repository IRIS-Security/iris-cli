"""
iris evidence — Evidence Vault read path and audit reporting.

Fully offline: no LLM calls, no network. Generates audit reports for
CISO review, annual compliance checks, and external auditor handoff.

Copyright 2024-2025 Gilbert Martin / IRIS Security, Inc.
All Rights Reserved. Proprietary and Confidential.
"""

from __future__ import annotations

import csv
import io
import json
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from iris_core.compliance.exporters.aiuc1_export import AIUC1EvidenceExporter
from iris_core.compliance.exporters.evidence_html import build_evidence_html
from iris_core.entitlements import Entitlements, Feature
from iris_core.evidence.vault import EvidenceVault, VaultSummary
from iris_core.evidence.vault_v2 import EvidenceVaultV2
from iris_core.compliance.bundles.colorado_ai_act import get_colorado_rules
from iris_core.models.passport import AgentPassport

console = Console()

ANNUAL_REVIEW_WARNING_DAYS = 30


def _governance_dir(governance_dir: Optional[Path]) -> Path:
    return governance_dir or Path.cwd() / "governance" / "agents"


def _load_passport(agent: str, governance_dir: Optional[Path]) -> AgentPassport:
    passport_file = _governance_dir(governance_dir) / agent / "passport.yaml"
    if not passport_file.exists():
        raise FileNotFoundError(
            f"Passport not found: {passport_file}\nRun: iris register --name {agent}"
        )
    return AgentPassport.from_yaml(passport_file.read_text())


def _last_reviewed_iso(passport: AgentPassport) -> Optional[str]:
    if passport.last_reviewed_at:
        return passport.last_reviewed_at.isoformat()
    return None


def _open_vault(agent: str, vault_dir: Optional[Path]) -> EvidenceVault:
    return EvidenceVault(agent_id=agent, vault_dir=vault_dir)


def _compliance_status(passport: AgentPassport) -> List[dict]:
    """Evaluate Colorado AI Act rules against passport fields."""
    rules = get_colorado_rules()["rules"]
    statuses: List[dict] = []

    checks = {
        "CO-001": bool(passport.agent_id) and bool(passport.owner),
        "CO-002": bool(passport.evidence_vault_id),
        "CO-003": bool(passport.intent_ref),
        "CO-004": bool(passport.intent_ref),
        "CO-RR-001": None,
        "CO-DEV-001": bool(passport.intent_ref) and bool(passport.description),
    }

    for rule in rules:
        rule_id = rule["rule_id"]
        if rule.get("status") == "BEST_PRACTICE":
            passed = checks.get(rule_id)
            status = "PASS" if passed else "RECOMMENDED"
            statuses.append(
                {
                    "rule_id": rule_id,
                    "name": rule["name"],
                    "status": status,
                    "detail": "Best practice (not legally required under SB 26-189)",
                }
            )
            continue

        passed = checks.get(rule_id)
        if passed is True:
            status = "PASS"
        elif passed is False:
            status = "FAIL"
        else:
            status = "PENDING"

        statuses.append(
            {"rule_id": rule_id, "name": rule["name"], "status": status, "detail": ""}
        )

    return statuses


def _annual_review_block(passport: AgentPassport, summary: VaultSummary) -> dict:
    last_reviewed = _last_reviewed_iso(passport)
    if not last_reviewed:
        return {
            "last_reviewed": None,
            "next_review_due": None,
            "days_until": None,
            "status": "OVERDUE",
            "status_label": "OVERDUE — no review on record",
        }

    reviewed_dt = passport.last_reviewed_at
    next_due = reviewed_dt + timedelta(days=365)
    days_until = summary.days_until_annual_review

    if days_until is not None and days_until < 0:
        status = "OVERDUE"
        status_label = f"OVERDUE by {abs(days_until)} days"
    elif days_until is not None and days_until <= ANNUAL_REVIEW_WARNING_DAYS:
        status = "DUE SOON"
        status_label = f"Due in {days_until} days"
    else:
        status = "CURRENT"
        status_label = "Current"

    return {
        "last_reviewed": reviewed_dt.strftime("%Y-%m-%d"),
        "next_review_due": next_due.strftime("%Y-%m-%d"),
        "days_until": days_until,
        "status": status,
        "status_label": status_label,
    }


def _violation_trend(events: List[dict]) -> List[dict]:
    """Group violation counts by month for trend reporting."""
    by_month: Counter[str] = Counter()
    for event in events:
        ts = event.get("timestamp", "")[:7]
        if not ts:
            continue
        count = len(event.get("violations", []))
        if count:
            by_month[ts] += count
    return [{"month": month, "violations": count} for month, count in sorted(by_month.items())]


def _top_violations(violations_by_rule: Dict[str, int], limit: int = 5) -> List[dict]:
    rule_names = {r["rule_id"]: r["name"] for r in get_colorado_rules()["rules"]}
    rule_names.update(
        {
            "IRIS-TOOL-001": "Tool not in declared permissions",
            "IRIS-XR-001": "Cross-region transfer attempted",
            "IRIS-ENV-001": "Environment not authorized",
        }
    )
    ranked = sorted(violations_by_rule.items(), key=lambda x: x[1], reverse=True)
    return [
        {
            "rule_id": rule_id,
            "name": rule_names.get(rule_id, rule_id),
            "count": count,
        }
        for rule_id, count in ranked[:limit]
    ]


def build_report_data(
    agent: str,
    passport: AgentPassport,
    vault: EvidenceVault,
    since: Optional[str] = None,
) -> dict:
    last_reviewed = _last_reviewed_iso(passport)
    summary = vault.get_summary(last_reviewed_at=last_reviewed)
    events = vault.get_events(limit=10_000, since=since)
    assessments = vault.get_assessments()
    integrity = vault.check_integrity(passport.evidence_vault_id)

    xr_events = [
        e
        for e in events
        if any(v.get("rule_id") == "IRIS-XR-001" for v in e.get("violations", []))
    ]
    hitl_events = [e for e in events if e.get("decision") == "HITL"]

    retention_warning = vault.get_retention_warning()
    oldest_age_days = None
    if summary.retention_days_remaining < EvidenceVault.FREE_RETENTION_DAYS:
        oldest_age_days = (
            EvidenceVault.FREE_RETENTION_DAYS - summary.retention_days_remaining
        )

    return {
        "agent": agent,
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d"),
        "period": since or f"last {EvidenceVault.FREE_RETENTION_DAYS} days",
        "identity": {
            "owner": passport.owner,
            "team": passport.team,
            "is_high_risk_ai": passport.is_high_risk_ai,
            "frameworks": [t.value for t in passport.compliance_tags],
            "assessment_id": passport.evidence_vault_id,
        },
        "compliance": _compliance_status(passport),
        "statistics": {
            "total_evaluations": summary.total_evaluations,
            "pass_rate": summary.compliance_pass_rate,
            "total_violations": summary.total_violations,
            "violations_by_severity": summary.violations_by_severity,
            "environments_active": summary.environments_active,
        },
        "top_violations": _top_violations(summary.violations_by_rule),
        "violation_trend": _violation_trend(events),
        "assessments": assessments,
        "cross_region_events": xr_events,
        "hitl_events": hitl_events,
        "annual_review": _annual_review_block(passport, summary),
        "integrity": integrity,
        "summary": summary,
        "retention": {
            "free_tier_days": EvidenceVault.FREE_RETENTION_DAYS,
            "days_remaining": summary.retention_days_remaining,
            "oldest_event_age_days": oldest_age_days,
            "upgrade_available": summary.upgrade_available,
            "warning": retention_warning,
        },
    }


def format_report_markdown(data: dict) -> str:
    identity = data["identity"]
    stats = data["statistics"]
    review = data["annual_review"]
    lines = [
        f"# Evidence Vault Report: {data['agent']}",
        "",
        f"**Period:** {data['period']}  |  **Generated:** {data['generated_at']}",
        "",
        "## Agent Identity",
        "",
        f"- **Owner:** {identity['owner']} ({identity['team']})",
        f"- **High-risk AI:** {'Yes' if identity['is_high_risk_ai'] else 'No'}",
        f"- **Framework:** {', '.join(identity['frameworks']) or 'none'}",
        f"- **Assessment ID:** {identity['assessment_id'] or 'none'}",
        "",
        "## Compliance Status",
        "",
    ]

    for item in data["compliance"]:
        icon = {"PASS": "✓", "FAIL": "✗", "PENDING": "⚠"}.get(item["status"], "?")
        detail = f" ({item['detail']})" if item.get("detail") else ""
        lines.append(
            f"- {icon} **{item['rule_id']}**  {item['name']}  "
            f"**{item['status']}**{detail}"
        )

    pass_pct = stats["pass_rate"] * 100
    sev_parts = [
        f"{count} {sev}"
        for sev, count in sorted(stats["violations_by_severity"].items(), reverse=True)
    ]
    sev_text = f" ({', '.join(sev_parts)})" if sev_parts else ""

    lines.extend(
        [
            "",
            "## Evaluation Statistics",
            "",
            f"- **Total evaluations:** {stats['total_evaluations']}",
            f"- **Pass rate:** {pass_pct:.1f}%",
            f"- **Violations:** {stats['total_violations']}{sev_text}",
            f"- **Environments active:** {', '.join(stats['environments_active']) or 'none'}",
            "",
            "## Top Violations",
            "",
        ]
    )

    if data["top_violations"]:
        for v in data["top_violations"]:
            lines.append(f"- **{v['rule_id']}**  {v['name']}  — {v['count']} times")
    else:
        lines.append("- No violations recorded")

    if data["violation_trend"]:
        lines.extend(["", "## Violation Trend", ""])
        for point in data["violation_trend"]:
            lines.append(f"- {point['month']}: {point['violations']} violations")

    if data["assessments"]:
        lines.extend(["", "## Impact Assessment History", ""])
        for assessment in data["assessments"]:
            lines.append(
                f"- {assessment.get('timestamp', 'unknown')[:10]}  "
                f"**{assessment.get('assessment_id', 'unknown')}**  "
                f"risk={assessment.get('risk_level', 'unknown')}"
            )

    lines.extend(
        [
            "",
            "## Cross-Region Detection",
            "",
            f"- **Blocks recorded:** {len(data['cross_region_events'])}",
        ]
    )
    for event in data["cross_region_events"][:5]:
        lines.append(
            f"  - {event.get('timestamp', '')[:19]}  "
            f"{event.get('action')} → {event.get('resource')}"
        )

    lines.extend(
        [
            "",
            "## HITL Gate Events",
            "",
            f"- **Gates triggered:** {len(data['hitl_events'])}",
        ]
    )
    for event in data["hitl_events"][:5]:
        lines.append(
            f"  - {event.get('timestamp', '')[:19]}  "
            f"{event.get('action')} → {event.get('resource')}"
        )

    review_status = review["status_label"]
    if review["status"] == "CURRENT":
        review_status = f"✓ {review_status}"

    retention = data.get("retention", {})
    lines.extend(["", "## Retention", ""])
    if retention.get("oldest_event_age_days") is not None:
        lines.append(
            f"- **Oldest event:** {retention['oldest_event_age_days']} days ago"
        )
        lines.append(
            f"- **Free tier limit:** {retention['free_tier_days']} days  │  "
            f"{retention['days_remaining']} days remaining"
        )
    else:
        lines.append(f"- **Free tier limit:** {retention.get('free_tier_days', 30)} days")
        lines.append("- **Oldest event:** none recorded")
    if retention.get("upgrade_available") and retention.get("warning"):
        lines.extend(
            [
                "",
                retention["warning"],
            ]
        )
    elif retention.get("upgrade_available"):
        lines.extend(
            [
                "",
                "Upgrade to IRIS Pro for unlimited retention + PDF export",
                "iris license activate <your-key>",
            ]
        )

    lines.extend(
        [
            "",
            "## Annual Review",
            "",
            f"- **Last reviewed:** {review['last_reviewed'] or 'never'}",
            f"- **Next review due:** {review['next_review_due'] or 'unknown'}"
            + (
                f"  ({review['days_until']} days)"
                if review["days_until"] is not None and review["days_until"] >= 0
                else ""
            ),
            f"- **Status:** {review_status}",
            "",
            "## Evidence Vault Integrity",
            "",
        ]
    )

    if data["integrity"]["valid"]:
        lines.append("- ✓ All entries consistent")
    else:
        lines.append("- ✗ **Vault corruption detected**")
        for issue in data["integrity"]["issues"]:
            lines.append(f"  - {issue}")

    return "\n".join(lines)


def format_report_json(data: dict) -> str:
    summary: VaultSummary = data["summary"]
    payload = {
        "schema_version": "1.0",
        "agent": data["agent"],
        "generated_at": data["generated_at"],
        "period": data["period"],
        "identity": data["identity"],
        "compliance": data["compliance"],
        "statistics": data["statistics"],
        "top_violations": data["top_violations"],
        "violation_trend": data["violation_trend"],
        "assessments": data["assessments"],
        "cross_region_event_count": len(data["cross_region_events"]),
        "hitl_event_count": len(data["hitl_events"]),
        "annual_review": data["annual_review"],
        "integrity": data["integrity"],
        "summary": {
            "agent_id": summary.agent_id,
            "total_evaluations": summary.total_evaluations,
            "total_violations": summary.total_violations,
            "violations_by_severity": summary.violations_by_severity,
            "violations_by_rule": summary.violations_by_rule,
            "most_violated_rule": summary.most_violated_rule,
            "compliance_pass_rate": summary.compliance_pass_rate,
            "last_assessment_date": summary.last_assessment_date,
            "last_reviewed_at": summary.last_reviewed_at,
            "days_until_annual_review": summary.days_until_annual_review,
            "environments_active": summary.environments_active,
            "cross_region_blocks": summary.cross_region_blocks,
            "hitl_gates_triggered": summary.hitl_gates_triggered,
            "retention_days_remaining": summary.retention_days_remaining,
            "upgrade_available": summary.upgrade_available,
        },
        "retention": data.get("retention"),
    }
    return json.dumps(payload, indent=2)


def _print_report_table(data: dict) -> None:
    agent = data["agent"]
    console.print(
        Panel(
            f"Period: {data['period']}  │  Generated: {data['generated_at']}",
            title=f"Evidence Vault Report: {agent}",
            style="blue",
        )
    )

    identity = data["identity"]
    console.print("\n[bold]AGENT IDENTITY[/bold]")
    console.print(
        f"Owner: {identity['owner']} ({identity['team']})\n"
        f"High-risk AI: {'Yes' if identity['is_high_risk_ai'] else 'No'}  │  "
        f"Framework: {', '.join(identity['frameworks']) or 'none'}\n"
        f"Assessment ID: {identity['assessment_id'] or 'none'}"
    )

    console.print("\n[bold]COMPLIANCE STATUS[/bold]")
    for item in data["compliance"]:
        icon = {"PASS": "[green]✓[/green]", "FAIL": "[red]✗[/red]", "PENDING": "[yellow]⚠[/yellow]"}.get(
            item["status"], "?"
        )
        detail = f" ({item['detail']})" if item.get("detail") else ""
        console.print(
            f"{icon} {item['rule_id']}  {item['name']:<30}  {item['status']}{detail}"
        )

    stats = data["statistics"]
    pass_pct = stats["pass_rate"] * 100
    sev_parts = [
        f"{count} {sev}"
        for sev, count in sorted(stats["violations_by_severity"].items(), reverse=True)
    ]
    sev_text = f"  ({', '.join(sev_parts)})" if sev_parts else ""

    console.print("\n[bold]EVALUATION STATISTICS[/bold]")
    console.print(
        f"Total evaluations:    {stats['total_evaluations']}\n"
        f"Pass rate:            {pass_pct:.1f}%\n"
        f"Violations:           {stats['total_violations']}{sev_text}\n"
        f"Environments active:  {', '.join(stats['environments_active']) or 'none'}"
    )

    console.print("\n[bold]TOP VIOLATIONS[/bold]")
    if data["top_violations"]:
        for v in data["top_violations"]:
            console.print(f"{v['rule_id']:<16} {v['name']:<40} {v['count']} times")
    else:
        console.print("[dim]No violations recorded[/dim]")

    retention = data.get("retention", {})
    console.print("\n[bold]RETENTION[/bold]")
    if retention.get("oldest_event_age_days") is not None:
        console.print(
            f"Oldest event: {retention['oldest_event_age_days']} days ago\n"
            f"Free tier limit: {retention['free_tier_days']} days  │  "
            f"{retention['days_remaining']} days remaining"
        )
    else:
        console.print(
            f"Free tier limit: {retention.get('free_tier_days', 30)} days  │  "
            "no events recorded"
        )
    if retention.get("upgrade_available"):
        console.print("[dim]─────────────────────────────────────────────────────────[/dim]")
        if retention.get("warning"):
            console.print(f"[yellow]{retention['warning']}[/yellow]")
        else:
            console.print(
                "Upgrade to IRIS Pro for unlimited retention + PDF export\n"
                "iris license activate <your-key>"
            )

    review = data["annual_review"]
    console.print("\n[bold]ANNUAL REVIEW[/bold]")
    status_style = {
        "CURRENT": "[green]✓ Current[/green]",
        "OVERDUE": "[red]OVERDUE[/red]",
        "DUE SOON": "[yellow]Due soon[/yellow]",
    }.get(review["status"], review["status_label"])
    days_suffix = ""
    if review["days_until"] is not None and review["days_until"] >= 0:
        days_suffix = f"  ({review['days_until']} days)"
    console.print(
        f"Last reviewed:    {review['last_reviewed'] or 'never'}\n"
        f"Next review due:  {review['next_review_due'] or 'unknown'}{days_suffix}\n"
        f"Status:           {status_style}"
    )

    console.print("\n[bold]INTEGRITY CHECK[/bold]")
    if data["integrity"]["valid"]:
        console.print("[green]✓ All vault entries consistent[/green]")
    else:
        console.print("[red]✗ Vault corruption detected[/red]")
        for issue in data["integrity"]["issues"]:
            console.print(f"  [red]•[/red] {issue}")


def _events_table(events: List[dict]) -> Table:
    table = Table(title="Evidence Vault Events")
    table.add_column("Timestamp", style="dim", no_wrap=True)
    table.add_column("Action")
    table.add_column("Resource")
    table.add_column("Decision")
    table.add_column("Violation Rule")
    for event in events:
        rules = ", ".join(v.get("rule_id", "") for v in event.get("violations", []))
        table.add_row(
            event.get("timestamp", "")[:19],
            event.get("action", ""),
            event.get("resource", ""),
            event.get("decision", ""),
            rules or "—",
        )
    return table


def _export_csv(vault_data: dict, output_path: Path) -> None:
    fieldnames = [
        "event_id",
        "timestamp",
        "agent_id",
        "action",
        "resource",
        "environment",
        "decision",
        "violation_rules",
        "violation_severities",
    ]
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for event in vault_data["events"]:
            violations = event.get("violations", [])
            writer.writerow(
                {
                    "event_id": event.get("event_id"),
                    "timestamp": event.get("timestamp"),
                    "agent_id": event.get("agent_id"),
                    "action": event.get("action"),
                    "resource": event.get("resource"),
                    "environment": event.get("environment"),
                    "decision": event.get("decision"),
                    "violation_rules": ";".join(v.get("rule_id", "") for v in violations),
                    "violation_severities": ";".join(
                        v.get("severity", "") for v in violations
                    ),
                }
            )


def aggregate_stats(governance_dir: Path, vault_root: Optional[Path] = None) -> dict:
    """Aggregate evidence stats across all governed agents."""
    agents: List[str] = []
    total_evaluations_week = 0
    rule_counter: Counter[str] = Counter()
    approaching_review: List[dict] = []
    critical_agents: List[dict] = []
    retention_warnings: List[dict] = []

    week_ago = (datetime.utcnow() - timedelta(days=7)).isoformat()

    for passport_file in governance_dir.rglob("passport.yaml"):
        try:
            passport = AgentPassport.from_yaml(passport_file.read_text())
        except Exception:
            continue
        agent_name = passport.name or passport_file.parent.name
        agents.append(agent_name)

        vault = EvidenceVault(agent_id=agent_name, vault_dir=vault_root)
        last_reviewed = _last_reviewed_iso(passport)
        summary = vault.get_summary(last_reviewed_at=last_reviewed)

        week_events = vault.get_events(limit=10_000, since=week_ago[:10])
        total_evaluations_week += len(week_events)

        for rule_id, count in summary.violations_by_rule.items():
            rule_counter[rule_id] += count

        days = summary.days_until_annual_review
        if days is None or days <= ANNUAL_REVIEW_WARNING_DAYS:
            approaching_review.append(
                {
                    "agent": agent_name,
                    "days_until": days,
                    "status": "OVERDUE" if days is None or days < 0 else "DUE SOON",
                }
            )

        critical = summary.violations_by_severity.get("CRITICAL", 0)
        if critical:
            critical_agents.append({"agent": agent_name, "critical_violations": critical})

        warning = vault.get_retention_warning()
        if warning:
            retention_warnings.append(
                {
                    "agent": agent_name,
                    "days_remaining": summary.retention_days_remaining,
                    "message": warning,
                }
            )

    return {
        "total_agents": len(agents),
        "total_evaluations_this_week": total_evaluations_week,
        "top_violated_rules": [
            {"rule_id": rule_id, "count": count}
            for rule_id, count in rule_counter.most_common(3)
        ],
        "retention_warnings": retention_warnings,
        "agents_approaching_review": sorted(
            approaching_review,
            key=lambda x: x["days_until"] if x["days_until"] is not None else -999,
        ),
        "agents_with_critical_violations": critical_agents,
    }


def _parse_date_filter(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%d")


def _event_risk_score(event: dict) -> int:
    if event.get("risk_score") is not None:
        return int(event["risk_score"])
    score = 0
    for violation in event.get("violations", []):
        severity = str(violation.get("severity", "")).upper()
        if severity == "CRITICAL":
            score = max(score, 90)
        elif severity == "HIGH":
            score = max(score, 70)
        elif severity == "MEDIUM":
            score = max(score, 50)
        elif severity == "LOW":
            score = max(score, 25)
    return score


def _event_regulation(event: dict) -> str:
    if event.get("regulation"):
        return str(event["regulation"])
    refs: List[str] = []
    for violation in event.get("violations", []):
        refs.extend(violation.get("compliance_refs", []))
    return ", ".join(sorted(set(refs))) if refs else "—"


def _matches_regulation(event: dict, regulation: str) -> bool:
    needle = regulation.lower()
    if needle in str(event.get("regulation", "")).lower():
        return True
    for violation in event.get("violations", []):
        for ref in violation.get("compliance_refs", []):
            if needle in str(ref).lower():
                return True
    return False


def _discover_agent_names(gov_dir: Path) -> List[str]:
    names: List[str] = []
    for passport_file in gov_dir.rglob("passport.yaml"):
        try:
            passport = AgentPassport.from_yaml(passport_file.read_text())
            names.append(passport.name or passport_file.parent.name)
        except Exception:
            continue
    return sorted(set(names))


def _load_query_events(
    agent: Optional[str],
    governance_dir: Optional[Path],
    vault_dir: Optional[Path],
) -> List[dict]:
    events: List[dict] = []
    if agent:
        vault = _open_vault(agent, vault_dir)
        for event in vault.get_events(limit=10_000):
            tagged = dict(event)
            tagged["_agent"] = agent
            events.append(tagged)
        return events

    gov_dir = _governance_dir(governance_dir)
    for agent_name in _discover_agent_names(gov_dir):
        vault = _open_vault(agent_name, vault_dir)
        for event in vault.get_events(limit=10_000):
            tagged = dict(event)
            tagged["_agent"] = agent_name
            events.append(tagged)
    return events


def filter_query_events(
    events: List[dict],
    *,
    decision: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    regulation: Optional[str] = None,
    risk_min: Optional[int] = None,
    violations_only: bool = False,
    drift_only: bool = False,
) -> List[dict]:
    filtered = list(events)

    if decision:
        aliases = {"allow": "permit"}
        needle = aliases.get(decision.lower(), decision.lower())
        filtered = [
            e for e in filtered if str(e.get("decision", "")).lower() == needle
        ]

    if since:
        since_dt = _parse_date_filter(since)
        filtered = [
            e
            for e in filtered
            if e.get("timestamp")
            and datetime.fromisoformat(str(e["timestamp"])[:19]) >= since_dt
        ]

    if until:
        until_dt = _parse_date_filter(until).replace(hour=23, minute=59, second=59)
        filtered = [
            e
            for e in filtered
            if e.get("timestamp")
            and datetime.fromisoformat(str(e["timestamp"])[:19]) <= until_dt
        ]

    if regulation:
        filtered = [e for e in filtered if _matches_regulation(e, regulation)]

    if risk_min is not None:
        filtered = [e for e in filtered if _event_risk_score(e) >= risk_min]

    if violations_only:
        filtered = [e for e in filtered if len(e.get("violations", [])) > 0]

    if drift_only:
        filtered = [e for e in filtered if e.get("drift_flagged")]

    filtered.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    return filtered


def _decision_style(decision: str) -> str:
    normalized = decision.lower()
    styles = {
        "deny": "[bold red]deny[/bold red]",
        "hitl": "[yellow]hitl[/yellow]",
        "modify": "[blue]modify[/blue]",
        "defer": "[magenta]defer[/magenta]",
        "allow": "[dim green]allow[/dim green]",
        "permit": "[dim green]allow[/dim green]",
    }
    return styles.get(normalized, decision)


def _query_events_table(events: List[dict]) -> Table:
    table = Table(title="Evidence Vault Query")
    table.add_column("Time", style="dim", no_wrap=True)
    table.add_column("Agent")
    table.add_column("Action")
    table.add_column("Resource")
    table.add_column("Decision")
    table.add_column("Risk")
    table.add_column("Regulation")
    for event in events:
        decision = str(event.get("decision", ""))
        table.add_row(
            str(event.get("timestamp", ""))[:19],
            event.get("_agent", event.get("agent_id", "")),
            event.get("action", ""),
            event.get("resource", ""),
            _decision_style(decision),
            str(_event_risk_score(event)),
            _event_regulation(event),
        )
    return table


def _query_events_csv(events: List[dict]) -> str:
    output = io.StringIO()
    fieldnames = [
        "time",
        "agent",
        "action",
        "resource",
        "decision",
        "risk",
        "regulation",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for event in events:
        writer.writerow(
            {
                "time": str(event.get("timestamp", ""))[:19],
                "agent": event.get("_agent", event.get("agent_id", "")),
                "action": event.get("action", ""),
                "resource": event.get("resource", ""),
                "decision": str(event.get("decision", "")).lower(),
                "risk": _event_risk_score(event),
                "regulation": _event_regulation(event),
            }
        )
    return output.getvalue()


def _active_filter_hints(**filters) -> str:
    active = []
    for key, value in filters.items():
        if value:
            active.append(f"{key}={value}")
    return ", ".join(active) if active else "none"


@click.group()
def evidence():
    """Evidence Vault audit trail commands."""
    pass


@evidence.command("report")
@click.option("--agent", required=True, help="Agent name")
@click.option(
    "--format",
    "output_format",
    default="table",
    type=click.Choice(["markdown", "json", "table"]),
)
@click.option("--since", default=None, help="Start date (YYYY-MM-DD)")
@click.option("--dir", "governance_dir", type=Path, default=None)
@click.option("--vault-dir", type=Path, default=None, help="Override evidence vault root")
def evidence_report(agent, output_format, since, governance_dir, vault_dir):
    """
    Generate a complete audit report for an agent.

    Example:
      iris evidence report --agent payment-agent
      iris evidence report --agent payment-agent --format markdown
    """
    try:
        passport = _load_passport(agent, governance_dir)
        vault = _open_vault(agent, vault_dir)
        data = build_report_data(agent, passport, vault, since=since)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise SystemExit(1)

    if output_format == "json":
        click.echo(format_report_json(data))
    elif output_format == "markdown":
        click.echo(format_report_markdown(data))
    else:
        _print_report_table(data)


@evidence.command("list")
@click.option("--agent", required=True, help="Agent name")
@click.option("--violations-only", is_flag=True, help="Show only events with violations")
@click.option("--limit", default=50, show_default=True)
@click.option("--dir", "governance_dir", type=Path, default=None)
@click.option("--vault-dir", type=Path, default=None)
def evidence_list(agent, violations_only, limit, governance_dir, vault_dir):
    """
    List recent Evidence Vault events.

    Example:
      iris evidence list --agent payment-agent
      iris evidence list --agent payment-agent --violations-only
    """
    try:
        _load_passport(agent, governance_dir)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise SystemExit(1)

    vault = _open_vault(agent, vault_dir)
    events = vault.get_events(limit=limit)
    if violations_only:
        events = [e for e in events if e.get("violations")]

    if not events:
        console.print("[yellow]No events found in Evidence Vault.[/yellow]")
        raise SystemExit(0)

    console.print(_events_table(events))


@evidence.command("query")
@click.option("--agent", default=None, help="Filter by agent name")
@click.option(
    "--decision",
    default=None,
    type=click.Choice(["allow", "deny", "hitl", "modify", "defer"]),
    help="Filter by policy decision",
)
@click.option("--since", default=None, help="Start date YYYY-MM-DD")
@click.option("--until", default=None, help="End date YYYY-MM-DD")
@click.option(
    "--regulation",
    default=None,
    help="Filter by regulation e.g. AIUC-1, SOC2, colorado-ai-act",
)
@click.option("--risk-min", default=None, type=int, help="Minimum risk score (0-100)")
@click.option("--violations-only", is_flag=True, help="Only show events with violations")
@click.option(
    "--drift-only",
    is_flag=True,
    help="Only show events where intent drift was detected",
)
@click.option("--limit", default=25, show_default=True)
@click.option("--dir", "governance_dir", type=Path, default=None)
@click.option("--vault-dir", type=Path, default=None)
@click.option(
    "--format",
    "output_format",
    default="table",
    type=click.Choice(["table", "json", "csv"]),
)
def evidence_query(
    agent,
    decision,
    since,
    until,
    regulation,
    risk_min,
    violations_only,
    drift_only,
    limit,
    governance_dir,
    vault_dir,
    output_format,
):
    """
    Query Evidence Vault with filters. Gets to what matters.

    The signal command: instead of showing all events, filter
    to exactly the events that need attention.

    This is the CLI equivalent of Evidence Vault Signal mode.
    AARM R5 conformant — all entries are tamper-evident.

    Examples:
      iris evidence query --decision deny
      iris evidence query --agent billing-agent --decision deny
      iris evidence query --since 2025-06-01 --regulation AIUC-1
      iris evidence query --risk-min 70 --violations-only
      iris evidence query --decision deny --format json | jq '.[].action'
    """
    filter_kwargs = {
        "decision": decision,
        "since": since,
        "until": until,
        "regulation": regulation,
        "risk_min": risk_min,
        "violations_only": violations_only,
        "drift_only": drift_only,
    }

    events = _load_query_events(agent, governance_dir, vault_dir)
    matched = filter_query_events(events, **filter_kwargs)
    total = len(matched)
    shown = matched[:limit]

    if not shown:
        console.print("[yellow]No events match the given filters.[/yellow]")
        console.print(
            f"[dim]Active filters: {_active_filter_hints(**filter_kwargs)}[/dim]"
        )
        raise SystemExit(0)

    if output_format == "json":
        payload = []
        for event in shown:
            row = dict(event)
            row.pop("_agent", None)
            row["agent"] = event.get("_agent", event.get("agent_id", ""))
            row["risk_score"] = _event_risk_score(event)
            row["regulation"] = _event_regulation(event)
            payload.append(row)
        click.echo(json.dumps(payload, indent=2))
    elif output_format == "csv":
        click.echo(_query_events_csv(shown))
    else:
        console.print(_query_events_table(shown))
        console.print(f"\nShowing {len(shown)} of {total} matching events")
        if total > limit:
            console.print(f"[dim]Use --limit {total} to see all[/dim]")


@evidence.command("record-cicd")
@click.option(
    "--system",
    required=True,
    type=click.Choice(
        ["github_actions", "gitlab", "jenkins", "terraform", "argocd"]
    ),
)
@click.option("--run-id", required=True, help="Pipeline or build run identifier")
@click.option("--pipeline-url", default="", help="URL to the pipeline run")
@click.option("--triggered-by", default="automated", help="User or service that triggered the run")
@click.option("--outcome", default="success", help="Run outcome (success, failure, synced, apply, etc.)")
@click.option("--agent", default=None, help="Agent ID for vault scoping (defaults to IRIS_AGENT_ID or cwd agent)")
@click.option("--vault-dir", type=Path, default=None)
def evidence_record_cicd(system, run_id, pipeline_url, triggered_by, outcome, agent, vault_dir):
    """
    Record a CI/CD pipeline run as an immutable EvidenceEvent.

    Example:
      iris evidence record-cicd --system github_actions --run-id test-123 --outcome success
    """
    import os

    agent_id = agent or os.environ.get("IRIS_AGENT_ID") or "platform-governance"
    vault = EvidenceVaultV2(agent_id=agent_id, vault_dir=vault_dir)
    event = vault.record_cicd(
        system=system,
        run_id=run_id,
        pipeline_url=pipeline_url,
        triggered_by=triggered_by,
        outcome=outcome,
    )
    click.echo(
        json.dumps(
            {
                "event_id": event.event_id,
                "sequence_number": event.sequence_number,
                "signature": event.signature,
                "timestamp": event.timestamp,
            },
            indent=2,
        )
    )


@evidence.command("export")
@click.option("--agent", required=True, help="Agent name")
@click.option("--output", "output_path", required=True, type=Path)
@click.option(
    "--format",
    "output_format",
    default="json",
    type=click.Choice(["json", "csv", "aiuc1", "pdf", "oscal"]),
)
@click.option("--dir", "governance_dir", type=Path, default=None)
@click.option("--vault-dir", type=Path, default=None)
@click.option(
    "--framework",
    "-f",
    default="aiuc-1",
    help="Compliance framework for aiuc1/pdf export (default: aiuc-1)",
)
def evidence_export(agent, output_path, output_format, governance_dir, vault_dir, framework):
    """
    Export the full Evidence Vault for external audit tools.

    Example:
      iris evidence export --agent payment-agent --output audit.json
      iris evidence export --agent payment-agent --output audit.csv --format csv
      iris evidence export --agent payment-agent --output report.html --format pdf
    """
    try:
        passport = _load_passport(agent, governance_dir)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise SystemExit(1)

    gov_root = _governance_dir(governance_dir).parent

    if output_format == "aiuc1":
        Entitlements().require(
            Feature.CERTIFICATION_READINESS_PDF,
            context="evidence export --format aiuc1",
        )
        exporter = AIUC1EvidenceExporter(passport, gov_root)
        payload = exporter.export_full_package(agent)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(payload, indent=2))
        console.print(f"[green]✓ Exported AIUC-1 evidence package to {output_path}[/green]")
        return

    if output_format == "pdf":
        Entitlements().require(
            Feature.CERTIFICATION_READINESS_PDF,
            context="evidence export --format pdf",
        )
        html_path = output_path
        if html_path.suffix.lower() == ".pdf":
            html_path = html_path.with_suffix(".html")
        html_content = build_evidence_html(
            agent,
            passport,
            framework=framework,
            governance_dir=gov_root,
            vault_dir=vault_dir,
        )
        html_path.parent.mkdir(parents=True, exist_ok=True)
        html_path.write_text(html_content, encoding="utf-8")
        console.print(
            "[green]✓ HTML report generated. Open in browser and print to PDF.[/green]"
        )
        console.print(
            f"[dim]iris evidence export --agent {agent} "
            f"--output {html_path.name} --format pdf[/dim]"
        )
        console.print(f"[green]  → {html_path}[/green]")
        return

    if output_format == "oscal":
        vault = _open_vault(agent, vault_dir)
        vault_data = vault.export_vault()
        oscal_payload = {
            "oscal-version": "1.1.2",
            "uuid": passport.agent_id or agent,
            "metadata": {
                "title": f"IRIS Evidence Export — {agent}",
                "published": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            "iris_evidence": vault_data,
        }
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(oscal_payload, indent=2))
        console.print(f"[green]✓ Exported OSCAL evidence to {output_path}[/green]")
        return

    vault = _open_vault(agent, vault_dir)
    vault_data = vault.export_vault()
    vault_data["passport"] = {
        "owner": passport.owner,
        "team": passport.team,
        "evidence_vault_id": passport.evidence_vault_id,
        "last_reviewed_at": _last_reviewed_iso(passport),
    }
    vault_data["integrity"] = vault.check_integrity(passport.evidence_vault_id)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_format == "json":
        output_path.write_text(json.dumps(vault_data, indent=2))
    else:
        _export_csv(vault_data, output_path)

    console.print(f"[green]✓ Exported to {output_path}[/green]")


@evidence.command("stats")
@click.option("--dir", "governance_dir", type=Path, default=None)
@click.option("--vault-dir", type=Path, default=None)
@click.option(
    "--format",
    "output_format",
    default="table",
    type=click.Choice(["table", "json"]),
)
def evidence_stats(governance_dir, vault_dir, output_format):
    """
    Show aggregate Evidence Vault stats across all governed agents.

    Example:
      iris evidence stats
    """
    gov_dir = _governance_dir(governance_dir)
    if not gov_dir.exists():
        console.print(f"[yellow]Governance directory not found: {gov_dir}[/yellow]")
        raise SystemExit(0)

    stats = aggregate_stats(gov_dir, vault_root=vault_dir)

    if output_format == "json":
        click.echo(json.dumps(stats, indent=2))
        return

    console.print(Panel("[bold]Evidence Vault — Aggregate Stats[/bold]", style="blue"))
    console.print(f"\nTotal agents governed:          {stats['total_agents']}")
    console.print(f"Total evaluations this week:    {stats['total_evaluations_this_week']}")

    console.print("\n[bold]Top violated rules[/bold]")
    if stats["top_violated_rules"]:
        for item in stats["top_violated_rules"][:3]:
            console.print(f"  {item['rule_id']:<16} {item['count']} times")
    else:
        console.print("  [dim]None[/dim]")

    console.print("\n[bold]Retention warnings[/bold]")
    if stats.get("retention_warnings"):
        for item in stats["retention_warnings"]:
            console.print(
                f"  {item['agent']:<24} {item['days_remaining']} days remaining"
            )
    else:
        console.print("  [dim]None[/dim]")

    console.print("\n[bold]Agents approaching annual review[/bold]")
    if stats["agents_approaching_review"]:
        for item in stats["agents_approaching_review"]:
            days = item["days_until"]
            days_label = "OVERDUE" if days is None else f"{days} days"
            console.print(f"  {item['agent']:<24} {item['status']:<10} {days_label}")
    else:
        console.print("  [dim]None[/dim]")

    console.print("\n[bold]Agents with open critical violations[/bold]")
    if stats["agents_with_critical_violations"]:
        for item in stats["agents_with_critical_violations"]:
            console.print(
                f"  {item['agent']:<24} {item['critical_violations']} critical"
            )
    else:
        console.print("  [dim]None[/dim]")
