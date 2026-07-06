# Copyright 2024-2025 Gilbert Martin / IRIS Security, Inc.
# All Rights Reserved.
# Author: Gilbert Martin <gilbert@iris-security.io>
# IRIS CLI — Policy as Code for AI Agents — https://iris-security.io

"""
iris audit-log — SIEM-ready audit log export.
Track A3 capability. CLI-only, fully offline.
Answers the CISO question: "plug this into what I already have."
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import signal
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable, List, Optional

import click
from rich.console import Console

from iris_cli.evidence import (
    _event_regulation,
    _event_risk_score,
    _load_query_events,
    _open_vault,
    filter_query_events,
)
from iris_core.evidence.vault import EvidenceVault

err_console = Console(file=sys.stderr)

IRIS_VERSION = "0.2.12"
DEFAULT_RETENTION_DAYS = EvidenceVault.FREE_RETENTION_DAYS


def _agent_name(event: dict) -> str:
    return event.get("_agent") or event.get("agent_name") or event.get("agent_id") or "unknown"


def _event_policy(event: dict) -> str:
    if event.get("policy_name"):
        return str(event["policy_name"])
    violations = event.get("violations") or []
    if violations:
        return str(violations[0].get("rule_id", ""))
    if event.get("triggered_by"):
        return str(event["triggered_by"])
    return "—"


def _event_r5_satisfied(event: dict) -> bool:
    """R5 tamper-evidence applies only to HMAC-signed vault events (Evidence Vault v2)."""
    return bool(event.get("signature"))


def _event_hash(event: dict) -> str:
    if event.get("hash"):
        return str(event["hash"])
    if event.get("signature"):
        return str(event["signature"])
    raw = f"{event.get('event_id', '')}:{_agent_name(event)}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _normalize_decision(event: dict) -> str:
    decision = str(event.get("decision", "PERMIT")).upper()
    if event.get("event_type") == "hitl_requested":
        return "HITL"
    return decision


def _aiuc1_control(event: dict) -> str:
    regulation = _event_regulation(event)
    return regulation if regulation != "—" else ""


def _filter_decisions(events: List[dict], decisions: str) -> List[dict]:
    if decisions == "all":
        return events
    if decisions == "deny":
        return [e for e in events if _normalize_decision(e) == "DENY"]
    if decisions == "hitl":
        return [
            e
            for e in events
            if _normalize_decision(e) == "HITL"
            or e.get("event_type") in ("hitl_requested", "hitl_resolved")
        ]
    if decisions == "violations":
        return [e for e in events if len(e.get("violations", [])) > 0]
    return events


def _load_audit_events(
    agent: Optional[str],
    governance_dir: Optional[Path],
    vault_dir: Optional[Path],
) -> List[dict]:
    vault_root = vault_dir or Path.home() / ".iris" / "evidence"
    if agent:
        return _load_query_events(agent, governance_dir, vault_dir)

    if vault_root.exists():
        events: List[dict] = []
        for agent_dir in sorted(vault_root.iterdir()):
            if not agent_dir.is_dir():
                continue
            events_file = agent_dir / "events.jsonl"
            if not events_file.exists():
                continue
            vault = _open_vault(agent_dir.name, vault_dir)
            for event in vault.get_events(limit=10_000):
                tagged = dict(event)
                tagged["_agent"] = agent_dir.name
                events.append(tagged)
        if events:
            return events

    return _load_query_events(None, governance_dir, vault_dir)


def _parse_timestamp(event: dict) -> datetime:
    ts = str(event.get("timestamp", ""))
    if not ts:
        return datetime.utcnow()
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00").replace("+00:00", ""))
    except ValueError:
        return datetime.fromisoformat(ts[:19])


def _format_splunk(event: dict) -> dict:
    ts = _parse_timestamp(event)
    agent = _agent_name(event)
    decision = _normalize_decision(event)
    return {
        "time": ts.timestamp(),
        "host": "iris-governance",
        "source": f"iris:agent:{agent}",
        "sourcetype": "iris:evidence",
        "index": "security",
        "event": {
            "iris_agent": agent,
            "iris_action": event.get("action", ""),
            "iris_decision": decision,
            "iris_policy": _event_policy(event),
            "iris_risk_score": _event_risk_score(event),
            "iris_regulation": _event_regulation(event),
            "iris_event_id": event.get("event_id", ""),
            "iris_hash": _event_hash(event),
            "aarm_r5": _event_r5_satisfied(event),
            "aiuc1_control": _aiuc1_control(event),
        },
    }


def _format_datadog(event: dict) -> dict:
    ts = _parse_timestamp(event)
    agent = _agent_name(event)
    decision = _normalize_decision(event)
    resource = event.get("resource") or event.get("tool") or "unknown"
    action = event.get("action", "call")
    return {
        "ddsource": "iris",
        "ddtags": f"env:prod,iris_decision:{decision.lower()}",
        "hostname": "iris-governance",
        "message": f"{agent} {decision}: {action} on {resource}",
        "service": "iris-agent-governance",
        "date": int(ts.timestamp() * 1000),
        "iris.agent": agent,
        "iris.decision": decision,
        "iris.risk_score": _event_risk_score(event),
        "iris.policy": _event_policy(event),
    }


def _format_elastic(event: dict) -> dict:
    ts = _parse_timestamp(event)
    agent = _agent_name(event)
    decision = _normalize_decision(event)
    outcome = "success" if decision in ("PERMIT", "ALLOW") else "failure"
    return {
        "@timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "event.kind": "event",
        "event.category": ["authentication", "network"],
        "event.type": ["access"],
        "event.action": decision.lower(),
        "event.outcome": outcome,
        "agent.name": agent,
        "agent.type": "iris-governance",
        "rule.name": _event_policy(event),
        "rule.description": event.get("action", ""),
        "risk.score": _event_risk_score(event),
        "labels": {
            "iris_regulation": _event_regulation(event),
            "aarm_r5": "true" if _event_r5_satisfied(event) else "false",
        },
    }


def _otel_attribute(key: str, value: str | int) -> dict:
    if isinstance(value, int):
        return {"key": key, "value": {"intValue": value}}
    return {"key": key, "value": {"stringValue": str(value)}}


def _format_otel_envelope(events: List[dict]) -> dict:
    spans = []
    for event in events:
        decision = _normalize_decision(event)
        event_id = str(event.get("event_id", ""))
        agent = _agent_name(event)
        trace_id = hashlib.sha256(f"{event_id}{agent}".encode()).hexdigest()[:32]
        span_id = event_id.replace("ev_", "").ljust(16, "0")[:16]
        start_ms = int(_parse_timestamp(event).timestamp() * 1000)
        spans.append(
            {
                "traceId": trace_id,
                "spanId": span_id,
                "parentSpanId": event.get("session_id"),
                "name": f"iris.agent.action.{decision.lower()}",
                "kind": 3,
                "startTimeUnixNano": start_ms * 1_000_000,
                "endTimeUnixNano": (start_ms + 2) * 1_000_000,
                "attributes": [
                    _otel_attribute("iris.agent.id", agent),
                    _otel_attribute("iris.action", event.get("action", "")),
                    _otel_attribute("iris.decision", decision),
                    _otel_attribute("iris.policy.name", _event_policy(event)),
                    _otel_attribute("iris.risk_score", _event_risk_score(event)),
                    _otel_attribute("iris.regulation", _event_regulation(event)),
                    _otel_attribute("iris.evidence.hash", _event_hash(event)),
                    _otel_attribute("aarm.requirement", "R5"),
                    _otel_attribute("aiuc1.control", _aiuc1_control(event)),
                ],
                "status": {"code": 2 if decision == "DENY" else 1},
            }
        )

    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        _otel_attribute("service.name", "iris-cli"),
                        _otel_attribute("service.version", IRIS_VERSION),
                        _otel_attribute("iris.vendor", "IRIS Security, Inc."),
                        _otel_attribute("aarm.alignment", "designed-toward"),
                    ],
                },
                "scopeSpans": [
                    {
                        "scope": {"name": "iris.evidence", "version": "1.0"},
                        "spans": spans,
                    }
                ],
            }
        ],
    }


def _cef_severity(risk: int) -> int:
    if risk >= 90:
        return 10
    if risk >= 80:
        return 8
    if risk >= 60:
        return 6
    if risk >= 40:
        return 4
    return 2


def _format_cef(event: dict) -> str:
    agent = _agent_name(event)
    decision = _normalize_decision(event)
    resource = event.get("resource") or event.get("tool") or "unknown"
    policy = _event_policy(event)
    risk = _event_risk_score(event)
    rule_id = policy.replace("|", "\\|")
    action = str(event.get("action", "")).replace("|", "\\|")
    regulation = _event_regulation(event).replace("=", "\\=")
    return (
        f"CEF:0|IRIS Security|iris-governance|{IRIS_VERSION}|{rule_id}|"
        f"{action}|{_cef_severity(risk)}|"
        f"src={agent} dst={resource} act={decision} "
        f"cs1={policy} cs1Label=PolicyName "
        f"cn1={risk} cn1Label=RiskScore "
        f"flexString1={regulation} flexString1Label=Regulation"
    )


def _format_leef(event: dict) -> str:
    agent = _agent_name(event)
    decision = _normalize_decision(event)
    resource = event.get("resource") or event.get("tool") or "unknown"
    policy = _event_policy(event)
    risk = _event_risk_score(event)
    event_id = str(event.get("event_id", "unknown"))
    ts = _parse_timestamp(event).strftime("%Y-%m-%dT%H:%M:%SZ")
    regulation = _event_regulation(event)
    return (
        f"LEEF:2.0|IRIS Security|iris-governance|{IRIS_VERSION}|{event_id}|"
        f"devTime={ts} devTimeFormat=ISO 8601 "
        f"src={agent} dst={resource} usrName={agent} "
        f"proto=HTTPS sev={risk} cat={decision} "
        f"policy={policy} regulation={regulation}"
    )


def _format_json_events(events: List[dict]) -> str:
    payload = []
    for event in events:
        row = dict(event)
        row.pop("_agent", None)
        row["agent"] = _agent_name(event)
        row["risk_score"] = _event_risk_score(event)
        row["regulation"] = _event_regulation(event)
        payload.append(row)
    return json.dumps(payload, indent=2)


def _format_csv_events(events: List[dict]) -> str:
    fieldnames = [
        "event_id",
        "timestamp",
        "agent",
        "action",
        "resource",
        "environment",
        "decision",
        "risk_score",
        "policy",
        "regulation",
        "hash",
    ]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for event in events:
        writer.writerow(
            {
                "event_id": event.get("event_id", ""),
                "timestamp": event.get("timestamp", ""),
                "agent": _agent_name(event),
                "action": event.get("action", ""),
                "resource": event.get("resource") or event.get("tool", ""),
                "environment": event.get("environment", ""),
                "decision": _normalize_decision(event),
                "risk_score": _event_risk_score(event),
                "policy": _event_policy(event),
                "regulation": _event_regulation(event),
                "hash": _event_hash(event),
            }
        )
    return buf.getvalue()


def _serialize_events(events: List[dict], output_format: str) -> str:
    if output_format == "json":
        return _format_json_events(events)
    if output_format == "csv":
        return _format_csv_events(events)
    if output_format == "otel":
        return json.dumps(_format_otel_envelope(events), indent=2)

    lines: List[str] = []
    for event in events:
        if output_format == "splunk":
            lines.append(json.dumps(_format_splunk(event)))
        elif output_format == "datadog":
            lines.append(json.dumps(_format_datadog(event)))
        elif output_format == "elastic":
            lines.append(json.dumps(_format_elastic(event)))
        elif output_format == "cef":
            lines.append(_format_cef(event))
        elif output_format == "leef":
            lines.append(_format_leef(event))
    return "\n".join(lines) + ("\n" if lines else "")


def _format_label(output_format: str) -> str:
    labels = {
        "splunk": "Splunk HEC",
        "datadog": "Datadog",
        "elastic": "Elastic ECS",
        "otel": "OTel OTLP",
        "cef": "CEF",
        "leef": "LEEF",
        "json": "JSON",
        "csv": "CSV",
    }
    return labels.get(output_format, output_format)


def _print_export_summary(
    count: int,
    output_format: str,
    since: str,
    until: str,
) -> None:
    err_console.print(
        f"Exported {count} events · {_format_label(output_format)} format · "
        f"{since}–{until}"
    )
    err_console.print(
        "Formats: Splunk HEC · Datadog · Elastic ECS · OTel OTLP"
    )
    err_console.print(
        "OTel export · https://iris-security.io"
    )


def _resolve_date_range(
    since: Optional[str],
    until: Optional[str],
) -> tuple[str, str]:
    resolved_since = since or (
        datetime.utcnow() - timedelta(days=DEFAULT_RETENTION_DAYS)
    ).strftime("%Y-%m-%d")
    resolved_until = until or datetime.utcnow().strftime("%Y-%m-%d")
    return resolved_since, resolved_until


def _collect_events(
    agent: Optional[str],
    since: str,
    until: str,
    decisions: str,
    governance_dir: Optional[Path],
    vault_dir: Optional[Path],
) -> List[dict]:
    events = _load_audit_events(agent, governance_dir, vault_dir)
    events = filter_query_events(events, since=since, until=until)
    events = _filter_decisions(events, decisions)
    events.sort(key=lambda e: e.get("timestamp", ""))
    return events


def _format_single_event(event: dict, output_format: str) -> str:
    if output_format == "json":
        return json.dumps(
            {
                **{k: v for k, v in event.items() if k != "_agent"},
                "agent": _agent_name(event),
                "risk_score": _event_risk_score(event),
                "regulation": _event_regulation(event),
            }
        )
    if output_format == "splunk":
        return json.dumps(_format_splunk(event))
    if output_format == "elastic":
        return json.dumps(_format_elastic(event))
    if output_format == "cef":
        return _format_cef(event)
    return json.dumps(event)


def _vault_agent_dirs(vault_dir: Optional[Path], agent: Optional[str]) -> Iterable[Path]:
    vault_root = vault_dir or Path.home() / ".iris" / "evidence"
    if agent:
        yield vault_root / agent
        return
    if not vault_root.exists():
        return
    for path in sorted(vault_root.iterdir()):
        if path.is_dir() and (path / "events.jsonl").exists():
            yield path


@click.group("audit-log")
def audit_log():
    """Audit log export in SIEM-compatible formats."""
    pass


@audit_log.command("export")
@click.option("--agent", default=None, help="Agent name. Omit to export all agents.")
@click.option(
    "--since",
    default=None,
    help=f"Start date YYYY-MM-DD. Default: last {DEFAULT_RETENTION_DAYS} days.",
)
@click.option("--until", default=None, help="End date YYYY-MM-DD.")
@click.option(
    "--format",
    "output_format",
    required=True,
    type=click.Choice(
        ["splunk", "datadog", "elastic", "otel", "cef", "leef", "json", "csv"]
    ),
    help="Output format for SIEM ingestion.",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Write to file. Omit to print to stdout.",
)
@click.option("--dir", "governance_dir", type=Path, default=None)
@click.option("--vault-dir", type=Path, default=None)
@click.option(
    "--decisions",
    default="all",
    type=click.Choice(["all", "deny", "hitl", "violations"]),
    help="Filter which events to export.",
)
def audit_log_export(
    agent,
    since,
    until,
    output_format,
    output_path,
    governance_dir,
    vault_dir,
    decisions,
):
    """
    Export audit log in SIEM-compatible format.

    Plug IRIS evidence directly into your existing security stack.
    No IRIS account required — reads from local Evidence Vault.

    Exports governance telemetry in standard SIEM formats (including OTel OTLP).

    Examples:
      iris audit-log export --format splunk --output events.json
      iris audit-log export --format elastic --agent billing-agent
      iris audit-log export --format cef | nc splunk-hec 9997
      iris audit-log export --format csv --since 2025-06-01 > audit.csv
      iris audit-log export --format otel --decisions deny
    """
    since, until = _resolve_date_range(since, until)
    events = _collect_events(agent, since, until, decisions, governance_dir, vault_dir)
    body = _serialize_events(events, output_format)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(body, encoding="utf-8")
    else:
        click.echo(body, nl=False)

    _print_export_summary(len(events), output_format, since, until)


@audit_log.command("stream")
@click.option(
    "--format",
    "output_format",
    default="json",
    type=click.Choice(["json", "splunk", "elastic", "cef"]),
)
@click.option("--agent", default=None)
@click.option(
    "--decisions",
    default="deny",
    type=click.Choice(["all", "deny", "hitl", "violations"]),
)
@click.option("--vault-dir", type=Path, default=None)
def audit_log_stream(output_format, agent, decisions, vault_dir):
    """
    Stream live audit events to stdout (tail -f style).

    Pipe directly into Splunk/Datadog/Elastic forwarders.

    Example:
      iris audit-log stream --format splunk | splunk-forwarder
      iris audit-log stream --decisions deny --format elastic
    """
    err_console.print(
        "[dim]Streaming IRIS audit events... Ctrl+C to stop[/dim]"
    )

    seen: set[str] = set()
    running = True

    def _stop(*_args):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, _stop)

    poll_interval = 2.0
    while running:
        for agent_dir in _vault_agent_dirs(vault_dir, agent):
            events_file = agent_dir / "events.jsonl"
            if not events_file.exists():
                continue
            try:
                lines = events_file.read_text(encoding="utf-8").strip().splitlines()
            except OSError:
                continue
            for raw in lines:
                try:
                    event = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                event_id = event.get("event_id") or raw
                if event_id in seen:
                    continue
                tagged = dict(event)
                tagged["_agent"] = agent_dir.name
                if decisions != "all":
                    filtered = _filter_decisions([tagged], decisions)
                    if not filtered:
                        continue
                seen.add(event_id)
                click.echo(_format_single_event(tagged, output_format))
        time.sleep(poll_interval)

    err_console.print("[dim]Audit log stream stopped.[/dim]")
