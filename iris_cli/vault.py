"""iris vault — Evidence Vault GDPR erasure commands."""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import click
from rich.console import Console

from iris_core.dlp.patterns import all_patterns
from iris_core.entitlements import Entitlements, Feature
from iris_core.evidence.vault import EvidenceVault

console = Console()

GDPR_ERASURE_LOG = Path.home() / ".iris" / "gdpr-erasure-log.jsonl"

_PII_REGEXES = [pattern.regex for pattern in all_patterns()]


def _governance_dir(governance_dir: Optional[Path]) -> Path:
    return governance_dir or Path.cwd() / "governance" / "agents"


def _redaction_marker(user_id: str, date_str: str) -> str:
    return f"[GDPR-ERASURE-{user_id}-{date_str}]"


def _entry_matches_user(entry: dict, user_id: str) -> bool:
    return user_id in json.dumps(entry)


def _redact_value(value: Any, marker: str, user_id: str) -> Tuple[Any, bool]:
    if isinstance(value, str):
        if user_id in value:
            return marker, True
        for regex in _PII_REGEXES:
            if regex.search(value):
                return marker, True
        return value, False
    if isinstance(value, dict):
        changed = False
        redacted: Dict[str, Any] = {}
        for key, nested in value.items():
            new_value, nested_changed = _redact_value(nested, marker, user_id)
            redacted[key] = new_value
            changed = changed or nested_changed
        return redacted, changed
    if isinstance(value, list):
        changed = False
        redacted_list: List[Any] = []
        for item in value:
            new_value, nested_changed = _redact_value(item, marker, user_id)
            redacted_list.append(new_value)
            changed = changed or nested_changed
        return redacted_list, changed
    return value, False


def _load_events(vault: EvidenceVault) -> List[dict]:
    return vault._read_jsonl("events.jsonl")


def _write_events(vault: EvidenceVault, events: List[dict]) -> None:
    with open(vault._log_file, "w") as handle:
        for event in events:
            handle.write(json.dumps(event) + "\n")


def _plan_redactions(
    events: List[dict],
    user_id: str,
    marker: str,
) -> List[dict]:
    planned: List[dict] = []
    for event in events:
        if not _entry_matches_user(event, user_id):
            continue
        redacted_event, changed = _redact_value(event, marker, user_id)
        if changed:
            planned.append(
                {
                    "event_id": event.get("event_id"),
                    "timestamp": event.get("timestamp"),
                    "before": event,
                    "after": redacted_event,
                }
            )
    return planned


def _append_erasure_log(entry: dict) -> None:
    GDPR_ERASURE_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(GDPR_ERASURE_LOG, "a") as handle:
        handle.write(json.dumps(entry) + "\n")


def _print_erasure_summary(
    agent_name: str,
    user_id: str,
    entries_redacted: int,
    redacted_at: str,
    marker: str,
) -> None:
    console.print(
        f"""┌─ GDPR Erasure Complete ────────────────────────────────────┐
│ Agent:           {agent_name:<41}│
│ User ID:         {user_id:<41}│
│ Entries redacted: {entries_redacted:<40}│
│ Redacted at:     {redacted_at:<41}│
│ Legal basis:     GDPR Article 17 — Right to Erasure       │
│                                                             │
│ PII values replaced with:                                  │
│   {marker:<55}│
│                                                             │
│ Audit structure preserved. Erasure logged to:              │
│   ~/.iris/gdpr-erasure-log.jsonl                           │
└─────────────────────────────────────────────────────────────┘"""
    )


@click.group()
def vault():
    """Evidence Vault GDPR and retention commands."""
    pass


@vault.command("redact")
@click.option("--agent", required=True, help="Agent name")
@click.option("--user-id", required=True, help="User whose data to redact")
@click.option("--confirm", is_flag=True, help="Confirm redaction (required to execute)")
@click.option("--dry-run", is_flag=True, help="Show what would be redacted without modifying")
@click.option("--dir", "governance_dir", type=Path, default=None)
@click.option("--vault-dir", type=Path, default=None)
def vault_redact(agent, user_id, confirm, dry_run, governance_dir, vault_dir):
    """
    Redact PII for a specific user from the Evidence Vault (GDPR Article 17).

    Example:
      iris vault redact --agent apex-loan-processor --user-id user-12345 --dry-run
      iris vault redact --agent apex-loan-processor --user-id user-12345 --confirm
    """
    if not dry_run:
        if not Entitlements().has(Feature.VAULT_GDPR_REDACTION):
            console.print(
                "GDPR right to erasure requires Pro Evidence Vault with extended retention.\n"
                "Upgrade: iris license activate <your-key>"
            )
            raise SystemExit(1)

        if not confirm:
            console.print(
                "[red]Refusing to redact without --confirm.[/red]\n"
                "Use --dry-run to preview changes first."
            )
            raise SystemExit(1)

    passport_file = _governance_dir(governance_dir) / agent / "passport.yaml"
    if not passport_file.exists():
        console.print(
            f"[red]Passport not found for agent '{agent}'.[/red]\n"
            f"Expected: {passport_file}"
        )
        raise SystemExit(1)

    vault = EvidenceVault(agent_id=agent, vault_dir=vault_dir)
    events = _load_events(vault)
    date_str = datetime.utcnow().strftime("%Y-%m-%d")
    marker = _redaction_marker(user_id, date_str)
    planned = _plan_redactions(events, user_id, marker)

    if dry_run:
        if not planned:
            console.print(
                f"[yellow]No matching Evidence Vault entries for user '{user_id}'.[/yellow]"
            )
            raise SystemExit(0)
        console.print(
            f"[bold]Dry run — {len(planned)} entries would be redacted[/bold]\n"
        )
        for item in planned:
            console.print(
                f"  event_id={item['event_id']} "
                f"timestamp={item['timestamp']}"
            )
        raise SystemExit(0)

    if not planned:
        console.print(
            f"[yellow]No matching Evidence Vault entries for user '{user_id}'.[/yellow]"
        )
        raise SystemExit(0)

    redacted_ids = {item["event_id"] for item in planned}
    updated_events: List[dict] = []
    for event in events:
        if event.get("event_id") in redacted_ids:
            updated_events.append(next(i["after"] for i in planned if i["event_id"] == event.get("event_id")))
        else:
            updated_events.append(event)

    _write_events(vault, updated_events)

    redacted_at = datetime.utcnow().isoformat()
    erasure_entry = {
        "erasure_id": str(uuid.uuid4()),
        "agent_name": agent,
        "user_id": user_id,
        "entries_redacted": len(planned),
        "redacted_at": redacted_at,
        "requested_by": "iris-cli",
        "legal_basis": "GDPR Article 17 — Right to Erasure",
    }
    _append_erasure_log(erasure_entry)
    _print_erasure_summary(agent, user_id, len(planned), redacted_at, marker)
