"""iris witness — live attested feed of every policy decision."""

from __future__ import annotations

import json
import signal
import sys
import time
from datetime import datetime
from pathlib import Path

import click
from rich.console import Console

console = Console()


def _format_witness_event(event: dict, agent: str) -> str:
    ts = event.get("timestamp", "")
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        time_str = dt.strftime("%H:%M:%S.%f")[:12]
    except ValueError:
        time_str = ts[:12] if len(ts) >= 12 else "??:??:??.???"

    decision = event.get("decision", "PERMIT")
    resource = event.get("resource") or event.get("tool", "?")
    action = event.get("action", "call")
    env = event.get("environment", "dev")
    violations = event.get("violations") or []

    if violations and decision == "PERMIT":
        decision = "WARN"

    icon = {"PERMIT": "●", "DENY": "●", "WARN": "◐", "PERMIT_WITH_WARNINGS": "◐"}.get(
        decision, "●"
    )
    color_decision = "WARN" if decision in ("WARN", "PERMIT_WITH_WARNINGS") else decision

    user = event.get("user_email") or event.get("acting_for_user") or ""
    cost = event.get("cost_usd")
    cost_str = f" · Cost: ${cost:.3f}" if cost is not None else ""

    rule_line = ""
    if violations:
        v = violations[0]
        rule_line = f"\n                   Rule: {v.get('rule_id', '')} — {v.get('message', '')[:60]}"
    elif decision == "PERMIT":
        rule_line = "\n                   Rule: permit — all conditions satisfied"

    user_line = f"\n                   User: {user}{cost_str}" if user or cost_str else ""

    header = f"{time_str}  {icon} {color_decision:<6}  {resource} › {action:<12}  [{env}]"
    return header + rule_line + user_line


def _color_line(line: str) -> str:
    if " DENY" in line:
        return f"[red]{line}[/red]"
    if " WARN" in line or "◐" in line:
        return f"[yellow]{line}[/yellow]"
    return f"[green]{line}[/green]"


@click.command("witness")
@click.option("--agent", required=True, help="Agent name to witness")
@click.option("--tail", default=0, show_default=True, help="Show last N events before watching")
@click.option("--vault-dir", type=click.Path(path_type=Path), default=None)
def witness_cmd(agent: str, tail: int, vault_dir: Path | None) -> None:
    """
    Live attested feed of every policy decision.

    Alias: iris watch
    """
    vault_root = vault_dir or Path.home() / ".iris" / "evidence"
    events_file = vault_root / agent / "events.jsonl"

    if not events_file.exists():
        events_file.parent.mkdir(parents=True, exist_ok=True)
        events_file.touch()

    console.print(f"[bold]IRIS Witness Feed[/bold] — {agent}")
    console.print("Every policy decision attested and logged.\n")
    console.print("Press Ctrl+C to stop.\n")

    lines_read = 0
    if tail > 0 and events_file.stat().st_size > 0:
        all_lines = events_file.read_text(encoding="utf-8").strip().splitlines()
        for raw in all_lines[-tail:]:
            try:
                event = json.loads(raw)
                console.print(_color_line(_format_witness_event(event, agent)))
            except json.JSONDecodeError:
                pass
        lines_read = len(all_lines)

    running = True

    def _stop(*_args):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, _stop)

    while running:
        try:
            if not events_file.exists():
                time.sleep(0.5)
                continue
            all_lines = events_file.read_text(encoding="utf-8").strip().splitlines()
            for raw in all_lines[lines_read:]:
                try:
                    event = json.loads(raw)
                    console.print(_color_line(_format_witness_event(event, agent)))
                except json.JSONDecodeError:
                    pass
            lines_read = len(all_lines)
        except OSError:
            pass
        time.sleep(0.5)

    console.print("\n[dim]Witness feed stopped.[/dim]")
    sys.exit(0)
