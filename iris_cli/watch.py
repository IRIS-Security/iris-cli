"""iris watch — live feed of IRIS policy decisions."""

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


def _format_event(event: dict) -> str:
    ts = event.get("timestamp", "")
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        time_str = dt.strftime("%H:%M:%S")
    except ValueError:
        time_str = ts[:8] if len(ts) >= 8 else "??:??:??"

    decision = event.get("decision", "PERMIT")
    action = event.get("action", "?")
    resource = event.get("resource", "?")
    env = event.get("environment", "dev")
    violations = event.get("violations") or []

    if violations and decision == "PERMIT":
        decision = "WARN"

    detail = ""
    if violations:
        detail = f" {violations[0].get('rule_id', '')}: {violations[0].get('message', '')[:40]}"

    return f"{time_str}  {decision:<8}  {action} → {resource:<22}  [{env}]{detail}"


def _color_line(line: str) -> str:
    if "  DENY" in line or line.startswith("DENY"):
        return f"[red]{line}[/red]"
    if "  WARN" in line:
        return f"[yellow]{line}[/yellow]"
    return f"[green]{line}[/green]"


@click.command("watch")
@click.option("--agent", required=True, help="Agent name to watch")
@click.option("--tail", default=0, show_default=True, help="Show last N events before watching")
@click.option("--vault-dir", type=click.Path(path_type=Path), default=None)
def watch_cmd(agent: str, tail: int, vault_dir: Path | None) -> None:
    """Live feed of IRIS policy decisions (tail -f for your agent)."""
    vault_root = vault_dir or Path.home() / ".iris" / "evidence"
    events_file = vault_root / agent / "events.jsonl"

    if not events_file.exists():
        events_file.parent.mkdir(parents=True, exist_ok=True)
        events_file.touch()

    console.print(f"Watching decisions for: [cyan]{agent}[/cyan]")
    console.print("Press Ctrl+C to stop.\n")

    lines_read = 0
    if tail > 0 and events_file.stat().st_size > 0:
        all_lines = events_file.read_text(encoding="utf-8").strip().splitlines()
        for raw in all_lines[-tail:]:
            try:
                event = json.loads(raw)
                console.print(_color_line(_format_event(event)))
            except json.JSONDecodeError:
                pass
        lines_read = len(all_lines)

    running = True

    def _stop(*_args):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    while running:
        try:
            if events_file.exists():
                all_lines = events_file.read_text(encoding="utf-8").strip().splitlines()
                for raw in all_lines[lines_read:]:
                    try:
                        event = json.loads(raw)
                        console.print(_color_line(_format_event(event)))
                    except json.JSONDecodeError:
                        pass
                lines_read = len(all_lines)
        except OSError:
            pass
        time.sleep(0.5)

    console.print("\n[dim]Stopped watching.[/dim]")
    sys.exit(0)
