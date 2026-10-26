"""iris devspend — developer tool spend tracking (Claude Code adapter, Phase 1).

Fully separate command group from `iris cost`: `iris cost` tracks spend
from agents IRIS governs through its instrumented SDK adapters
(production runtime cost). `iris devspend` tracks what it costs the
developer to use an AI coding assistant to build the project — a
different data source (local session transcripts, not governed API
calls), a different package (iris_core.devspend, not iris_core.cost),
and a different storage root (project-local `.iris/devspend/`, not
`~/.iris/costs/`). See docs/specs/F-35_devspend_CLI.md.
"""

from __future__ import annotations

import json
import sys
import time
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from iris_core.devspend.aggregate import DevspendSummary, project_rollup, rollup, sync_latest_session
from iris_core.devspend.chip import STYLE_WARNING, render_chip
from iris_core.devspend.store import list_sessions, project_root

console = Console()


@click.group()
def devspend():
    """Developer tool spend tracking — what it costs YOU to use an AI coding assistant."""
    pass


@devspend.command("report")
@click.option("--format", "output_format", default="table", type=click.Choice(["table", "json"]))
def devspend_report(output_format: str) -> None:
    """One-shot project rollup: tokens and $ spent using AI coding assistants on this project."""
    summary = project_rollup()

    if output_format == "json":
        payload = {
            "session_count": summary.session_count,
            "total_tokens": summary.total_tokens,
            "total_cost_usd": summary.total_cost_usd,
            "cost_by_tool_source": summary.cost_by_tool_source,
            "cost_by_model": summary.cost_by_model,
            "flag_counts": summary.flag_counts,
        }
        click.echo(json.dumps(payload, indent=2))
        return

    _render_report_table(summary)


def _render_report_table(summary: DevspendSummary) -> None:
    root = project_root()
    console.print(f"[bold]iris devspend report[/bold] — {root}\n")

    if summary.session_count == 0:
        console.print("[dim]No Claude Code sessions found for this project yet.[/dim]")
        return

    console.print(f"Sessions:     {summary.session_count}")
    console.print(f"Total tokens: {summary.total_tokens:,}")
    console.print(f"Total spend:  ${summary.total_cost_usd:,.2f}\n")

    table = Table(title="Spend by model", show_header=True, header_style="bold")
    table.add_column("Model")
    table.add_column("Cost", justify="right")
    for model, cost in sorted(summary.cost_by_model.items(), key=lambda kv: -kv[1]):
        table.add_row(model, f"${cost:,.2f}")
    console.print(table)

    if summary.cost_by_tool_source:
        console.print("\n[bold]By tool[/bold]")
        for tool_source, cost in sorted(summary.cost_by_tool_source.items()):
            console.print(f"  {tool_source}: ${cost:,.2f}")

    if summary.flag_counts:
        console.print("\n[bold yellow]Heuristic flags (informational — human judgment required)[/bold yellow]")
        for flag_type, count in sorted(summary.flag_counts.items()):
            console.print(f"  [yellow]⚠[/yellow] {flag_type}: {count}")
        console.print("[dim]Run with --format json for per-flag detail.[/dim]")
    else:
        console.print("\n[dim]No inefficiency flags detected.[/dim]")


@devspend.command("live")
@click.option("--interval", default=2.0, type=float, show_default=True, help="Refresh interval in seconds")
def devspend_live(interval: float) -> None:
    """Ambient single-line chip: live tokens/$ for the current project. Ctrl+C to stop."""
    root = project_root()
    try:
        # Full sync once up front so the first render reflects everything
        # already on disk, not just whichever session happens to be newest.
        summary = project_rollup()
        _print_chip(summary)
        while True:
            time.sleep(interval)
            sync_latest_session(root=root)
            summary = rollup(list_sessions(root=root))
            _print_chip(summary)
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        sys.stdout.flush()


_ANSI_DIM = "\033[2m"
_ANSI_RED = "\033[31m"
_ANSI_RESET = "\033[0m"


def _print_chip(summary: DevspendSummary) -> None:
    chip = render_chip(summary)
    color = _ANSI_RED if chip.style == STYLE_WARNING else _ANSI_DIM
    # \r + trailing pad clears any leftover characters from a longer
    # previous line, then no trailing newline — the next tick overwrites
    # this same line. Never blocks: one parse of at most one file per
    # tick (see sync_latest_session), then a plain sleep.
    line = f"{color}{chip.text}{_ANSI_RESET}"
    sys.stdout.write("\r" + line + " " * 4)
    sys.stdout.flush()
