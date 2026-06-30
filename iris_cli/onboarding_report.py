"""iris onboarding-report — real per-step timing breakdown."""

from __future__ import annotations

from typing import Optional

import click
from rich.console import Console

from iris_core.cli_timing.session import OnboardingSession

console = Console()


@click.command("onboarding-report")
@click.option("--session-id", default=None, help="Specific onboarding session ID")
def onboarding_report(session_id: Optional[str]) -> None:
    """
    Print the real timing breakdown from install through enforced policy.

    Example:
      iris onboarding-report
      iris onboarding-report --session-id abc-123
    """
    session: Optional[OnboardingSession] = None
    if session_id:
        for row in OnboardingSession.load_history():
            if row.get("session_id") == session_id:
                session = OnboardingSession.from_dict(row)
                break
        if session is None:
            raise click.ClickException(f"No session found with id {session_id}")
    else:
        history = OnboardingSession.load_history()
        if history:
            session = OnboardingSession.from_dict(history[-1])

    if session is None or not session.steps:
        console.print(
            "[yellow]No onboarding session recorded yet.[/yellow]\n"
            "Run [bold]iris quickstart[/bold] to start your first session."
        )
        return

    for line in session.report_lines():
        console.print(line)
