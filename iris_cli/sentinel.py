"""iris sentinel — continuous governance monitoring and alerting."""

from __future__ import annotations

import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from iris_core.cost.tracker import discover_agent_trackers
from iris_core.discovery.scanner import CodebaseScanner
from iris_core.drift.detector import DriftDetector
from iris_core.drift.notifier import load_alert_config

console = Console()


def _gov_dir(governance_dir: Path | None) -> Path:
    return governance_dir or Path.cwd() / "governance" / "agents"


def _monthly_cost_total() -> float:
    total = 0.0
    for tracker in discover_agent_trackers():
        summary = tracker.get_summary()
        total += summary.estimated_monthly_cost
    return total


def _count_governed(governance_dir: Path) -> int:
    if not governance_dir.exists():
        return 0
    return len(list(governance_dir.rglob("passport.yaml")))


def _render_sentinel_clear(governed: int, violations: int, cost: float) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    console.print(
        f"[{ts}]  ● All clear — {governed} agents governed, "
        f"{violations} violations, ${cost:.0f}/mo"
    )


def _render_sentinel_alert(report, detector: DriftDetector) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    for change in report.score_changes:
        if change.direction != "degraded":
            continue
        prev = int(change.previous_score * 100)
        curr = int(change.current_score * 100)
        console.print(
            f"[{ts}]  ◐ ALERT — {change.agent_name} score dropped {prev}%→{curr}%"
        )
        console.print(f"               Cause: compliance posture changed recently")
        console.print(
            f"               Action: iris certify --framework colorado-ai-act "
            f"--agent {change.agent_name}"
        )
    config = load_alert_config()
    if config.get("slack_webhook"):
        console.print(f"               Alert sent to: [configured Slack webhook]")

    alert = detector.generate_alert(report)
    if alert:
        console.print(f"[bold red]{alert}[/bold red]")


@click.command("sentinel")
@click.option("--agent", default=None, help="Monitor a specific agent")
@click.option("--interval", default=60, show_default=True, help="Check interval in minutes")
@click.option("--dir", "governance_dir", type=click.Path(path_type=Path), default=None)
def sentinel(
    agent: Optional[str],
    interval: int,
    governance_dir: Optional[Path],
) -> None:
    """
    Continuous governance monitoring — drift, violations, cost anomalies.

    Alias: iris drift watch
    """
    gov = _gov_dir(governance_dir)
    detector = DriftDetector(gov)
    if not detector.list_snapshots():
        detector.take_snapshot()
        console.print("[dim]Initial baseline snapshot saved.[/dim]")

    scanner = CodebaseScanner()
    console.print(
        f"IRIS Sentinel standing guard every {interval} minute(s). Press Ctrl+C to stop."
    )

    try:
        while True:
            report = detector.detect_drift()
            governed = _count_governed(gov)
            violations = len(report.new_violations)
            cost = _monthly_cost_total()

            if agent:
                report.new_violations = [v for v in report.new_violations if v.agent_name == agent]
                report.score_changes = [c for c in report.score_changes if c.agent_name == agent]

            ungoverned = scanner.scan_directory(Path.cwd()).ungoverned_findings
            if ungoverned and not report.has_degradation():
                ts = datetime.now().strftime("%H:%M:%S")
                console.print(
                    f"[{ts}]  ◐ ALERT — {len(ungoverned)} ungoverned agent pattern(s) detected"
                )
                console.print("               Action: iris scan --discover --govern")

            if report.has_degradation():
                _render_sentinel_alert(report, detector)
            else:
                _render_sentinel_clear(governed, violations, cost)

            time.sleep(interval * 60)
    except KeyboardInterrupt:
        console.print("\n[dim]Sentinel stopped.[/dim]")
        sys.exit(0)
