"""iris drift — compliance posture change detection and alerting."""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from iris_core.entitlements import Entitlements, Feature
from iris_core.drift.detector import DriftDetector, DriftReport
from iris_core.drift.notifier import DriftNotifier, load_alert_config, save_alert_config

console = Console()


def _gov_dir(governance_dir: Path | None) -> Path:
    return governance_dir or Path.cwd() / "governance" / "agents"


def _require_pro_license(feature_name: str, feature: Feature) -> None:
    ents = Entitlements()
    if not ents.has(feature):
        try:
            ents.require(feature, context=feature_name)
        except Exception as exc:
            console.print(str(exc))
            sys.exit(1)


def _render_check_table(report: DriftReport) -> None:
    table = Table(title="Compliance Drift Check")
    table.add_column("Change", style="bold")
    table.add_column("Agent")
    table.add_column("Detail")

    for event in report.new_violations:
        table.add_row("[red]NEW[/red]", event.agent_name, f"{event.rule_id}: {event.description}")
    for event in report.resolved_violations:
        table.add_row("[green]RESOLVED[/green]", event.agent_name, f"{event.rule_id}: {event.description}")
    for event in report.new_cost_anomalies:
        table.add_row("[red]COST[/red]", event.agent_name, f"{event.severity}: {event.description}")
    for event in report.resolved_cost_anomalies:
        table.add_row("[green]COST RESOLVED[/green]", event.agent_name, f"{event.severity}: {event.description}")
    for change in report.score_changes:
        if change.direction == "degraded":
            style = "[red]SCORE ↓[/red]"
        elif change.direction == "improved":
            style = "[green]SCORE ↑[/green]"
        else:
            style = "[dim]SCORE[/dim]"
        detail = (
            f"{change.framework}: {int(change.previous_score * 100)}% → "
            f"{int(change.current_score * 100)}% ({int(change.delta * 100):+d}%)"
        )
        table.add_row(style, change.agent_name, detail)

    if report.production_ready_lost:
        for name in report.production_ready_lost:
            table.add_row("[red]NOT READY[/red]", name, "was production-ready")

    if (
        not report.new_violations
        and not report.resolved_violations
        and not report.score_changes
        and not report.new_cost_anomalies
        and not report.resolved_cost_anomalies
    ):
        table.add_row("[dim]—[/dim]", "—", "[dim]No changes[/dim]")

    console.print(table)
    console.print(f"\n[dim]{report.summary}[/dim]")


def _send_configured_alerts(report: DriftReport, detector: DriftDetector) -> None:
    if not report.has_degradation():
        return

    config = load_alert_config()
    notifier = DriftNotifier()
    alert_text = detector.generate_alert(report)

    if config.get("slack_webhook"):
        if notifier.notify_slack(config["slack_webhook"], report):
            console.print("[dim]Slack alert sent.[/dim]")
    if config.get("webhook"):
        if notifier.notify_webhook(config["webhook"], report):
            console.print("[dim]Webhook alert sent.[/dim]")
    if config.get("email") and alert_text:
        if notifier.notify_email(config["email"], report):
            console.print("[dim]Email alert sent.[/dim]")


@click.group()
def drift():
    """Compliance drift detection — snapshot, compare, and alert."""
    pass


@drift.command("snapshot")
@click.option("--dir", "governance_dir", type=click.Path(path_type=Path), default=None)
@click.option("--output", type=click.Path(path_type=Path), default=None, help="Write snapshot to this path")
def drift_snapshot(governance_dir: Optional[Path], output: Optional[Path]) -> None:
    """Take a compliance snapshot right now (baseline before changes)."""
    detector = DriftDetector(_gov_dir(governance_dir))
    snapshot = detector.take_snapshot(output_path=output)
    dest = output or detector.snapshot_dir
    console.print(
        f"[bold green]✓ Snapshot saved[/bold green] at {snapshot.timestamp}\n"
        f"Agents captured: {len(snapshot.agents)}\n"
        f"Location: {dest}"
    )


@drift.command("check")
@click.option("--since", default=None, help="Timestamp or snapshot file to compare against")
@click.option("--dir", "governance_dir", type=click.Path(path_type=Path), default=None)
@click.option("--format", "output_format", type=click.Choice(["table", "json"]), default="table")
def drift_check(since: Optional[str], governance_dir: Optional[Path], output_format: str) -> None:
    """Compare current compliance state against the last snapshot."""
    detector = DriftDetector(_gov_dir(governance_dir))

    if not since and not detector.list_snapshots():
        detector.take_snapshot()
        console.print(
            "[yellow]Baseline established.[/yellow]\n"
            "Run [bold]iris drift check[/bold] again tomorrow to detect changes."
        )
        sys.exit(0)

    report = detector.detect_drift(since=since)

    if report.comparison_period == "baseline established":
        detector.take_snapshot()
        console.print(
            "[yellow]Baseline established.[/yellow]\n"
            "Run [bold]iris drift check[/bold] again tomorrow to detect changes."
        )
        sys.exit(0)

    if output_format == "json":
        click.echo(json.dumps(report.to_dict(), indent=2))
    else:
        _render_check_table(report)

    alert = detector.generate_alert(report)
    if alert:
        console.print(f"\n[bold red]{alert}[/bold red]")
        _send_configured_alerts(report, detector)

    if report.has_degradation():
        sys.exit(1)
    sys.exit(0)


@drift.command("report")
@click.option("--days", default=7, show_default=True, help="Trend window in days")
@click.option("--dir", "governance_dir", type=click.Path(path_type=Path), default=None)
@click.option("--format", "output_format", type=click.Choice(["markdown", "table"]), default="table")
def drift_report(days: int, governance_dir: Optional[Path], output_format: str) -> None:
    """Show compliance trend over the past N days."""
    detector = DriftDetector(_gov_dir(governance_dir))
    snapshots = detector.list_snapshots()

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    recent = []
    for path in snapshots:
        try:
            snap = detector._load_snapshot_file(path)
            snap_dt = datetime.fromisoformat(snap.timestamp.replace("Z", "+00:00"))
            if snap_dt >= cutoff:
                recent.append(snap)
        except (ValueError, KeyError, json.JSONDecodeError):
            continue

    if len(recent) < 2:
        console.print(
            "[yellow]Need at least 2 snapshots in the selected window.[/yellow]\n"
            "Run [bold]iris drift snapshot[/bold] daily to build a trend."
        )
        sys.exit(0)

    rows: list[tuple[str, int, int, float]] = []
    for i in range(1, len(recent)):
        prev = recent[i - 1]
        curr = recent[i]
        report = detector.detect_drift(since=str(prev.timestamp))
        rows.append(
            (
                curr.timestamp,
                len(report.new_violations),
                len(report.resolved_violations),
                report.net_score_change,
            )
        )

    if output_format == "markdown":
        lines = [
            f"# IRIS Compliance Drift Report ({days} days)",
            "",
            "| Snapshot | New violations | Resolved | Net score change |",
            "| --- | ---: | ---: | ---: |",
        ]
        for ts, new_v, resolved, net in rows:
            lines.append(f"| {ts} | {new_v} | {resolved} | {net:+.2f} |")
        click.echo("\n".join(lines))
    else:
        table = Table(title=f"Compliance Trend ({days} days)")
        table.add_column("Snapshot")
        table.add_column("New violations", justify="right")
        table.add_column("Resolved", justify="right")
        table.add_column("Net score Δ", justify="right")
        for ts, new_v, resolved, net in rows:
            color = "red" if net < 0 else "green" if net > 0 else "dim"
            table.add_row(ts, str(new_v), str(resolved), f"[{color}]{net:+.2f}[/{color}]")
        console.print(table)


@drift.command("watch")
@click.option("--interval", default=60, show_default=True, help="Check interval in minutes")
@click.option("--dir", "governance_dir", type=click.Path(path_type=Path), default=None)
def drift_watch(interval: int, governance_dir: Optional[Path]) -> None:
    """Run drift check every N minutes (free tier — terminal alerts only)."""
    detector = DriftDetector(_gov_dir(governance_dir))
    if not detector.list_snapshots():
        detector.take_snapshot()
        console.print("[dim]Initial baseline snapshot saved.[/dim]")

    console.print(
        f"Watching for compliance drift every {interval} minute(s). Press Ctrl+C to stop."
    )
    try:
        while True:
            report = detector.detect_drift()
            if report.has_degradation():
                alert = detector.generate_alert(report)
                if alert:
                    console.print(f"\n[bold red]{alert}[/bold red]\n")
            else:
                console.print(f"[dim]{datetime.now().strftime('%H:%M:%S')} — no degradation[/dim]")
            time.sleep(interval * 60)
    except KeyboardInterrupt:
        console.print("\n[dim]Drift watch stopped.[/dim]")


@drift.command("alert-config")
@click.option("--slack-webhook", default=None, help="Slack incoming webhook URL")
@click.option("--email", default=None, help="Alert email address")
@click.option("--webhook", default=None, help="Generic webhook URL for JSON alerts")
def drift_alert_config(slack_webhook: Optional[str], email: Optional[str], webhook: Optional[str]) -> None:
    """Configure Slack, email, or webhook drift alerts (Pro license for Slack/email)."""
    config = load_alert_config()

    if slack_webhook:
        _require_pro_license("Slack drift alerts", Feature.DRIFT_SLACK_ALERT)
        config["slack_webhook"] = slack_webhook
    if email:
        _require_pro_license("Email drift alerts", Feature.DRIFT_EMAIL_ALERT)
        config["email"] = email
    if webhook:
        _require_pro_license("Webhook drift alerts", Feature.DRIFT_WEBHOOK_ALERT)
        config["webhook"] = webhook

    if not any([slack_webhook, email, webhook]):
        console.print("[yellow]No options provided. Current config:[/yellow]")
        if config:
            for key, value in config.items():
                if "secret" in key or "pass" in key:
                    value = "***"
                console.print(f"  {key}: {value}")
        else:
            console.print("  (not configured)")
        return

    path = save_alert_config(config)
    console.print(f"[bold green]✓ Alert config saved[/bold green] to {path}")
