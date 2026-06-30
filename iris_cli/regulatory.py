"""iris regulatory — regulatory intelligence commands."""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from iris_core.regulatory.tracker import RegulatoryTracker

console = Console()


def _collect_active_frameworks(governance_dir: Optional[Path] = None) -> list[str]:
    """Collect compliance tags from agent passports in the governance directory."""
    from iris import AgentPassport

    gov_dir = governance_dir or Path.cwd() / "governance" / "agents"
    frameworks: set[str] = set()

    if gov_dir.exists():
        for passport_file in gov_dir.rglob("passport.yaml"):
            try:
                passport = AgentPassport.from_yaml(passport_file.read_text(encoding="utf-8"))
                for tag in passport.compliance_tags or []:
                    value = tag.value if hasattr(tag, "value") else str(tag)
                    frameworks.add(value)
            except Exception:
                continue

    if not frameworks:
        frameworks.add("colorado-ai-act")

    return sorted(frameworks)


def _format_effective_date(iso_date: str) -> str:
    try:
        dt = datetime.strptime(iso_date, "%Y-%m-%d")
        return dt.strftime("%B %d, %Y")
    except ValueError:
        return iso_date


def _render_rule_changes(bundle_id: str, old_version: str, new_version: str) -> None:
    """Show rule-level changes when registry versions differ."""
    import json

    from iris_core.compliance.dynamic_loader import DynamicBundleLoader, _bundled_registry_path

    loader = DynamicBundleLoader()
    cache_path = Path.home() / ".iris" / "registry-cache.json"
    bundled = _bundled_registry_path()

    old_registry: dict = {}
    if cache_path.exists():
        try:
            old_registry = json.loads(cache_path.read_text())
        except Exception:
            pass
    elif bundled.exists():
        old_registry = json.loads(bundled.read_text())

    if not bundled.exists():
        return
    new_registry = json.loads(bundled.read_text())
    changes = loader.diff_rules(bundle_id, old_registry, new_registry)
    if not changes:
        return

    console.print(f"\n   [bold]REGULATORY UPDATE — {bundle_id} v{old_version} → v{new_version}[/bold]")
    console.print("   [bold]RULE CHANGES:[/bold]")
    for change in changes[:10]:
        console.print(f"   ● {change}")
    console.print(
        "\n   Run: [bold]iris certify --agent <name>[/bold] to see updated status"
    )


def _render_check_output(
    tracker: RegulatoryTracker,
    updates: list,
    up_to_date: list[str],
    frameworks: list[str],
    *,
    show_all_up_to_date: bool = False,
) -> None:
    state = tracker.load_state()
    last_checked = state.get("last_checked", tracker.last_updated or "never")

    console.print(
        Panel(
            "Checking your active compliance frameworks...\n"
            f"Last checked: {last_checked}",
            title="Regulatory Intelligence Check",
            border_style="blue",
        )
    )

    if updates:
        console.print("\n[bold yellow]UPDATES AVAILABLE[/bold yellow]\n")
        for update in updates:
            if update.is_new_bundle:
                console.print(
                    f"[bold cyan]NEW[/bold cyan]    {update.bundle_id}  "
                    f"[dim](not installed)[/dim]"
                )
                console.print(f"{update.change_summary}")
                console.print(f"Effective: {_format_effective_date(update.effective_date)}")
                if update.notes:
                    console.print(update.notes)
                console.print(
                    f"   To activate: "
                    f"[bold]iris compliance check --framework {update.bundle_id}[/bold]\n"
                )
            else:
                severity_color = {
                    "MAJOR": "red",
                    "MINOR": "yellow",
                    "CLARIFICATION": "blue",
                }.get(update.change_severity, "white")
                console.print(
                    f"[{severity_color}]{update.change_severity}[/{severity_color}]  "
                    f"{update.bundle_id}  "
                    f"v{update.current_installed_version} → v{update.available_version}"
                )
                console.print(update.change_summary)
                console.print(
                    f"Effective: {_format_effective_date(update.effective_date)}"
                )
                _render_rule_changes(update.bundle_id, update.current_installed_version, update.available_version)
                console.print("   Action required:")
                console.print(
                    "   1. Run: [bold]pip install --upgrade iris-security-sdk[/bold]"
                )
                console.print(
                    f"   2. Run: [bold]iris compliance check[/bold] "
                    f"to see updated requirements"
                )
                if update.bundle_id == "colorado-ai-act" and update.change_severity == "MAJOR":
                    console.print(
                        "   3. Review CO-RR-001 — 3-year retention requires IRIS Pro"
                    )
                console.print()

    display_up_to_date = up_to_date if show_all_up_to_date else [
        fw for fw in up_to_date if fw in frameworks
    ]
    if display_up_to_date:
        console.print("[bold green]UP TO DATE[/bold green]")
        for bundle_id in display_up_to_date:
            version = (
                tracker._get_local_bundle_version(bundle_id)  # noqa: SLF001
                or tracker._remote_registry.get("bundles", {})  # noqa: SLF001
                .get(bundle_id, {})
                .get("current_version", "?")
            )
            console.print(
                f"[green]✓[/green] {bundle_id:<20} v{version}   "
                f"No changes since last check"
            )


@click.group()
def regulatory():
    """Regulatory intelligence — track AI law changes automatically."""
    pass


@regulatory.command("check")
@click.option(
    "--framework",
    "-f",
    "frameworks",
    multiple=True,
    help="Specific framework(s) to check (default: active compliance tags)",
)
@click.option("--dir", "governance_dir", type=click.Path(path_type=Path), default=None)
@click.option("--format", "output_format", default="table", type=click.Choice(["table", "json"]))
@click.option("--offline", is_flag=True, help="Use bundled registry only (no network)")
def regulatory_check(
    frameworks: tuple[str, ...],
    governance_dir: Optional[Path],
    output_format: str,
    offline: bool,
) -> None:
    """
    Check for regulatory updates affecting your active compliance tags.

    Shows what changed, what law changed it, and what to do.
    """
    active = list(frameworks) if frameworks else _collect_active_frameworks(governance_dir)
    tracker = RegulatoryTracker()
    updates = tracker.check_for_updates(active, use_remote=not offline)

    if output_format == "json":
        payload = {
            "last_updated": tracker.last_updated,
            "frameworks_checked": active,
            "updates": [u.to_dict() for u in updates],
            "up_to_date": tracker.up_to_date_frameworks,
        }
        click.echo(json.dumps(payload, indent=2))
        sys.exit(1 if updates else 0)
        return

    _render_check_output(
        tracker,
        updates,
        tracker.up_to_date_frameworks,
        active,
        show_all_up_to_date=bool(frameworks),
    )
    sys.exit(1 if updates else 0)


@regulatory.command("list")
@click.option("--format", "output_format", default="table", type=click.Choice(["table", "json"]))
@click.option("--offline", is_flag=True, help="Use bundled registry only (no network)")
def regulatory_list(output_format: str, offline: bool) -> None:
    """List all tracked regulatory frameworks with their current status."""
    tracker = RegulatoryTracker()
    tracker.fetch_registry(use_remote=not offline)
    frameworks = tracker.list_all_frameworks()

    if output_format == "json":
        click.echo(json.dumps(frameworks, indent=2))
        return

    table = Table(title="IRIS Regulatory Frameworks")
    table.add_column("Bundle", style="cyan")
    table.add_column("Law")
    table.add_column("Version")
    table.add_column("Installed")
    table.add_column("Effective")
    table.add_column("Status")

    for entry in frameworks:
        installed = (
            "[green]yes[/green]" if entry["installed"] else "[dim]no[/dim]"
        )
        status = (
            f"v{entry['installed_version']}"
            if entry["installed_version"] != "not installed"
            else "[yellow]not installed[/yellow]"
        )
        table.add_row(
            entry["bundle_id"],
            entry["law_name"][:50],
            entry["current_version"],
            status,
            entry["effective_date"],
            installed,
        )

    console.print(table)
    console.print(
        f"\n[dim]Registry last updated: {tracker.last_updated}[/dim]"
    )


@regulatory.command("watch")
@click.option(
    "--interval",
    default=86400,
    show_default=True,
    help="Check interval in seconds (default: daily)",
)
@click.option(
    "--framework",
    "-f",
    "frameworks",
    multiple=True,
    help="Framework(s) to watch (default: active compliance tags)",
)
@click.option("--dir", "governance_dir", type=click.Path(path_type=Path), default=None)
@click.option("--once", is_flag=True, help="Run a single check and exit (for CI)")
def regulatory_watch(
    interval: int,
    frameworks: tuple[str, ...],
    governance_dir: Optional[Path],
    once: bool,
) -> None:
    """
    Run regulatory checks on an interval and alert on changes.

    Useful in CI pipelines to catch regulatory changes automatically.
    """
    active = list(frameworks) if frameworks else _collect_active_frameworks(governance_dir)
    tracker = RegulatoryTracker()

    def _run_check() -> int:
        alerts = tracker.watch_once(active)
        if alerts:
            console.print(
                f"\n[bold red]REGULATORY ALERT[/bold red] — "
                f"{len(alerts)} change(s) detected\n"
            )
            for alert in alerts:
                console.print(
                    f"[{alert.severity}] {alert.bundle_id}: {alert.summary}"
                )
            return 1
        console.print(
            f"[green]✓[/green] No regulatory changes "
            f"({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})"
        )
        return 0

    if once:
        sys.exit(_run_check())

    console.print(
        f"Watching {len(active)} framework(s) every {interval}s. Press Ctrl+C to stop."
    )
    exit_code = 0
    try:
        while True:
            exit_code = _run_check()
            time.sleep(interval)
    except KeyboardInterrupt:
        sys.exit(exit_code)


@regulatory.command("history")
@click.option("--framework", "-f", required=True, help="Framework to show history for")
@click.option("--format", "output_format", default="table", type=click.Choice(["table", "json"]))
@click.option("--offline", is_flag=True, help="Use bundled registry only (no network)")
def regulatory_history(framework: str, output_format: str, offline: bool) -> None:
    """Show the full change history for a regulatory framework."""
    tracker = RegulatoryTracker()
    tracker.fetch_registry(use_remote=not offline)
    entry = tracker._remote_registry.get("bundles", {}).get(framework)  # noqa: SLF001

    if not entry:
        console.print(f"[red]Unknown framework:[/red] {framework}")
        sys.exit(1)

    history = tracker.get_framework_history(framework)

    if output_format == "json":
        click.echo(
            json.dumps(
                {
                    "framework": framework,
                    "law_name": entry.get("law_name"),
                    "current_version": entry.get("current_version"),
                    "history": history,
                },
                indent=2,
            )
        )
        return

    console.print(
        Panel(
            f"{entry.get('law_name', framework)}\n"
            f"Current version: {entry.get('current_version', '?')}\n"
            f"Effective: {entry.get('effective_date', '?')}",
            title=f"Regulatory History — {framework}",
            border_style="blue",
        )
    )

    if not history:
        console.print("[dim]No history entries recorded.[/dim]")
        return

    table = Table()
    table.add_column("Date")
    table.add_column("Version")
    table.add_column("Severity")
    table.add_column("Summary")

    for item in history:
        table.add_row(
            item.get("date", ""),
            item.get("version", ""),
            item.get("severity", ""),
            item.get("summary", ""),
        )

    console.print(table)


@regulatory.command("apply")
@click.option("--framework", "-f", required=True, help="Framework to apply update for")
def regulatory_apply(framework: str) -> None:
    """Show changelog and upgrade instructions for a regulatory update."""
    tracker = RegulatoryTracker()
    if not tracker.apply_update(framework):
        console.print(f"[red]Unknown framework:[/red] {framework}")
        sys.exit(1)
