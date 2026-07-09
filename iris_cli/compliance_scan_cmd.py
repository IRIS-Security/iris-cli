"""iris compliance scan — offline workload detection + local obligation eval."""

# Copyright 2024-2025 Gilbert Martin / IRIS Security, Inc.
# All Rights Reserved.
# Author: Gilbert Martin <gilbert@iris-security.io>

from __future__ import annotations

import os
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from iris.scan import detect_workload
from iris_core.compliance.workload_eval import (
    evaluate_workload_profile,
    framework_coverage,
    top_recommended_actions,
)

console = Console()

_SEVERITY_RANK = {"blocker": 0, "required": 1, "recommended": 2}


def _exit_on_fail_threshold(obligations: list[dict], fail_on: str) -> None:
    if fail_on == "none":
        return
    threshold = _SEVERITY_RANK[fail_on]
    blocking = [
        obligation
        for obligation in obligations
        if not obligation.get("informational", False)
        and _SEVERITY_RANK.get(obligation.get("severity", "recommended"), 9) <= threshold
    ]
    if blocking:
        sys.exit(1)


def _resolve_profile(
    *,
    scan_source: str | None,
    path: str,
    litellm_config: str | None,
    litellm_proxy: str | None,
    lookback_days: int,
) -> dict:
    if scan_source is None:
        return detect_workload(path)

    if scan_source == "langfuse":
        try:
            from iris_langfuse import profile_from_langfuse
        except ImportError as exc:
            raise click.ClickException(
                'iris-langfuse is not installed. Run: pip install "iris-langfuse[live]"'
            ) from exc
        try:
            return profile_from_langfuse(lookback_days=lookback_days)
        except ImportError as exc:
            raise click.ClickException(
                'Langfuse SDK missing. Run: pip install "iris-langfuse[live]"'
            ) from exc
        except ValueError as exc:
            raise click.ClickException(str(exc)) from exc

    if scan_source == "litellm":
        try:
            from iris_litellm import profile_from_litellm_config, profile_from_litellm_proxy
        except ImportError as exc:
            raise click.ClickException(
                'iris-litellm is not installed. Run: pip install "iris-litellm[live]"'
            ) from exc
        if litellm_config:
            return profile_from_litellm_config(litellm_config)
        if litellm_proxy:
            return profile_from_litellm_proxy(litellm_proxy)
        raise click.ClickException(
            "LiteLLM source requires --config <litellm.config.yaml> or --proxy <base_url>"
        )

    raise click.ClickException(f"Unknown scan source: {scan_source}")


def _scan_subtitle(scan_source: str | None) -> str:
    if scan_source == "langfuse":
        return "Langfuse trace metadata — no prompt content read."
    if scan_source == "litellm":
        return "LiteLLM config/proxy — models and providers inferred."
    return "Offline detection — no network calls required."


def _print_profile(profile: dict) -> None:
    table = Table(title="What you're building", show_header=True, header_style="bold")
    table.add_column("Attribute")
    table.add_column("Detected values")
    for key in (
        "providers",
        "frameworks",
        "models",
        "data_categories",
        "deployment_regions",
        "agent_count",
        "autonomy_level",
        "customer_facing",
    ):
        value = profile.get(key, [])
        if isinstance(value, bool):
            display = "yes" if value else "no"
        elif isinstance(value, list):
            display = ", ".join(value) if value else "—"
        else:
            display = str(value)
        table.add_row(key.replace("_", " ").title(), display)
    console.print(table)


def _print_frameworks(profile: dict) -> None:
    coverage = framework_coverage(profile)
    table = Table(title="Applicable frameworks", show_header=True, header_style="bold")
    table.add_column("Framework")
    table.add_column("Why this applies to you")
    table.add_column("Depth")
    for entry in coverage:
        depth = (
            f"[yellow]mapped — thin[/yellow]"
            if entry["thin"]
            else f"{entry['rule_count']} rules"
        )
        table.add_row(entry["bundle_id"], entry["why"], depth)
    console.print(table)

    thin = [entry for entry in coverage if entry["thin"]]
    if thin:
        console.print(
            "[dim]Thin coverage means the registry has this framework mapped but "
            "not yet deeply evaluated here — run one of the following for a real "
            "control-by-control check:[/dim]"
        )
        for entry in thin:
            console.print(
                f"  [dim]•[/dim] iris compliance check --framework {entry['bundle_id']}"
            )


def _print_actions(obligations: list[dict]) -> None:
    actions = top_recommended_actions(obligations, limit=5)
    if not actions:
        console.print("[dim]No obligations triggered for detected profile.[/dim]")
        return
    table = Table(title="Top recommended actions", show_header=True, header_style="bold")
    table.add_column("#", style="dim")
    table.add_column("Severity")
    table.add_column("Framework")
    table.add_column("Action")
    for idx, action in enumerate(actions, 1):
        sev = action.get("severity", "recommended")
        color = {"blocker": "red", "required": "yellow"}.get(sev, "cyan")
        table.add_row(
            str(idx),
            f"[{color}]{sev}[/{color}]",
            action.get("framework_key", ""),
            (action.get("recommended_action") or "")[:80],
        )
    console.print(table)


def _push_profile(profile: dict) -> None:
    api_key = os.environ.get("IRIS_API_KEY") or os.environ.get("IRIS_CLOUD_API_KEY")
    base_url = os.environ.get("IRIS_API_URL", "http://localhost:8000")
    if not api_key:
        console.print("[yellow]Set IRIS_API_KEY to push profile to cloud.[/yellow]")
        return
    import httpx

    response = httpx.post(
        f"{base_url.rstrip('/')}/intelligence/profile/scan",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json=profile,
        timeout=30,
    )
    if response.status_code >= 400:
        console.print(f"[red]Push failed ({response.status_code}): {response.text}[/red]")
        return
    console.print("[green]Profile pushed to IRIS Cloud.[/green]")


@click.command("scan")
@click.option("--path", default=".", help="Project path to scan (default local code scan)")
@click.option(
    "--from",
    "scan_source",
    type=click.Choice(["langfuse", "litellm"], case_sensitive=False),
    default=None,
    help="Observability source instead of local code scan",
)
@click.option("--config", "litellm_config", type=click.Path(exists=True), help="LiteLLM config.yaml")
@click.option("--proxy", "litellm_proxy", help="LiteLLM proxy base URL")
@click.option("--lookback-days", default=30, show_default=True, help="Langfuse lookback window")
@click.option("--push", is_flag=True, help="POST profile to cloud when IRIS_API_KEY is set")
@click.option(
    "--fail-on",
    default="none",
    type=click.Choice(["blocker", "required", "none"]),
    show_default=True,
    help="Exit 1 when obligations meet or exceed this severity (CI integration)",
)
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON")
def compliance_scan_cmd(
    path: str,
    scan_source: str | None,
    litellm_config: str | None,
    litellm_proxy: str | None,
    lookback_days: int,
    push: bool,
    fail_on: str,
    as_json: bool,
) -> None:
    """Detect workload attributes and evaluate local regulatory obligations (offline)."""
    root = Path(path).resolve()
    if scan_source is None and not root.exists():
        raise click.ClickException(f"Path not found: {root}")

    profile = _resolve_profile(
        scan_source=scan_source,
        path=str(root),
        litellm_config=litellm_config,
        litellm_proxy=litellm_proxy,
        lookback_days=lookback_days,
    )
    obligations = evaluate_workload_profile(profile)

    if as_json:
        import json

        click.echo(json.dumps({"profile": profile, "obligations": obligations}, indent=2))
        if push:
            _push_profile(profile)
        _exit_on_fail_threshold(obligations, fail_on)
        return

    console.print(
        Panel(
            "[bold]IRIS Compliance Intelligence Scan[/bold]\n"
            + _scan_subtitle(scan_source),
            border_style="cyan",
        )
    )
    _print_profile(profile)
    _print_frameworks(profile)
    _print_actions(obligations)
    console.print(
        "\n[dim]Continuous monitoring, evidence mapping, and team workflows: "
        "iris cloud connect  ->  https://iris-security.io[/dim]"
    )
    if push:
        _push_profile(profile)
    _exit_on_fail_threshold(obligations, fail_on)
