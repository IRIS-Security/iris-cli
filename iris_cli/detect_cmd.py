"""iris detect — runtime detection and response over signed agent evidence."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import List, Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

import click
from rich.console import Console
from rich.table import Table

console = Console()

_STYLE = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "dim"}


def _post_webhook(url: str, alerts: List[dict], secret: Optional[str]) -> bool:
    body = json.dumps({"source": "iris-detect", "alerts": alerts}).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if secret:
        from iris_core.drift.notifier import SIGNATURE_HEADER, _sign_payload

        headers[SIGNATURE_HEADER] = _sign_payload(body, secret)
    try:
        with urlopen(Request(url, data=body, headers=headers, method="POST"), timeout=10) as resp:
            return 200 <= resp.status < 300
    except (URLError, OSError):
        return False


def _run_once(agent, vault_root, gov_dir, record, only_new, cfg):
    from iris_core.detection import detect_agent, detect_all
    from iris_core.evidence.locate import resolve_vault_id

    if agent:
        vault_id = resolve_vault_id(agent, gov_dir, vault_root)
        alerts = detect_agent(vault_id, vault_root, config=cfg, only_new=only_new, record=record)
        return {vault_id: alerts} if alerts else {}
    return detect_all(vault_root, config=cfg, only_new=only_new, record=record)


def _print_table(results, with_response: bool = True) -> None:
    if not results:
        console.print("[green]● No detections.[/green]")
        return
    table = Table(title="IRIS detections", show_lines=True)
    cols = ("Severity", "Rule", "Agent", "What happened") + (("Response",) if with_response else ())
    for col in cols:
        table.add_column(col)
    for alerts in results.values():
        for a in alerts:
            style = _STYLE.get(a.severity, "white")
            row = [f"[{style}]{a.severity}[/{style}]", a.rule, a.agent_name, a.summary]
            table.add_row(*(row + [a.response] if with_response else row))
    console.print(table)
    if not with_response:
        console.print("[dim]Recommended responses, SIEM output (--format json|jsonl), webhooks, and --watch "
                      "are in IRIS Business.[/dim]")


@click.command("detect")
@click.option("--agent", default=None, help="One agent; default is every agent with evidence")
@click.option("--vault-dir", type=click.Path(path_type=Path), default=None, help="Evidence root (default ~/.iris/evidence)")
@click.option("--dir", "governance_dir", type=click.Path(path_type=Path), default=None)
@click.option("--all-events", is_flag=True, help="Judge every event, not only events since the last run")
@click.option("--record/--no-record", default=True, show_default=True,
              help="Write each alert back to the vault as signed evidence")
@click.option("--webhook", default=None, envvar="IRIS_DETECT_WEBHOOK", help="POST alerts as JSON to this URL")
@click.option("--webhook-secret", default=None, envvar="IRIS_DETECT_WEBHOOK_SECRET",
              help="Sign webhook bodies (X-IRIS-Signature, HMAC-SHA256)")
@click.option("--format", "fmt", type=click.Choice(["table", "json", "jsonl"]), default="table")
@click.option("--watch", "watch_seconds", type=int, default=0, help="Repeat every N seconds")
@click.option("--window", "window_minutes", type=int, default=15, show_default=True)
@click.option("--burst", "burst_threshold", type=int, default=5, show_default=True,
              help="Blocked actions in the window that raise BLOCK-BURST")
@click.option("--fail-on", type=click.Choice(["none", "medium", "high", "critical"]), default="critical",
              show_default=True, help="Exit non-zero at this severity (for CI and cron)")
def detect(agent, vault_dir, governance_dir, all_events, record, webhook, webhook_secret, fmt,
           watch_seconds, window_minutes, burst_threshold, fail_on):
    """Detect tampering, blocked-action bursts, privileged and novel actions, and spikes.

    Each run judges events added since the last run. Alerts carry a
    recommended response and are recorded as signed evidence.

    \b
    Examples:
      iris detect
      iris detect --agent helpdesk --format jsonl          # pipe to your SIEM
      iris detect --watch 60 --webhook https://hooks.example.com/iris
    """
    from iris_core.detection import DetectionConfig
    from iris_core.detection.runtime import SEVERITY_RANK
    from iris_core.entitlements import Feature

    from iris_cli._tiers import entitled, require

    if fmt != "table":
        require(Feature.DETECT_RESPONSE, f"--format {fmt}")
    if webhook:
        require(Feature.DETECT_RESPONSE, "--webhook")
    if watch_seconds:
        require(Feature.DETECT_RESPONSE, "--watch")
    full = entitled(Feature.DETECT_RESPONSE)

    vault_root = vault_dir or Path.home() / ".iris" / "evidence"
    gov_dir = governance_dir or Path.cwd() / "governance" / "agents"
    cfg = DetectionConfig(window_minutes=window_minutes, block_burst_threshold=burst_threshold)
    threshold = {"none": 99, "medium": 2, "high": 3, "critical": 4}[fail_on]
    worst = 0

    while True:
        results = _run_once(agent, vault_root, gov_dir, record, not all_events, cfg)
        flat = [a.to_dict() for alerts in results.values() for a in alerts]
        worst = max([worst] + [SEVERITY_RANK[a["severity"]] for a in flat])
        if fmt == "json":
            click.echo(json.dumps({"alerts": flat}, indent=2))
        elif fmt == "jsonl":
            for a in flat:
                click.echo(json.dumps(a))
        else:
            _print_table(results, with_response=full)
        if webhook and flat:
            ok = _post_webhook(webhook, flat, webhook_secret)
            if fmt == "table":
                console.print("[dim]Webhook delivered.[/dim]" if ok else "[red]Webhook delivery failed.[/red]")
        if not watch_seconds:
            break
        time.sleep(watch_seconds)

    sys.exit(1 if worst >= threshold else 0)
