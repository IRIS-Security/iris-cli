"""iris cost — token cost tracking, reporting, and optimization suggestions."""

from __future__ import annotations

import csv
import io
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

import click
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from iris_core.cost.pricing import DEFAULT_PRICING, overrides_path, PricingRegistry
from iris_core.cost.tracker import CostSummary, CostTracker, discover_agent_trackers
from iris_core.entitlements import Entitlements, Feature

console = Console()

ALERTS_PATH = Path.home() / ".iris" / "cost-alerts.yaml"


def _since_from_days(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _since_from_date(since: Optional[str], days: int) -> str:
    if since:
        return datetime.fromisoformat(since).replace(tzinfo=timezone.utc).isoformat()
    return _since_from_days(days)


def _format_usd(amount: float) -> str:
    if amount >= 1:
        return f"${amount:,.2f}"
    return f"${amount:.3f}"


def _find_tracker(agent_name: str) -> Optional[CostTracker]:
    for tracker in discover_agent_trackers():
        if tracker.agent_name == agent_name or tracker.agent_id == agent_name:
            return tracker
    return None


def _resolve_trackers(agent: Optional[str]) -> List[CostTracker]:
    trackers = discover_agent_trackers()
    if not agent:
        return trackers
    matched = [t for t in trackers if t.agent_name == agent or t.agent_id == agent]
    if not matched:
        console.print(f"[yellow]No cost data found for agent '{agent}'.[/yellow]")
        sys.exit(1)
    return matched


def _model_call_counts(tracker: CostTracker, since: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for entry in tracker.get_entries(since=since):
        counts[entry.model] = counts.get(entry.model, 0) + 1
    return counts


def _render_report_table(summary: CostSummary, days: int) -> None:
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    header = (
        f"┌─ Cost Report: {summary.agent_name} "
        f"{'─' * max(1, 40 - len(summary.agent_name))}┐\n"
        f"│ Period: last {days} days  │  Generated: {generated}"
        f"{' ' * max(1, 18 - len(str(days)))}│\n"
        f"└{'─' * 58}┘"
    )
    console.print(header)
    console.print("\n[bold]SUMMARY[/bold]")
    console.print(f"Total spend:        {_format_usd(summary.total_cost_usd)}")
    console.print(f"Total calls:         {summary.total_calls:,}")
    console.print(f"Avg cost per call:  {_format_usd(summary.avg_cost_per_call)}")
    console.print(f"Estimated monthly:  {_format_usd(summary.estimated_monthly_cost)}")

    if summary.cost_by_model:
        console.print("\n[bold]BY MODEL[/bold]")
        tracker = _find_tracker(summary.agent_name)
        since = summary.period_start
        call_counts = _model_call_counts(tracker, since) if tracker else {}
        total = summary.total_cost_usd or 1.0
        for model, cost in sorted(summary.cost_by_model.items(), key=lambda x: -x[1]):
            pct = int(cost / total * 100)
            calls = call_counts.get(model, 0)
            console.print(
                f"{model:<20} {_format_usd(cost):>8}  {pct:>3}%   ({calls:,} calls)"
            )

    if summary.cost_by_tool:
        console.print("\n[bold]BY TOOL[/bold]")
        for tool, cost in sorted(summary.cost_by_tool.items(), key=lambda x: -x[1]):
            entries = [
                e for e in (_find_tracker(summary.agent_name) or CostTracker("", "")).get_entries(since=summary.period_start)
                if e.tool_name == tool
            ]
            calls = len(entries) if entries else 0
            per_call = cost / calls if calls else 0.0
            console.print(
                f"{tool:<20} {_format_usd(cost):>8}   ({calls:,} calls)  "
                f"{_format_usd(per_call)}/call"
            )

    if summary.anomalies:
        console.print("\n[bold]ANOMALIES[/bold]")
        for anomaly in summary.anomalies[:10]:
            ts = anomaly.call.timestamp[:16].replace("T", " ")
            console.print(
                f"⚠ {ts}  {_format_usd(anomaly.call.cost_usd)} call — "
                f"{anomaly.call.tool_name}()\n"
                f"  {anomaly.description}"
            )


def _render_summary_table(summaries: List[CostSummary], days: int) -> None:
    total_org = sum(s.total_cost_usd for s in summaries)
    header = (
        f"┌─ IRIS Cost Summary — All Agents {'─' * 24}┐\n"
        f"│ Period: last {days} days  │  Total org spend: {_format_usd(total_org):<12}│\n"
        f"└{'─' * 58}┘"
    )
    console.print(header)
    console.print("")

    table = Table(show_header=True, header_style="bold")
    table.add_column("Agent")
    table.add_column("Spend", justify="right")
    table.add_column("Calls", justify="right")
    table.add_column("Avg/call", justify="right")
    table.add_column("Trend")

    for summary in sorted(summaries, key=lambda s: -s.total_cost_usd):
        trend = summary.cost_trend
        if trend == "INCREASING":
            trend_display = "↑ increasing"
        elif trend == "DECREASING":
            trend_display = "↓ decreasing"
        else:
            trend_display = "→ stable"
        table.add_row(
            summary.agent_name,
            _format_usd(summary.total_cost_usd),
            f"{summary.total_calls:,}",
            _format_usd(summary.avg_cost_per_call),
            trend_display,
        )
    console.print(table)


def _suggest_optimizations(summary: CostSummary, since: str) -> List[str]:
    suggestions: List[str] = []
    tracker = _find_tracker(summary.agent_name)
    if not tracker:
        return suggestions

    downgrade_map = {
        "gpt-4o": "gpt-4o-mini",
        "claude-sonnet-4-6": "claude-haiku-4-5",
        "claude-opus-4-6": "claude-sonnet-4-6",
        "gemini-2.0-pro": "gemini-2.0-flash",
        "gemini-1.5-pro": "gemini-1.5-flash",
    }
    registry = PricingRegistry()
    idx = 1
    total_saving = 0.0

    for tool, tool_cost in sorted(summary.cost_by_tool.items(), key=lambda x: -x[1]):
        tool_entries = [e for e in tracker.get_entries(since=since) if e.tool_name == tool]
        if not tool_entries:
            continue
        current_model = max(
            {(e.model, e.cost_usd) for e in tool_entries},
            key=lambda x: x[1],
        )[0]
        suggested_model = downgrade_map.get(current_model)
        if not suggested_model:
            continue

        calls = len(tool_entries)
        current_per_call = tool_cost / calls
        provider = tool_entries[0].provider
        avg_input = sum(e.input_tokens for e in tool_entries) // calls
        avg_output = sum(e.output_tokens for e in tool_entries) // calls
        suggested_cost = registry.calculate_cost(provider, suggested_model, avg_input, avg_output)
        suggested_total = suggested_cost * calls
        saving = tool_cost - suggested_total
        if saving <= 0:
            continue
        total_saving += saving
        suggestions.append(
            f"{idx}. Switch {tool} to {suggested_model}\n"
            f"   Current: {current_model} at {_format_usd(current_per_call)}/call "
            f"({calls:,} calls = {_format_usd(tool_cost)})\n"
            f"   Suggested: {suggested_model} at {_format_usd(suggested_cost)}/call "
            f"({calls:,} calls = {_format_usd(suggested_total)})\n"
            f"   Estimated saving: {_format_usd(saving)}/month "
            f"({int(saving / tool_cost * 100)}% reduction)\n"
            f"   Risk: Lower capability model. Test accuracy before switching."
        )
        idx += 1

    large_prompt_entries = [
        e for e in tracker.get_entries(since=since) if e.input_tokens > 10_000
    ]
    if large_prompt_entries:
        avg_tokens = int(
            sum(e.input_tokens for e in large_prompt_entries) / len(large_prompt_entries)
        )
        excess_cost = sum(e.cost_usd for e in large_prompt_entries) * 0.3
        total_saving += excess_cost
        suggestions.append(
            f"{idx}. The {min(3, len(large_prompt_entries))} most expensive calls include "
            f"large prompts (avg {avg_tokens:,} tokens). Consider summarizing first.\n"
            f"   Estimated saving: {_format_usd(excess_cost)}/month"
        )

    if suggestions:
        pct = int(total_saving / max(summary.estimated_monthly_cost, 0.01) * 100)
        suggestions.append(
            f"\nTotal estimated saving: {_format_usd(total_saving)}/month ({pct}% reduction)"
        )
    return suggestions


def _push_cost_summary(summary: CostSummary) -> None:
    import os

    api_key = os.environ.get("IRIS_API_KEY") or os.environ.get("IRIS_CLOUD_API_KEY")
    base_url = os.environ.get("IRIS_API_URL", "http://localhost:8000")
    if not api_key:
        console.print("[yellow]Set IRIS_API_KEY to push cost attribution to cloud.[/yellow]")
        return
    import httpx

    payload = {
        "agent_id": summary.agent_id,
        "agent_name": summary.agent_name,
        "period_start": summary.period_start,
        "period_end": summary.period_end,
        "cost_usd": summary.total_cost_usd,
        "total_calls": summary.total_calls,
    }
    response = httpx.post(
        f"{base_url.rstrip('/')}/cost/push",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json=payload,
        timeout=30,
    )
    if response.status_code >= 400:
        console.print(f"[red]Push failed ({response.status_code}): {response.text}[/red]")
        return
    console.print("[green]Cost attribution pushed to IRIS Cloud.[/green]")


def load_alert_config() -> dict:
    if not ALERTS_PATH.exists():
        return {}
    return yaml.safe_load(ALERTS_PATH.read_text()) or {}


def save_alert_config(config: dict) -> None:
    ALERTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    ALERTS_PATH.write_text(yaml.dump(config, default_flow_style=False, sort_keys=False))


@click.group()
def cost():
    """Token cost tracking and reporting across all IRIS integrations."""
    pass


@cost.command("report")
@click.option("--agent", default=None, help="Agent name (default: all agents)")
@click.option("--days", default=30, type=int, help="Report period in days")
@click.option("--format", "output_format", default="table", type=click.Choice(["table", "json", "csv"]))
@click.option("--since", default=None, help="ISO date string for period start")
@click.option("--push", is_flag=True, help="POST cost attribution to IRIS Cloud when IRIS_API_KEY is set")
def cost_report(
    agent: Optional[str], days: int, output_format: str, since: Optional[str], push: bool
) -> None:
    """Show a detailed cost report for one or all agents."""
    since_iso = _since_from_date(since, days)
    trackers = _resolve_trackers(agent)
    summaries = [t.get_summary(since=since_iso) for t in trackers]

    if push:
        for summary in summaries:
            _push_cost_summary(summary)

    if output_format == "json":
        payload = [
            {
                "agent_name": s.agent_name,
                "total_cost_usd": s.total_cost_usd,
                "total_calls": s.total_calls,
                "avg_cost_per_call": s.avg_cost_per_call,
                "estimated_monthly_cost": s.estimated_monthly_cost,
                "cost_by_model": s.cost_by_model,
                "cost_by_tool": s.cost_by_tool,
                "cost_trend": s.cost_trend,
                "anomalies": [
                    {
                        "type": a.type,
                        "description": a.description,
                        "tool_name": a.call.tool_name,
                        "cost_usd": a.call.cost_usd,
                        "threshold_usd": a.threshold_usd,
                    }
                    for a in s.anomalies
                ],
            }
            for s in summaries
        ]
        click.echo(json.dumps(payload, indent=2))
        return

    if output_format == "csv":
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(
            ["agent", "total_cost_usd", "total_calls", "avg_cost_per_call", "estimated_monthly"]
        )
        for s in summaries:
            writer.writerow(
                [s.agent_name, s.total_cost_usd, s.total_calls, s.avg_cost_per_call, s.estimated_monthly_cost]
            )
        click.echo(buffer.getvalue())
        return

    for summary in summaries:
        _render_report_table(summary, days)
        if len(summaries) > 1:
            console.print("")


@cost.command("summary")
@click.option("--days", default=30, type=int, help="Report period in days")
@click.option("--since", default=None, help="ISO date string for period start")
def cost_summary(days: int, since: Optional[str]) -> None:
    """CFO report — cost across all agents sorted by spend."""
    Entitlements().require(Feature.COST_ORG_SUMMARY, context="org-wide cost summary")
    since_iso = _since_from_date(since, days)
    trackers = discover_agent_trackers()
    if not trackers:
        console.print("[yellow]No cost data recorded yet.[/yellow]")
        console.print("Cost tracking starts automatically when governed LLM calls are made.")
        return
    summaries = [t.get_summary(since=since_iso) for t in trackers]
    _render_summary_table(summaries, days)


@cost.command("alert")
@click.option("--agent", default=None, help="Agent name to monitor")
@click.option("--threshold", type=float, default=None, help="Alert if single call exceeds USD")
@click.option("--monthly-budget", type=float, default=None, help="Alert if monthly spend exceeds USD")
def cost_alert(agent: Optional[str], threshold: Optional[float], monthly_budget: Optional[float]) -> None:
    """Configure cost alerts (terminal delivery on free tier)."""
    config = load_alert_config()
    if agent:
        agents = config.setdefault("agents", {})
        agent_cfg = agents.setdefault(agent, {})
        if threshold is not None:
            agent_cfg["single_call_threshold_usd"] = threshold
        if monthly_budget is not None:
            agent_cfg["monthly_budget_usd"] = monthly_budget
        save_alert_config(config)
        console.print(f"[green]✓ Alert config saved for {agent}[/green]")
        console.print(f"Config: {ALERTS_PATH}")

    config = load_alert_config()
    if not config.get("agents"):
        console.print("[yellow]No alert rules configured.[/yellow]")
        console.print("Example: iris cost alert --agent my-agent --threshold 1.00 --monthly-budget 50")
        return

    since_iso = _since_from_days(30)
    for agent_name, rules in config.get("agents", {}).items():
        tracker = _find_tracker(agent_name)
        if not tracker:
            continue
        summary = tracker.get_summary(since=since_iso)
        if rules.get("monthly_budget_usd") and summary.estimated_monthly_cost > rules["monthly_budget_usd"]:
            console.print(
                f"[red]⚠ BUDGET ALERT[/red] {agent_name}: "
                f"estimated monthly {_format_usd(summary.estimated_monthly_cost)} "
                f"exceeds budget {_format_usd(rules['monthly_budget_usd'])}"
            )
        call_threshold = rules.get("single_call_threshold_usd")
        if call_threshold:
            for entry in tracker.get_entries(since=since_iso):
                if entry.cost_usd > call_threshold:
                    console.print(
                        f"[red]⚠ CALL ALERT[/red] {agent_name}: "
                        f"{entry.tool_name}() cost {_format_usd(entry.cost_usd)} "
                        f"at {entry.timestamp[:16]}"
                    )


@cost.command("optimize")
@click.option("--agent", required=True, help="Agent name to analyze")
@click.option("--days", default=30, type=int, help="Analysis period in days")
def cost_optimize(agent: str, days: int) -> None:
    """Suggest cost optimizations without modifying any code or config."""
    since_iso = _since_from_days(days)
    tracker = _find_tracker(agent)
    if not tracker:
        console.print(f"[yellow]No cost data found for agent '{agent}'.[/yellow]")
        sys.exit(1)

    summary = tracker.get_summary(since=since_iso)
    console.print(f"\n[bold]IRIS Cost Optimization — {summary.agent_name}[/bold]\n")
    suggestions = _suggest_optimizations(summary, since_iso)
    if not suggestions:
        console.print("[green]No optimization opportunities identified.[/green]")
        return
    for block in suggestions:
        console.print(block)
        console.print("")


@cost.command("pricing")
@click.option("--provider", default=None, help="Filter pricing by provider")
@click.option("--update", is_flag=True, help="Show pricing override instructions")
def cost_pricing(provider: Optional[str], update: bool) -> None:
    """Show current LLM pricing table and custom override options."""
    registry = PricingRegistry()
    pricing = registry.all_pricing()

    if update:
        console.print(
            Panel(
                "Custom pricing overrides are stored in:\n"
                f"  {overrides_path()}\n\n"
                "Format:\n"
                "  pricing:\n"
                '    "openai/gpt-4o":\n'
                "      input_per_1m: 2.50\n"
                "      output_per_1m: 10.00\n\n"
                "Overrides always take precedence over the built-in table.",
                title="Pricing Overrides",
                style="blue",
            )
        )
        return

    table = Table(title="IRIS LLM Pricing (per 1M tokens)", show_header=True, header_style="bold")
    table.add_column("Model")
    table.add_column("Input", justify="right")
    table.add_column("Output", justify="right")

    combined = {**DEFAULT_PRICING, **pricing}
    for model_key in sorted(combined):
        if provider and not model_key.startswith(f"{provider.lower()}/"):
            continue
        input_price, output_price = combined[model_key]
        table.add_row(model_key, f"${input_price:.3f}", f"${output_price:.3f}")

    console.print(table)
    console.print(f"\n[dim]Overrides: {overrides_path()}[/dim]")
