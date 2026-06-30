"""iris models — list model tiers, export controls, and active directives."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from iris_core.models.directives import DirectiveRegistry
from iris_core.models.governance_paths import find_governance_root
from iris_core.models.model_registry import ModelRegistry, ModelTier

console = Console()


def _gov_root(governance_dir: Optional[Path]) -> Path:
    return governance_dir or find_governance_root()


@click.group()
def models():
    """Model capability registry and export-control directives."""
    pass


@models.command("list")
@click.option("--dir", "governance_dir", type=click.Path(path_type=Path), default=None)
@click.option(
    "--tier",
    type=click.Choice([t.value for t in ModelTier]),
    default=None,
    help="Filter by model tier",
)
@click.option("--format", "output_format", type=click.Choice(["table", "json"]), default="table")
def models_list(governance_dir: Optional[Path], tier: Optional[str], output_format: str):
    """List models in the capability registry."""
    registry = ModelRegistry.load(_gov_root(governance_dir))
    tier_filter = ModelTier(tier) if tier else None
    items = registry.list_models(tier=tier_filter)

    if output_format == "json":
        click.echo(
            json.dumps(
                {
                    "source": str(registry.source_path) if registry.source_path else None,
                    "models": [m.to_dict() | {"model_id": m.model_id} for m in items],
                },
                indent=2,
            )
        )
        return

    table = Table(title="IRIS Model Capability Registry")
    table.add_column("Model", style="bold")
    table.add_column("Tier")
    table.add_column("Export control")
    table.add_column("HITL")
    table.add_column("Fallback")
    for model in items:
        table.add_row(
            model.model_id,
            model.tier.value,
            model.export_control.value,
            "yes" if model.requires_hitl else "no",
            model.fallback_model or "—",
        )
    console.print(table)
    if registry.source_path:
        console.print(f"\n[dim]Source: {registry.source_path}[/dim]")


@models.command("directives")
@click.option("--dir", "governance_dir", type=click.Path(path_type=Path), default=None)
@click.option("--format", "output_format", type=click.Choice(["table", "json"]), default="table")
def models_directives(governance_dir: Optional[Path], output_format: str):
    """Show active model suspension directives (kill switches)."""
    directives = DirectiveRegistry.load(_gov_root(governance_dir))
    active = directives.active_directives()

    if output_format == "json":
        click.echo(
            json.dumps(
                {
                    "source": str(directives.source_path) if directives.source_path else None,
                    "directives": [d.to_dict() for d in active],
                },
                indent=2,
            )
        )
        return

    if not active:
        console.print("[green]No active model directives.[/green]")
        if directives.source_path:
            console.print(f"[dim]Watching: {directives.source_path}[/dim]")
        return

    table = Table(title="Active Model Directives")
    table.add_column("Directive", style="bold")
    table.add_column("Model")
    table.add_column("Status")
    table.add_column("Fallback")
    table.add_column("Reason")
    for directive in active:
        table.add_row(
            directive.directive_id,
            directive.model_id,
            directive.status,
            directive.fallback_model or "—",
            directive.reason[:80] + ("…" if len(directive.reason) > 80 else ""),
        )
    console.print(table)
    if directives.source_path:
        console.print(f"\n[dim]Source: {directives.source_path}[/dim]")
        console.print(
            "[dim]Edit this file and merge via PR to activate or lift a suspension.[/dim]"
        )


@models.command("reload")
@click.option("--dir", "governance_dir", type=click.Path(path_type=Path), default=None)
def models_reload(governance_dir: Optional[Path]):
    """Verify registry and directive files load successfully."""
    root = _gov_root(governance_dir)
    registry = ModelRegistry.load(root)
    directives = DirectiveRegistry.load(root)
    console.print(
        f"[green]OK[/green] — {len(registry.models)} models, "
        f"{len(directives.active_directives())} active directives"
    )
    if not registry.models:
        console.print("[yellow]Warning:[/yellow] model registry is empty", file=sys.stderr)
        raise SystemExit(1)
