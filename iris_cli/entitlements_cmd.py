"""iris entitlements — transparent feature map by tier."""

from __future__ import annotations

import click
from rich.console import Console

from iris_core.entitlements.display import build_entitlements_panel

console = Console()


@click.command("entitlements")
def entitlements_cmd() -> None:
    """Show the complete IRIS feature map — what is available at each tier."""
    console.print(build_entitlements_panel())
