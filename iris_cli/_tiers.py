"""Tier checks for CLI commands: free finds the problem, paid runs the program."""

from __future__ import annotations

import sys

from rich.console import Console

from iris_core.entitlements import Entitlements, Feature

_console = Console(stderr=True)


def _ents() -> Entitlements:
    return Entitlements()


def entitled(feature: Feature) -> bool:
    return _ents().has(feature)


def require(feature: Feature, what: str) -> None:
    """Exit with a clear upgrade message when the license does not include `feature`."""
    ents = _ents()
    if ents.has(feature):
        return
    _console.print(f"[yellow]{what} is part of IRIS {_label(feature)}.[/yellow] {ents.upgrade_message(feature)}")
    _console.print("[dim]Plans and services: https://iris-security.github.io/iris-sdk/services.html[/dim]")
    sys.exit(2)


def _label(feature: Feature) -> str:
    from iris_core.entitlements.features import FEATURE_TIERS, Tier

    return {Tier.FREE: "Community", Tier.PRO: "Business", Tier.ENTERPRISE: "Enterprise"}[FEATURE_TIERS[feature]]
