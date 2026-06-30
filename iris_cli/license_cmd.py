"""iris license — IRIS Pro license management commands."""

from __future__ import annotations

import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from iris_core.entitlements import Entitlements, Feature, LicenseKey, Tier
from iris_core.entitlements.features import FEATURE_TIERS, TIER_RANK

console = Console()

_STATUS_BOX = """┌─ IRIS License Status ──────────────────────────────────────┐
│ Tier:    {tier:<52}│
│ Key:     {key:<52}│
│                                                             │
│ Available now (free forever):                              │
│   Colorado AI Act bundle, all LLM integrations,            │
│   Cursor MCP, local Evidence Vault (30 days),              │
│   iris scan, iris status, iris framework suggest           │
│                                                             │
│ Unlock with Pro:                                           │
│   NIST AI RMF, FedRAMP, HIPAA, SOC 2, GDPR, EU AI Act    │
│   Unlimited Evidence Vault + cloud sync + PDF export       │
│   K8s sidecar, HITL gate, SCM org scanner                 │
│   Team RBAC, SSO, drift alerts, cost anomaly alerts        │
│                                                             │
│ Activate: iris license activate <your-key>                 │
│ Get a key: https://iris.ai/pricing                         │
└────────────────────────────────────────────────────────────┘"""


def _mask_key(key: str | None) -> str:
    if not key:
        return "Not activated"
    if len(key) <= 16:
        return key
    return f"{key[:9]}…{key[-4:]}"


def _is_test_key(key: str) -> bool:
    return key.startswith("IRIS-TEST-") or key.startswith("IRIS-DEMO-")


def _features_for_tier(tier: Tier) -> list[Feature]:
    return [
        feature
        for feature, required in FEATURE_TIERS.items()
        if TIER_RANK[tier] >= TIER_RANK[required]
    ]


def _features_exactly_tier(tier: Tier) -> list[Feature]:
    return [feature for feature, required in FEATURE_TIERS.items() if required == tier]


@click.group()
def license():
    """IRIS Pro license management."""
    pass


@license.command("status")
def license_status():
    """Show current license status, tier, and what is unlocked."""
    ents = Entitlements()
    key = ents.license_key
    tier_label = ents.tier_name()
    key_label = _mask_key(key)
    if key and not ents.license_valid:
        tier_label = f"{tier_label} (invalid key: {ents.license_reason})"
        key_label = "Invalid"

    console.print(_STATUS_BOX.format(tier=tier_label, key=key_label))


@license.command("activate")
@click.argument("key")
def license_activate(key: str):
    """Validate and save an IRIS license key."""
    key = key.strip()
    valid, tier, reason = LicenseKey.validate(key)
    if not valid:
        if reason == "dev_key_disabled":
            console.print(
                "[red]This key is for IRIS development/CI only and is not valid "
                "in production builds.[/red]\n"
                "Get a license: https://iris.ai/pricing"
            )
        else:
            console.print(
                "[red]Invalid license key format.[/red]\n"
                "Expected: IRIS-XXXX-XXXX-XXXX-XXXX (uppercase letters and digits)\n"
                "Get a key: https://iris.ai/pricing"
            )
        sys.exit(1)

    LicenseKey.save(key)
    ents = Entitlements()
    test_note = " (test key)" if _is_test_key(key) else ""
    unlocked = _features_for_tier(tier)
    newly = [f.value for f in unlocked if FEATURE_TIERS[f] == tier]
    feature_list = ", ".join(newly[:12])
    if len(newly) > 12:
        feature_list += f", … (+{len(newly) - 12} more)"

    console.print(
        Panel(
            f"[bold green]✓ License activated{test_note}[/bold green]\n\n"
            f"Tier unlocked: [cyan]{ents.tier_name()}[/cyan]\n"
            f"Saved to: {LicenseKey.license_file_path()}\n\n"
            f"Features unlocked at this tier:\n  {feature_list}",
            style="green",
        )
    )


@license.command("deactivate")
@click.confirmation_option(prompt="Remove your IRIS license key?")
def license_deactivate():
    """Remove the license key and revert to the free tier."""
    removed = LicenseKey.clear()
    if removed:
        console.print("[yellow]License deactivated.[/yellow] You are now on the Free tier.")
    else:
        console.print("[dim]No license key was stored.[/dim]")


@license.command("features")
@click.option("--tier", type=click.Choice(["free", "pro", "enterprise"]), default=None)
def license_features(tier: str | None):
    """List features by tier (comparison table by default)."""
    if tier:
        selected = Tier(tier)
        features = _features_exactly_tier(selected)
        console.print(f"\n[bold]{selected.value.title()} tier features[/bold] ({len(features)})\n")
        for feature in sorted(features, key=lambda f: f.value):
            console.print(f"  • {feature.value}")
        return

    table = Table(title="IRIS Feature Comparison")
    table.add_column("Feature", style="bold")
    table.add_column("Free")
    table.add_column("Pro")
    table.add_column("Enterprise")

    for feature in sorted(FEATURE_TIERS, key=lambda f: f.value):
        required = FEATURE_TIERS[feature]
        table.add_row(
            feature.value,
            "✓" if TIER_RANK[Tier.FREE] >= TIER_RANK[required] else "—",
            "✓" if TIER_RANK[Tier.PRO] >= TIER_RANK[required] else "—",
            "✓" if TIER_RANK[Tier.ENTERPRISE] >= TIER_RANK[required] else "—",
        )
    console.print(table)
