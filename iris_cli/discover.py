"""Org-wide discovery CLI — iris discover org."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import List, Optional

import click

from iris_core.discovery.coordinator import DiscoveryCoordinator
from iris_core.discovery.sources import (
    CICDDiscoverySource,
    KubernetesDiscoverySource,
    MCPRegistryDiscoverySource,
    SCMDiscoverySource,
)

SOURCE_MAP = {
    "scm": SCMDiscoverySource,
    "cicd": CICDDiscoverySource,
    "k8s": KubernetesDiscoverySource,
    "mcp": MCPRegistryDiscoverySource,
}

FRAMEWORK_LABELS = {
    "langchain": "LangChain",
    "openai_sdk": "OpenAI SDK",
    "anthropic_sdk": "Anthropic SDK",
    "bedrock": "Bedrock",
    "gemini": "Gemini",
    "crewai": "CrewAI",
    "autogen": "Autogen",
    "mcp_server": "MCP Server",
    "custom": "Custom/unknown",
    "unknown": "Custom/unknown",
}


def _format_duration(seconds: float) -> str:
    minutes = int(seconds // 60)
    secs = int(seconds % 60)
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def _resolve_scm_config(org_name: str, config_file: Optional[Path]) -> dict:
    if config_file and config_file.exists():
        data = json.loads(config_file.read_text())
        scm = data.get("scm", data)
        scm.setdefault("org", org_name)
        return scm

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    config: dict = {"provider": "github", "org": org_name}
    if token:
        config["token"] = token
    if os.environ.get("IRIS_DISCOVERY_REPOS"):
        config["repos"] = json.loads(os.environ["IRIS_DISCOVERY_REPOS"])
    return config


def _build_configs(
    source_names: List[str],
    org_name: str,
    config_file: Optional[Path],
) -> dict:
    configs: dict = {}
    if config_file and config_file.exists():
        all_cfg = json.loads(config_file.read_text())
    else:
        all_cfg = {}

    if "scm" in source_names:
        configs["scm_repo"] = all_cfg.get("scm", _resolve_scm_config(org_name, config_file))
        configs["scm_repo"].setdefault("org", org_name)

    if "cicd" in source_names:
        cicd = all_cfg.get("cicd", {})
        if configs.get("scm_repo", {}).get("repos"):
            cicd["repos"] = configs["scm_repo"]["repos"]
        configs["cicd_pipeline"] = cicd

    if "k8s" in source_names:
        k8s = all_cfg.get("k8s", {})
        kubeconfig = os.environ.get("KUBECONFIG")
        if kubeconfig:
            k8s.setdefault("kubeconfig", kubeconfig)
        configs["k8s_workload"] = k8s

    if "mcp" in source_names:
        configs["mcp_registry"] = all_cfg.get("mcp", {})

    return configs


def render_org_discovery_report(inventory, duration_seconds: float) -> str:
    """Render CLI output matching the Brownfield demo format."""
    lines: List[str] = []
    org = inventory.org_id

    repos = 0
    pipelines = 0
    clusters = 0
    for src in inventory.sources_scanned:
        if src.get("source_type") == "scm_repo":
            repos = src.get("repos_scanned", repos)
        elif src.get("source_type") == "cicd_pipeline":
            pipelines = src.get("findings_count", pipelines)
        elif src.get("source_type") == "k8s_workload":
            clusters = src.get("clusters_scanned", 1 if src.get("status") == "complete" else 0)

    cicd_count = sum(
        1
        for a in inventory.agents
        if a.source_type == "cicd_pipeline" and a.confidence == "certain"
    )
    if pipelines == 0 and cicd_count:
        pipelines = cicd_count

    lines.append(f"IRIS Org Discovery — {org}")
    lines.append(
        f"Scanned: {repos} repos, {pipelines} CI/CD pipelines, {clusters} K8s clusters"
    )
    lines.append(
        f"Duration: {_format_duration(duration_seconds)}, Status: {inventory.status}"
    )
    lines.append("")
    lines.append(f"Found {inventory.total_agents} agents across your organization.")
    lines.append(
        f"{inventory.ungoverned_count} are ungoverned — no IRIS policy, no audit trail."
    )
    lines.append("")
    lines.append("By framework:")

    ungoverned_by_fw = inventory.ungoverned_by_framework()
    fw_counts = inventory.by_framework
    sorted_fw = sorted(
        fw_counts.keys(),
        key=lambda k: fw_counts[k],
        reverse=True,
    )
    for fw in sorted_fw:
        label = FRAMEWORK_LABELS.get(fw, fw.replace("_", " ").title())
        total = fw_counts[fw]
        ungov = ungoverned_by_fw.get(fw, 0)
        lines.append(f"  {label:<18} {total:>4}   ({ungov} ungoverned)")

    prod_unowned = inventory.ungoverned_production_without_owner()
    if prod_unowned:
        lines.append("")
        lines.append(
            f"{prod_unowned} ungoverned agents are in PRODUCTION with no owner on record."
        )

    lines.append("Run: iris discover org --report for the full inventory.")
    return "\n".join(lines)


@click.group()
def discover():
    """Org-wide AI agent discovery across SCM, CI/CD, Kubernetes, and MCP."""
    pass


@discover.command("org")
@click.option(
    "--sources",
    default="scm,cicd,k8s,mcp",
    show_default=True,
    help="Comma-separated discovery sources",
)
@click.option("--org-name", required=True, help="Organization identifier for this scan")
@click.option(
    "--config",
    "config_file",
    type=click.Path(exists=False, path_type=Path),
    default=None,
    help="JSON config file with source credentials and repo fixtures",
)
@click.option("--report", is_flag=True, help="Output full JSON inventory")
@click.option(
    "--vault-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Evidence vault directory for scan results",
)
def discover_org(sources: str, org_name: str, config_file: Optional[Path], report: bool, vault_dir: Optional[Path]):
    """
    Scan your organization for AI agents across all configured surfaces.

    Example:
      iris discover org --sources scm --org-name acme-corp
    """
    source_names = [s.strip() for s in sources.split(",") if s.strip()]
    unknown = set(source_names) - set(SOURCE_MAP)
    if unknown:
        raise click.ClickException(f"Unknown sources: {', '.join(sorted(unknown))}")

    if not config_file and not os.environ.get("GITHUB_TOKEN") and "scm" in source_names:
        if not os.environ.get("IRIS_DISCOVERY_REPOS"):
            token = click.prompt("GitHub token (contents:read)", hide_input=True, default="", show_default=False)
            if token:
                os.environ["GITHUB_TOKEN"] = token
            org_name = click.prompt("GitHub organization name", default=org_name)

    configs = _build_configs(source_names, org_name, config_file)
    instances = [SOURCE_MAP[name]() for name in source_names]
    coordinator = DiscoveryCoordinator(vault_dir=vault_dir)

    start = time.monotonic()
    inventory = coordinator.run_scan_sync(org_name, instances, configs)
    duration = time.monotonic() - start

    if report:
        payload = inventory.to_dict()
        payload["duration_seconds"] = duration
        click.echo(json.dumps(payload, indent=2))
    else:
        click.echo(render_org_discovery_report(inventory, duration))
