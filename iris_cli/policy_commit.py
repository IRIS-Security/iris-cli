# Copyright 2024-2025 Gilbert Martin / IRIS Security, Inc.
# All Rights Reserved. Proprietary and Confidential.
# Author:

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from iris_cli.policy_cache import clear_policy_draft, draft_paths, load_draft_meta
from iris_cli.policy_diff import run_policy_diff

console = Console()


def _agent_dir(agent: str, governance_dir: Optional[Path]) -> Path:
    if governance_dir and (governance_dir / "passport.yaml").exists():
        return governance_dir
    return governance_dir or Path.cwd() / "governance" / "agents" / agent


def _changelog_path(gov_dir: Path) -> Path:
    agents_root = gov_dir.parent
    if agents_root.name == "agents":
        return agents_root.parent / "CHANGELOG.md"
    return Path.cwd() / "governance" / "CHANGELOG.md"


def _append_changelog(
    changelog: Path,
    agent: str,
    message: str,
    backend: str,
    model: str,
    line_count: int,
) -> None:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    entry = (
        f"\n## {timestamp} — {agent}\n"
        f"{message}\n"
        f"Backend: {backend} / {model}\n"
        f"Lines: {line_count}\n"
    )
    if changelog.exists():
        changelog.write_text(changelog.read_text() + entry)
    else:
        changelog.parent.mkdir(parents=True, exist_ok=True)
        changelog.write_text(f"# IRIS Governance Changelog\n{entry}")


@click.command("commit")
@click.option("--agent", required=True, help="Agent name")
@click.option("--dir", "governance_dir", type=Path, default=None)
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
@click.option(
    "--message",
    "-m",
    default=None,
    help="Commit message for the governance changelog",
)
def policy_commit(agent, governance_dir, yes, message):
    """
    Commit the compiled policy draft to governance directory.

    Moves the cached draft from iris policy compile into
    the official policy.cedar file and logs the change.

    Run iris policy compile first to generate a draft, then
    iris policy commit to apply it.

    Examples:
      iris policy commit --agent payment-agent
      iris policy commit --agent payment-agent -y -m "Restrict S3 to read-only"
    """
    gov_dir = _agent_dir(agent, governance_dir)
    draft_file, _ = draft_paths(gov_dir)

    if not draft_file.exists():
        console.print(
            f"[red]No draft found. Run: iris policy compile --agent {agent}[/red]"
        )
        raise SystemExit(1)

    draft_content = draft_file.read_text()
    meta = load_draft_meta(gov_dir)
    backend = meta.compiler_backend if meta else "unknown"
    model = meta.compiler_model if meta else "unknown"

    try:
        result = run_policy_diff(agent=agent, governance_dir=gov_dir)
    except FileNotFoundError:
        result = None

    if result and result.diffs:
        from iris_cli.policy_diff import _print_diff_entry

        console.print(f"\n[bold]Policy changes for {agent}:[/bold]")
        for diff in result.diffs:
            _print_diff_entry(console, diff)

    if not yes:
        if not click.confirm("Apply this policy?", default=False):
            console.print("[yellow]Commit cancelled.[/yellow]")
            raise SystemExit(0)

    cedar_file = gov_dir / "policy.cedar"
    cedar_file.parent.mkdir(parents=True, exist_ok=True)
    cedar_file.write_text(draft_content)

    commit_message = message or "Policy updated via iris policy commit"
    line_count = len(draft_content.splitlines())
    _append_changelog(
        _changelog_path(gov_dir),
        agent,
        commit_message,
        backend,
        model,
        line_count,
    )

    clear_policy_draft(gov_dir)

    rel_path = f"governance/agents/{agent}/policy.cedar"
    console.print(f"[bold green]✓ Policy committed: {rel_path}[/bold green]")
    console.print(f"  Run: iris enforce --agent {agent} to verify enforcement")
