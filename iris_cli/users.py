"""iris users — manage user access for governed agents."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

console = Console()


@click.group()
def users():
    """Manage which users may invoke governed agents (PRO tier RBAC)."""
    pass


@users.command("add")
@click.option("--email", required=True, help="User email address")
@click.option("--role", required=True, help="User role (e.g. developer, admin)")
@click.option("--agent", required=True, help="Agent name")
@click.option("--dir", "governance_dir", type=Path, default=None, help="Governance root directory")
def users_add(email: str, role: str, agent: str, governance_dir: Path):
    """
    Grant a user access to invoke an agent.

    Updates the agent passport allowlists and the local user registry.

    Example:
      iris users add --email alice@co.com --role developer --agent my-agent
    """
    from iris_core.rbac.registry import add_user

    try:
        entry = add_user(agent, email, role, governance_dir)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise SystemExit(1) from exc

    console.print(
        f"[bold green]✓ User added[/bold green]\n"
        f"  Email: [cyan]{entry.email}[/cyan]\n"
        f"  Role:  [cyan]{entry.role}[/cyan]\n"
        f"  Agent: [cyan]{agent}[/cyan]"
    )


@users.command("list")
@click.option("--agent", required=True, help="Agent name")
@click.option("--dir", "governance_dir", type=Path, default=None, help="Governance root directory")
def users_list(agent: str, governance_dir: Path):
    """
    List users authorized to invoke an agent.

    Example:
      iris users list --agent my-agent
    """
    from iris_core.rbac.registry import list_users

    registered = list_users(agent, governance_dir)
    if not registered:
        console.print(f"[yellow]No users registered for agent '{agent}'.[/yellow]")
        console.print(f"Add one with: iris users add --email you@co.com --role developer --agent {agent}")
        return

    table = Table(title=f"Users — {agent}")
    table.add_column("Email", style="cyan")
    table.add_column("Role", style="green")
    for user in registered:
        table.add_row(user.email, user.role)
    console.print(table)


@users.command("remove")
@click.option("--email", required=True, help="User email address")
@click.option("--agent", required=True, help="Agent name")
@click.option("--dir", "governance_dir", type=Path, default=None, help="Governance root directory")
def users_remove(email: str, agent: str, governance_dir: Path):
    """
    Revoke a user's access to invoke an agent.

    Example:
      iris users remove --email alice@co.com --agent my-agent
    """
    from iris_core.rbac.registry import remove_user

    try:
        removed = remove_user(agent, email, governance_dir)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise SystemExit(1) from exc

    if not removed:
        console.print(f"[yellow]User '{email}' not found for agent '{agent}'.[/yellow]")
        raise SystemExit(1)

    console.print(f"[bold green]✓ Removed {email} from agent '{agent}'[/bold green]")
