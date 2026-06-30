"""
iris policy diff — show Cedar rule changes before compiling.

Fully offline by default: compares policy.cedar on disk against a cached
policy-draft.cedar produced by the developer's last compile/dry-run.

To refresh the draft (uses the developer's own LLM key):
  iris policy compile --agent <name> --dry-run
"""

from __future__ import annotations

import json
import subprocess
import click
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from iris_cli.cedar_parser import (
    CedarDiff,
    CedarRule,
    _environment_scope,
    diff_cedar,
    parse_cedar,
    summarize_diffs,
)
from iris_cli.policy_cache import DraftCacheStatus, check_draft_cache, load_cached_draft


@dataclass
class PolicyDiffResult:
    agent: str
    diffs: List[CedarDiff]
    summary: dict
    compare_label: str = "policy.cedar → policy-draft.cedar"
    old_source: str = "policy.cedar"
    new_source: str = "policy-draft.cedar"
    draft_stale: bool = False
    draft_status: Optional[DraftCacheStatus] = None


def run_policy_diff(
    agent: str,
    governance_dir: Optional[Path] = None,
    from_branch: Optional[str] = None,
    verbose: bool = False,
    draft_cedar: Optional[str] = None,
    draft_path: Optional[Path] = None,
    compile: bool = False,
) -> PolicyDiffResult:
    """
    Compare policy.cedar against a cached or explicit Cedar draft.

    Offline by default — reads policy-draft.cedar from the last compile/dry-run.
    Pass compile=True to regenerate the draft via the developer's LLM (opt-in).
    """
    gov_dir = governance_dir or Path.cwd() / "governance" / "agents" / agent
    passport_file = gov_dir / "passport.yaml"
    intent_file = gov_dir / "policy-intent.md"
    cedar_file = gov_dir / "policy.cedar"

    if not passport_file.exists():
        raise FileNotFoundError(f"Passport not found: {passport_file}")
    if not intent_file.exists():
        raise FileNotFoundError(f"Intent file not found: {intent_file}")

    intent_text = intent_file.read_text()
    draft_status = check_draft_cache(gov_dir, intent_text)

    if from_branch:
        old_cedar = _load_cedar_from_git(gov_dir, from_branch, agent)
        compare_label = f"Current: policy.cedar@{from_branch}  →  Draft: compiled from intent"
        old_source = f"policy.cedar@{from_branch}"
    elif cedar_file.exists():
        old_cedar = cedar_file.read_text()
        compare_label = "Current: policy.cedar  →  Draft: compiled from intent"
        old_source = "policy.cedar"
    else:
        old_cedar = ""
        compare_label = "Current: (none)  →  Draft: compiled from intent"
        old_source = "(none)"

    if draft_cedar is not None:
        new_cedar = draft_cedar
        new_source = "injected draft"
    elif draft_path is not None:
        if not draft_path.exists():
            raise FileNotFoundError(f"Draft file not found: {draft_path}")
        new_cedar = draft_path.read_text()
        new_source = str(draft_path)
    elif compile:
        new_cedar = _compile_draft(gov_dir, intent_text)
        draft_status = check_draft_cache(gov_dir, intent_text)
        new_source = "policy-draft.cedar (just compiled)"
    else:
        new_cedar, draft_status = load_cached_draft(gov_dir, intent_text)
        new_source = "policy-draft.cedar"

    old_rules = parse_cedar(old_cedar)
    new_rules = parse_cedar(new_cedar)
    diffs = diff_cedar(old_rules, new_rules)

    if not verbose:
        diffs = [d for d in diffs if d.status != "UNCHANGED"]

    summary = summarize_diffs(diff_cedar(old_rules, new_rules))

    return PolicyDiffResult(
        agent=agent,
        diffs=diffs,
        summary=summary,
        compare_label=compare_label,
        old_source=old_source,
        new_source=new_source,
        draft_stale=draft_status.is_stale if draft_status else False,
        draft_status=draft_status,
    )


def _compile_draft(gov_dir: Path, intent_text: str) -> str:
    from iris_core.models.passport import AgentPassport

    from iris_cli.compiler_config import compiler_info, create_policy_compiler
    from iris_cli.policy_cache import save_policy_draft

    passport = AgentPassport.from_yaml((gov_dir / "passport.yaml").read_text())
    compiler = create_policy_compiler()
    result = compiler.compile(intent_text, passport, dry_run=True)
    if not result.cedar_policy:
        raise RuntimeError(
            "Policy compiler returned empty Cedar.\n"
            "Set ANTHROPIC_API_KEY or OPENAI_API_KEY, or configure ~/.iris/config.yaml"
        )
    backend, model = compiler_info(compiler)
    save_policy_draft(gov_dir, intent_text, result.cedar_policy, backend, model)
    return result.cedar_policy


def _load_cedar_from_git(gov_dir: Path, branch: str, agent: str) -> str:
    rel = f"governance/agents/{agent}/policy.cedar"
    cwd = gov_dir
    while cwd != cwd.parent:
        if (cwd / ".git").exists():
            break
        cwd = cwd.parent
    else:
        cwd = Path.cwd()

    try:
        result = subprocess.run(
            ["git", "show", f"{branch}:{rel}"],
            capture_output=True,
            text=True,
            check=True,
            cwd=cwd,
        )
        return result.stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        cedar_file = gov_dir / "policy.cedar"
        if cedar_file.exists():
            return cedar_file.read_text()
        return ""


def _print_diff_entry(console, diff: CedarDiff) -> None:
    refs = ", ".join(f"[{r}]" for r in diff.compliance_affected) or "[—]"
    rule = diff.new_rule or diff.old_rule
    english = rule.plain_english if rule else ""

    if diff.status == "ADDED":
        console.print(f"\nADDED    {refs} {english}")
    elif diff.status == "REMOVED":
        console.print(f"\nREMOVED  {refs} {english}")
    elif diff.status == "MODIFIED":
        console.print(f"\n~ MODIFIED {refs} {_modified_summary(diff)}")
        if diff.old_rule and diff.new_rule:
            console.print(
                f"Was: {_condition_summary(diff.old_rule)}  →  "
                f"Now: {_condition_summary(diff.new_rule)}"
            )
    else:
        console.print(f"\n[dim]UNCHANGED[/dim] {refs} {english}")

    risk_color = {
        "INCREASED": "red",
        "DECREASED": "green",
        "NEUTRAL": "yellow",
    }.get(diff.risk_delta, "white")
    console.print(
        f"Risk: [{risk_color}]{diff.risk_delta}[/{risk_color}] — {diff.risk_reason}"
    )


def _modified_summary(diff: CedarDiff) -> str:
    if not diff.old_rule or not diff.new_rule:
        return diff.new_rule.plain_english if diff.new_rule else ""
    old_env = _environment_scope(diff.old_rule)
    new_env = _environment_scope(diff.new_rule)
    resource = _resource_label(diff.new_rule)
    if old_env != new_env:
        return f"{resource} now restricted to {new_env} only"
    return diff.new_rule.plain_english


def _resource_label(rule: CedarRule) -> str:
    quoted = __import__("re").search(r'"([^"]+)"', rule.resource)
    if quoted:
        name = quoted.group(1).replace("-", " ")
        if "API" in rule.resource:
            return f"{name.title()} API"
        return name.title()
    return "Resource"


def _condition_summary(rule: CedarRule) -> str:
    scope = _environment_scope(rule)
    if scope != "unspecified scope":
        return scope
    if rule.conditions:
        return f"{len(rule.conditions)} condition(s)"
    return "no conditions"


def _print_compliance_impact(console, result: PolicyDiffResult) -> None:
    summary = result.summary
    if not any(d.status != "UNCHANGED" for d in result.diffs):
        return

    console.print("\n[bold]Compliance impact:[/bold]")
    if summary["violations_opened"] == 0:
        console.print("[green]✓ No new violations opened[/green]")
    else:
        console.print(
            f"[red]✗ {summary['violations_opened']} change(s) may open compliance gaps[/red]"
        )

    if summary["violations_closed"] > 0:
        console.print(
            f"[green]✓ {summary['violations_closed']} change(s) reduced compliance risk[/green]"
        )

    for ref, count in sorted(result.summary["coverage_strengthened"].items()):
        if count == 1:
            console.print(f"[green]✓ {ref} coverage strengthened[/green]")
        else:
            console.print(
                f"[green]✓ {ref} coverage strengthened in {count} rule(s)[/green]"
            )


def _print_draft_notice(console, result: PolicyDiffResult) -> None:
    if result.draft_stale:
        console.print(
            "\n[yellow]⚠ policy-intent.md changed since the cached draft was compiled.[/yellow]"
        )
        console.print(
            f'[yellow]Refresh the draft:[/yellow] '
            f'[bold]iris policy compile --agent {result.agent} --dry-run[/bold]'
        )
        if result.draft_status and result.draft_status.meta:
            meta = result.draft_status.meta
            console.print(
                f"[dim]Cached draft: {meta.compiled_at} "
                f"via {meta.compiler_backend}/{meta.compiler_model}[/dim]"
            )
    elif result.draft_status and result.draft_status.meta:
        meta = result.draft_status.meta
        console.print(
            f"\n[dim]Draft compiled {meta.compiled_at} "
            f"via {meta.compiler_backend}/{meta.compiler_model}[/dim]"
        )


def _print_footer(console, result: PolicyDiffResult) -> None:
    _print_draft_notice(console, result)
    if result.draft_stale:
        console.print(
            f'\nRun "[bold]iris policy compile --agent {result.agent} --dry-run[/bold]" '
            f"to refresh the draft, then diff again."
        )
    else:
        console.print(
            f'\nRun "[bold]iris policy compile --agent {result.agent}[/bold]" '
            f"to apply these changes."
        )


def format_diff_json(result: PolicyDiffResult) -> str:
    """Machine-readable diff for CI integration."""
    payload = {
        "agent": result.agent,
        "compare": result.compare_label,
        "draft_stale": result.draft_stale,
        "summary": result.summary,
        "diffs": [
            {
                "status": d.status,
                "risk_delta": d.risk_delta,
                "risk_reason": d.risk_reason,
                "compliance_affected": d.compliance_affected,
                "plain_english": (
                    (d.new_rule or d.old_rule).plain_english
                    if (d.new_rule or d.old_rule)
                    else ""
                ),
                "old_rule": _rule_to_dict(d.old_rule),
                "new_rule": _rule_to_dict(d.new_rule),
            }
            for d in result.diffs
        ],
    }
    if result.draft_status and result.draft_status.meta:
        payload["draft_meta"] = {
            "compiled_at": result.draft_status.meta.compiled_at,
            "compiler_backend": result.draft_status.meta.compiler_backend,
            "compiler_model": result.draft_status.meta.compiler_model,
        }
    return json.dumps(payload, indent=2)


def _rule_to_dict(rule: Optional[CedarRule]) -> Optional[dict]:
    if rule is None:
        return None
    return {
        "type": rule.type,
        "principal": rule.principal,
        "action": rule.action,
        "resource": rule.resource,
        "conditions": rule.conditions,
        "compliance_refs": rule.compliance_refs,
        "plain_english": rule.plain_english,
    }


def format_diff_markdown(result: PolicyDiffResult) -> str:
    """Render diff as markdown."""
    counts = result.summary["counts"]
    lines = [
        f"# Policy diff: {result.agent}",
        "",
        f"**Comparing:** {result.compare_label}",
        "",
        (
            f"**Rules:** {counts['ADDED']} added, {counts['REMOVED']} removed, "
            f"{counts['MODIFIED']} modified, {counts['UNCHANGED']} unchanged"
        ),
        "",
    ]

    if result.draft_stale:
        lines.append(
            "> ⚠ policy-intent.md changed since the cached draft. "
            f"Run `iris policy compile --agent {result.agent} --dry-run` to refresh."
        )
        lines.append("")

    for diff in result.diffs:
        refs = ", ".join(diff.compliance_affected) or "—"
        rule = diff.new_rule or diff.old_rule
        english = rule.plain_english if rule else ""
        lines.append(f"## {diff.status} [{refs}]")
        lines.append("")
        lines.append(english)
        lines.append("")
        lines.append(f"**Risk:** {diff.risk_delta} — {diff.risk_reason}")
        lines.append("")

    lines.append("## Compliance impact")
    lines.append("")
    if result.summary["violations_opened"] == 0:
        lines.append("- ✓ No new violations opened")
    for ref, count in sorted(result.summary["coverage_strengthened"].items()):
        lines.append(f"- ✓ {ref} coverage strengthened in {count} rule(s)")

    lines.append("")
    if result.draft_stale:
        lines.append(
            f"Run `iris policy compile --agent {result.agent} --dry-run` to refresh the draft."
        )
    else:
        lines.append(f"Run `iris policy compile --agent {result.agent}` to apply these changes.")
    return "\n".join(lines)


@click.command("diff")
@click.option("--agent", required=True, help="Agent name")
@click.option("--from", "from_branch", default=None, help="Git branch for baseline policy.cedar")
@click.option("--dir", "governance_dir", type=Path, default=None)
@click.option("--draft", "draft_path", type=Path, default=None, help="Compare against this Cedar file")
@click.option(
    "--compile",
    "compile_draft",
    is_flag=True,
    help="Recompile draft via your LLM before diffing (uses your API key)",
)
@click.option(
    "--format",
    "output_format",
    default="table",
    type=click.Choice(["table", "json", "markdown"]),
)
@click.option("--verbose", is_flag=True, help="Include unchanged rules in output")
def policy_diff(
    agent,
    from_branch,
    governance_dir,
    draft_path,
    compile_draft,
    output_format,
    verbose,
):
    """
    Preview Cedar policy changes before compiling.

    Fully offline by default — compares policy.cedar against a cached
    policy-draft.cedar from your last compile/dry-run. No API calls.

    Workflow:
      1. Edit policy-intent.md
      2. iris policy compile --agent <name> --dry-run  (your LLM key)
      3. iris policy diff --agent <name>              (offline, free)

    Example:
      iris policy diff --agent payment-agent
      iris policy diff --agent payment-agent --format json
      iris policy diff --agent payment-agent --compile
    """
    from rich.console import Console
    from rich.panel import Panel

    console = Console()

    try:
        result = run_policy_diff(
            agent=agent,
            governance_dir=governance_dir,
            from_branch=from_branch,
            verbose=verbose,
            draft_path=draft_path,
            compile=compile_draft,
        )
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise SystemExit(1)
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/red]")
        raise SystemExit(1)

    if output_format == "json":
        click.echo(format_diff_json(result))
    elif output_format == "markdown":
        click.echo(format_diff_markdown(result))
    else:
        counts = result.summary["counts"]
        header = (
            f"Current: {result.old_source}  →  Draft: compiled from intent\n"
            f"Changes: {counts['ADDED']} added, {counts['REMOVED']} removed, "
            f"{counts['MODIFIED']} modified, {counts['UNCHANGED']} unchanged"
        )
        console.print(Panel(header, title=f"Policy diff: {agent}", style="blue"))

        for diff in result.diffs:
            _print_diff_entry(console, diff)

        _print_compliance_impact(console, result)
        _print_footer(console, result)
