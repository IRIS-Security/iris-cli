"""iris quickstart — zero-friction first-run demo for new developers."""

from __future__ import annotations

import importlib.metadata
import os
import re
import shutil
import time
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.panel import Panel

from iris_cli.framework_suggest import (
    Q1_CHOICES,
    Q2_CHOICES,
    Q4_CHOICES,
    Q8_CHOICES,
    _render_table,
    _save_recommendations,
    build_recommendations,
)
from iris_core.cli_timing.instrument import timed_cli_command

console = Console()

AGENT_NAME = "quickstart-loan-processor"
REGISTER_OWNER = "quickstart@iris.ai"
REGISTER_TEAM = "demo"

SAMPLE_AGENT_CONTENT = '''from anthropic import Anthropic
import os

# Sample agent — ungoverned (IRIS will find this)
client = Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

def answer_customer_question(question: str, customer_id: str) -> str:
    """Answer a customer question using Claude."""
    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        messages=[{"role": "user", "content": question}]
    )
    return message.content[0].text

def process_loan_application(applicant_id: str, amount: float) -> dict:
    """Process a loan application — high-risk AI decision."""
    # No governance, no consent gate, no audit trail
    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=512,
        messages=[{
            "role": "user",
            "content": f"Approve or deny loan of ${amount} for {applicant_id}"
        }]
    )
    return {"decision": response.content[0].text}
'''

STATIC_CEDAR_EXAMPLE = """permit(
  principal == iris::Agent::"quickstart-loan-processor",
  action == iris::Action::"call",
  resource == iris::API::"anthropic-api"
) when {
  context.data_classification == "pii" &&
  context.user_consent_logged == true &&
  context.environment != "production" ||
  context.is_high_risk_approved == true
};"""


def quickstart_dir() -> Path:
    return Path.home() / ".iris" / "quickstart"


def governance_agents_dir() -> Path:
    return quickstart_dir() / "governance" / "agents"


def sample_agent_path() -> Path:
    return quickstart_dir() / "sample_agent.py"


def iris_version() -> str:
    try:
        return importlib.metadata.version("iris-security-cli")
    except Exception:
        return "0.1.7"


def has_llm_api_key() -> bool:
    return any(
        os.environ.get(key)
        for key in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY")
    )


def analyze_sample_agents(path: Path) -> list[dict[str, Any]]:
    """Return function-level ungoverned agent findings for the quickstart sample."""
    if not path.exists():
        return []

    content = path.read_text(encoding="utf-8")
    findings: list[dict[str, Any]] = []
    rel_file = path.name

    for match in re.finditer(r"^def\s+(\w+)\s*\(", content, re.MULTILINE):
        func_name = match.group(1)
        line_number = content[: match.start()].count("\n") + 1
        next_def = re.search(r"^def\s+\w+", content[match.end() :], re.MULTILINE)
        func_end = match.end() + next_def.start() if next_def else len(content)
        func_body = content[match.start() : func_end]

        if "messages.create" not in func_body:
            continue

        if "loan" in func_name.lower() or "loan" in func_body.lower():
            risk = "HIGH"
            reason = "Loan decision is a high-risk consequential decision"
        else:
            risk = "MEDIUM"
            reason = ""

        findings.append(
            {
                "file_path": rel_file,
                "line_number": line_number,
                "func_name": func_name,
                "risk_level": risk,
                "risk_reason": reason,
            }
        )

    findings.sort(key=lambda item: (0 if item["risk_level"] == "HIGH" else 1, item["line_number"]))
    return findings


def create_workspace() -> Path:
    root = quickstart_dir()
    root.mkdir(parents=True, exist_ok=True)
    sample_agent_path().write_text(SAMPLE_AGENT_CONTENT, encoding="utf-8")
    return root


def clean_workspace() -> None:
    root = quickstart_dir()
    if root.exists():
        shutil.rmtree(root)


def _pause(interactive: bool) -> None:
    if interactive:
        click.pause(info="Press Enter to continue...")


def _print_welcome() -> None:
    version = iris_version()
    console.print(
        Panel(
            "[bold]AI Agent Governance Platform[/bold]\n"
            f"Version {version} · Free tier\n\n"
            "This quickstart takes 2 minutes and shows you:\n"
            "  · How IRIS finds ungoverned agents\n"
            "  · How to register and govern a new agent\n"
            "  · Your compliance score in real time\n\n"
            "No API key required for most steps.\n"
            "github.com/gimartinb/iris-sdk",
            title="Welcome to IRIS",
            style="blue",
        )
    )


def _print_scan_results(findings: list[dict[str, Any]], scan_root: Path) -> None:
    console.print(f"\n→ Scanning [cyan]{scan_root}[/cyan] for ungoverned AI agents...\n")
    time.sleep(1)
    console.print(f"Found {len(findings)} ungoverned agents:\n")

    for finding in findings:
        risk = finding["risk_level"]
        risk_style = "red" if risk == "HIGH" else "yellow"
        func_label = f"{finding['file_path']}:{finding['line_number']}  {finding['func_name']}()"
        console.print(f"[{risk_style}]{risk:<9}[/{risk_style}]  {func_label}")
        console.print("           Pattern: Anthropic SDK without IRIS governance")
        if finding["risk_reason"]:
            console.print(f"           Reason:  {finding['risk_reason']}")
        console.print("           Fix:     Replace client = Anthropic() with IrisAnthropic()")
        console.print()


def _register_quickstart_agent() -> Path:
    from iris import IrisAgent

    agent_dir = governance_agents_dir() / AGENT_NAME
    agent_dir.mkdir(parents=True, exist_ok=True)

    console.print("\n→ Registering loan-processor agent...")
    console.print(
        f"[dim]$ iris register --name {AGENT_NAME} "
        f"--owner {REGISTER_OWNER} --team {REGISTER_TEAM} "
        "--compliance colorado-ai-act --high-risk[/dim]\n"
    )

    agent = IrisAgent(
        name=AGENT_NAME,
        owner=REGISTER_OWNER,
        team=REGISTER_TEAM,
        compliance=["colorado-ai-act"],
        environments=["dev"],
        is_high_risk_ai=True,
        policy_dir=agent_dir,
    )
    (agent_dir / "passport.yaml").write_text(agent.passport.to_yaml())

    intent_template = f"""# Policy Intent — {AGENT_NAME}

> Edit this file to describe what your agent is allowed to do.
> Then run: iris policy compile --agent {AGENT_NAME}

## What this agent does
Processes loan applications and answers customer questions for a financial services demo.

## What it is allowed to access
Anthropic Claude API for loan decision support and customer Q&A.

## What it must never do
Approve loans without human review in production.

## Compliance notes
Colorado AI Act high-risk loan decisioning demo agent.
"""
    (agent_dir / "policy-intent.md").write_text(intent_template)

    console.print(
        Panel(
            f"[bold green]✓ Agent registered[/bold green]\n\n"
            f"Name: [cyan]{AGENT_NAME}[/cyan]\n"
            f"Passport: {agent_dir / 'passport.yaml'}\n"
            f"Intent template: {agent_dir / 'policy-intent.md'}",
            style="green",
        )
    )
    return agent_dir


def _invoke_click_command(command: click.Command, **kwargs: Any) -> None:
    from iris_cli.main import cli

    ctx = click.Context(command)
    ctx.parent = click.Context(cli)
    try:
        with console.capture() as capture:
            ctx.invoke(command, **kwargs)
        output = capture.get().strip()
        if output:
            console.print(output)
    except SystemExit:
        output = capture.get().strip()
        if output:
            console.print(output)


def _run_compliance_check() -> None:
    from iris_cli.compliance_check_cmd import compliance_check_cmd

    console.print("\n→ Checking Colorado AI Act compliance...")
    console.print(
        "[dim]$ iris compliance check --framework colorado-ai-act "
        f"--dir {governance_agents_dir()}[/dim]\n"
    )
    _invoke_click_command(
        compliance_check_cmd,
        agent=None,
        framework="colorado-ai-act",
        governance_dir=governance_agents_dir(),
    )


def _run_framework_suggest() -> None:
    console.print("\n→ Which regulations apply to a loan processing agent?")
    console.print("[dim]$ iris framework suggest[/dim]\n")

    answers = {
        "q1": Q1_CHOICES[0],
        "q2": Q2_CHOICES[3],
        "q3": "On-premises / private cloud",
        "q4": Q4_CHOICES[1],
        "q5": True,
        "q6": False,
        "q7": [],
        "q8": [Q8_CHOICES[0]],
        "agent_description": "loan processing agent for financial services customers",
    }
    recommendations = build_recommendations(answers)
    _render_table(recommendations)
    save_path = _save_recommendations(AGENT_NAME, answers, recommendations)
    console.print(f"\n[dim]Saved recommendations: {save_path}[/dim]")


def _run_status() -> None:
    from iris_cli.status_cmd import status_cmd

    console.print("\n→ Your governance dashboard:")
    console.print(f"[dim]$ iris status --dir {governance_agents_dir()}[/dim]\n")
    _invoke_click_command(
        status_cmd,
        agent=None,
        governance_dir=governance_agents_dir(),
        include_demo=False,
    )


def _show_static_policy_compile() -> None:
    console.print("\n→ What iris policy compile would generate:")
    console.print(
        "[dim](Requires ANTHROPIC_API_KEY, OPENAI_API_KEY, or GOOGLE_API_KEY)[/dim]\n"
    )
    console.print("Example Cedar policy for a loan processor:")
    console.print(STATIC_CEDAR_EXAMPLE)
    console.print(
        "\nSet an API key and run:\n"
        f"  [cyan]iris policy compile --agent {AGENT_NAME}[/cyan]"
    )


def _run_policy_compile() -> None:
    from iris_cli.main import policy_compile

    console.print("\n→ Compiling policy from natural language intent...")
    console.print(
        f"[dim]$ iris policy compile --agent {AGENT_NAME} "
        f"--dir {governance_agents_dir() / AGENT_NAME}[/dim]\n"
    )
    _invoke_click_command(
        policy_compile,
        agent=AGENT_NAME,
        intent=None,
        governance_dir=governance_agents_dir() / AGENT_NAME,
        dry_run=False,
        backend=None,
        litellm_model=None,
        model=None,
    )


def _print_summary(findings_count: int) -> None:
    console.print(
        Panel(
            "\nWhat you just did:\n"
            f"  ✓ Found {findings_count} ungoverned agents in a sample codebase\n"
            "  ✓ Registered a loan processor with AgentPassport\n"
            "  ✓ Ran Colorado AI Act compliance check\n"
            "  ✓ Got your framework recommendations\n\n"
            "Next steps:\n"
            "  1. Point IRIS at your own codebase:\n"
            "     [cyan]iris scan --discover --dir /path/to/your/project[/cyan]\n\n"
            "  2. Register your own agent:\n"
            "     [cyan]iris register --name my-agent --compliance colorado-ai-act[/cyan]\n\n"
            "  3. Add IRIS to your code (one line):\n"
            "     [cyan]from iris_anthropic import IrisAnthropic[/cyan]\n"
            "     [cyan]client = IrisAnthropic(passport=passport)[/cyan]\n\n"
            "  4. Read the full guide:\n"
            "     github.com/gimartinb/iris-sdk/blob/main/QUICKSTART.md\n\n"
            "Questions? gilbert.martin@gmail.com",
            title="Quickstart complete",
            style="green",
        )
    )


def run_quickstart(*, interactive: bool = False, skip_compile: bool = False, clean: bool = False) -> int:
    if clean:
        clean_workspace()

    create_workspace()
    scan_root = quickstart_dir()
    findings = analyze_sample_agents(sample_agent_path())

    _print_welcome()
    _pause(interactive)

    console.print(f"\n→ Creating quickstart workspace at [cyan]{scan_root}[/cyan]")
    _pause(interactive)

    _print_scan_results(findings, scan_root)
    _pause(interactive)

    _register_quickstart_agent()
    _pause(interactive)

    _run_compliance_check()
    _pause(interactive)

    _run_framework_suggest()
    _pause(interactive)

    _run_status()
    _pause(interactive)

    if skip_compile or not has_llm_api_key():
        _show_static_policy_compile()
    else:
        _run_policy_compile()
    _pause(interactive)

    _print_summary(len(findings))
    return 0


@click.command("quickstart")
@click.option("--interactive", is_flag=True, help="Pause between steps for a guided walkthrough")
@click.option("--skip-compile", is_flag=True, help="Show example Cedar output instead of compiling policy")
@click.option("--clean", is_flag=True, help="Remove the quickstart workspace and run from scratch")
@timed_cli_command("iris quickstart")
def quickstart_cmd(interactive: bool, skip_compile: bool, clean: bool) -> None:
    """Set up a demo workspace and walk through IRIS in under two minutes."""
    try:
        code = run_quickstart(interactive=interactive, skip_compile=skip_compile, clean=clean)
    except KeyboardInterrupt:
        console.print("\n[yellow]Quickstart cancelled.[/yellow]")
        raise SystemExit(130) from None
    raise SystemExit(code)
