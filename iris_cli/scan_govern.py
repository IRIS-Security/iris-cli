"""Discovery-to-governance arc: register agents and show one-line IRIS fixes."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.panel import Panel

from iris_core.discovery.scanner import UngovernedFinding


@dataclass
class GovernChange:
    file_path: Path
    line_number: int
    original_line: str
    framework: str
    agent_name: str
    owner: str
    imports: List[str]
    passport_lines: List[str]
    replacement_line: str


LLM_DETECTORS = [
    (re.compile(r"\bChatOpenAI\s*\("), "openai", "iris_openai", "IrisOpenAI", "llm"),
    (re.compile(r"\bAzureChatOpenAI\s*\("), "openai", "iris_openai", "IrisAzureOpenAI", "llm"),
    (re.compile(r"\bChatAnthropic\s*\("), "anthropic", "iris_anthropic", "IrisAnthropic", "llm"),
    (re.compile(r"\banthropic\.Anthropic\s*\("), "anthropic", "iris_anthropic", "IrisAnthropic", "client"),
    (re.compile(r"\bopenai\.Client\s*\("), "openai", "iris_openai", "IrisOpenAI", "client"),
    (re.compile(r"\bOpenAI\s*\("), "openai", "iris_openai", "IrisOpenAI", "client"),
    (re.compile(r"\bgenai\.Client\s*\("), "gemini", "iris_gemini", "IrisGemini", "client"),
    (re.compile(r"\bGenerativeModel\s*\("), "generativeai", "iris_generativeai", "IrisGenerativeModel", "model"),
    (re.compile(r"\bAgentExecutor\s*\("), "langchain", "iris_langchain", "IrisLangChainAgent", "executor"),
    (re.compile(r"\bCrew\s*\("), "crewai", "iris_crewai", "IrisCrew", "crew"),
]


def _git_owner() -> str:
    try:
        email = subprocess.check_output(
            ["git", "config", "user.email"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        if email:
            return email
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return "platform-team@company.com"


def _unique_files(findings: List[UngovernedFinding]) -> List[UngovernedFinding]:
    seen: set[str] = set()
    result: List[UngovernedFinding] = []
    for f in sorted(findings, key=lambda x: (x.file_path, x.line_number)):
        if f.file_path in seen:
            continue
        seen.add(f.file_path)
        result.append(f)
    return result


def _detect_change(
    finding: UngovernedFinding,
    scan_dir: Path,
    owner: str,
) -> Optional[GovernChange]:
    file_path = scan_dir / finding.file_path
    if not file_path.exists():
        return None
    lines = file_path.read_text(encoding="utf-8").splitlines()
    if finding.line_number < 1 or finding.line_number > len(lines):
        return None
    line = lines[finding.line_number - 1]
    agent_name = finding.agent_name_hint

    for pattern, _fw, module, wrapper, var_name in LLM_DETECTORS:
        if not pattern.search(line):
            continue

        if wrapper == "IrisLangChainAgent":
            imports = [
                "from iris import AgentPassport, ComplianceTag",
                f"from {module} import {wrapper}",
            ]
            passport_lines = [
                f"_passport = AgentPassport(",
                f'    name="{agent_name}",',
                f'    owner="{owner}",',
                f"    compliance_tags=[ComplianceTag.COLORADO_AI_ACT],",
                f"    is_high_risk_ai=True,",
                f")",
            ]
            replacement = (
                f"governed_executor = {wrapper}.from_agent({var_name}, _passport)"
            )
            return GovernChange(
                file_path=file_path,
                line_number=finding.line_number,
                original_line=line.strip(),
                framework=finding.framework_detected,
                agent_name=agent_name,
                owner=owner,
                imports=imports,
                passport_lines=passport_lines,
                replacement_line=replacement,
            )

        if wrapper == "IrisCrew":
            imports = [
                "from iris import AgentPassport, ComplianceTag",
                f"from {module} import {wrapper}",
            ]
            passport_lines = [
                f"_passport = AgentPassport(",
                f'    name="{agent_name}",',
                f'    owner="{owner}",',
                f"    compliance_tags=[ComplianceTag.COLORADO_AI_ACT],",
                f")",
            ]
            replacement = f"governed_crew = {wrapper}({var_name}, passport=_passport)"
            return GovernChange(
                file_path=file_path,
                line_number=finding.line_number,
                original_line=line.strip(),
                framework=finding.framework_detected,
                agent_name=agent_name,
                owner=owner,
                imports=imports,
                passport_lines=passport_lines,
                replacement_line=replacement,
            )

        imports = [
            "from iris import AgentPassport, ComplianceTag",
            f"from {module} import {wrapper}",
        ]
        passport_lines = [
            f"_passport = AgentPassport(",
            f'    name="{agent_name}",',
            f'    owner="{owner}",',
            f"    compliance_tags=[ComplianceTag.COLORADO_AI_ACT],",
            f")",
        ]
        match = re.search(r"(\w+)\s*=", line)
        var = match.group(1) if match else var_name
        args_match = re.search(r"\((.*)\)", line)
        args = args_match.group(1) if args_match else ""
        if wrapper in ("IrisOpenAI", "IrisAzureOpenAI", "IrisAnthropic", "IrisGemini"):
            replacement = f"{var} = {wrapper}(passport=_passport)"
            if args and "api_key" in args:
                replacement = f"{var} = {wrapper}(passport=_passport, {args})"
        elif wrapper == "IrisGenerativeModel":
            replacement = f"{var} = IrisGenerativeAI(passport=_passport).GenerativeModel({args})"
            imports[-1] = "from iris_generativeai import IrisGenerativeAI"
        else:
            replacement = f"{var} = {wrapper}(passport=_passport)"

        return GovernChange(
            file_path=file_path,
            line_number=finding.line_number,
            original_line=line.strip(),
            framework=finding.framework_detected,
            agent_name=agent_name,
            owner=owner,
            imports=imports,
            passport_lines=passport_lines,
            replacement_line=replacement,
        )

    return None


def _print_change(console: Console, change: GovernChange) -> None:
    console.print(f"\n[bold]File:[/bold] {change.file_path}")
    console.print(f"[bold]Line {change.line_number}:[/bold]  {change.original_line}")
    console.print("\n[bold green]Change to:[/bold green]")
    line_no = 1
    for imp in change.imports:
        console.print(f"Line {line_no}:  {imp}")
        line_no += 1
    console.print("Line {0}:".format(line_no))
    line_no += 1
    for pline in change.passport_lines:
        console.print(f"Line {line_no}:  {pline}")
        line_no += 1
    console.print(f"Line {line_no}:  {change.replacement_line}")


def _register_agent(
    agent_name: str,
    owner: str,
    compliance: str,
    high_risk: bool,
) -> None:
    from iris import IrisAgent

    gov_dir = Path.cwd() / "governance" / "agents" / agent_name
    gov_dir.mkdir(parents=True, exist_ok=True)
    agent = IrisAgent(
        name=agent_name,
        owner=owner,
        team=owner.split("@")[0] if "@" in owner else "ai-platform",
        compliance=[compliance],
        is_high_risk_ai=high_risk,
        policy_dir=gov_dir,
    )
    (gov_dir / "passport.yaml").write_text(agent.passport.to_yaml())
    intent = f"""# Policy Intent — {agent_name}

## What this agent does
[Describe the agent's purpose here]

## What it is allowed to access
[List the tools, APIs, and data sources this agent needs]

## What it must never do
[List prohibited actions]

## Compliance notes
Registered via iris scan --discover --govern
"""
    (gov_dir / "policy-intent.md").write_text(intent)


def _apply_change(change: GovernChange) -> None:
    content = change.file_path.read_text(encoding="utf-8")
    lines = content.splitlines()
    idx = change.line_number - 1

    insert_block: List[str] = []
    for imp in change.imports:
        if imp not in content:
            insert_block.append(imp)
    insert_block.extend(change.passport_lines)
    insert_block.append(change.replacement_line)

    new_lines = lines[:idx] + insert_block + lines[idx + 1 :]
    change.file_path.write_text("\n".join(new_lines) + ("\n" if content.endswith("\n") else ""))


def run_govern_flow(
    findings: List[UngovernedFinding],
    scan_dir: Path,
    compliance: str,
    no_auto_apply: bool,
    govern_yes: bool,
    console: Console,
) -> None:
    unique = _unique_files(findings)
    if not unique:
        return

    count = len(unique)
    proceed = govern_yes
    if not proceed:
        if click.get_text_stream("stdin").isatty():
            console.print(
                f"\n[bold]Found {count} ungoverned agent{'s' if count != 1 else ''}.[/bold] "
                "Would you like IRIS to register them and show you the "
                "one-line change for each one?"
            )
            proceed = click.confirm("", default=True)
        else:
            proceed = True
            console.print(
                f"\n[dim]Non-interactive: showing one-line changes for "
                f"{count} ungoverned agent{'s' if count != 1 else ''}.[/dim]"
            )

    if not proceed:
        return

    owner = _git_owner()
    registered: set[str] = set()

    for finding in unique:
        change = _detect_change(finding, scan_dir, owner)
        if not change:
            console.print(
                f"[yellow]Could not generate one-liner for {finding.file_path}[/yellow]"
            )
            continue

        if change.agent_name not in registered:
            high_risk = "--high-risk" in finding.suggested_command
            passport_path = Path.cwd() / "governance" / "agents" / change.agent_name / "passport.yaml"
            if not passport_path.exists():
                _register_agent(change.agent_name, owner, compliance, high_risk)
                console.print(
                    f"[green]✓ Registered[/green] [cyan]{change.agent_name}[/cyan] "
                    f"→ governance/agents/{change.agent_name}/passport.yaml"
                )
            registered.add(change.agent_name)

        _print_change(console, change)

        if no_auto_apply:
            continue

        if click.get_text_stream("stdin").isatty():
            console.print("\nApply this change automatically? ([yes]/no/skip)")
            choice = click.prompt("", default="no", show_default=False).strip().lower()
        else:
            choice = "no"

        if choice in ("yes", "y"):
            _apply_change(change)
            console.print(
                "[green]Applied. Run your existing tests — they should still pass.[/green]"
            )
        elif choice == "skip":
            console.print("[dim]Skipped.[/dim]")
        else:
            console.print("[dim]Change shown above — apply manually when ready.[/dim]")

    console.print(
        Panel(
            "Discovery complete. Agents registered in governance/agents/.\n"
            "Run [bold]iris status[/bold] to see your compliance scores.",
            style="blue",
        )
    )
