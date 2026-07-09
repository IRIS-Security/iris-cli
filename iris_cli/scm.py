"""IRIS SCM CLI commands."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import click
from rich.console import Console

from iris_core.entitlements import Entitlements, Feature

console = Console()


def _write_output(content: str, output_file: str | None) -> None:
    if output_file:
        Path(output_file).write_text(content, encoding="utf-8")
        console.print(f"[green]Results saved to {output_file}[/green]")
    else:
        click.echo(content)


def _github_scanner(org: str, token: str | None, app_id, installation_id, private_key_path):
    from iris_scm import IrisGitHubScanner

    if token:
        return IrisGitHubScanner(org=org, token=token)
    if app_id and installation_id and private_key_path:
        return IrisGitHubScanner(
            org=org,
            app_id=app_id,
            private_key_path=private_key_path,
            installation_id=installation_id,
        )
    return None


@click.group()
def scm():
    """SCM integration — scan GitHub/GitLab orgs for ungoverned agents."""
    pass


@scm.command("scan-org")
@click.option("--platform", required=True, type=click.Choice(["github", "gitlab"]))
@click.option("--org", default=None, help="GitHub organization name")
@click.option("--group", default=None, help="GitLab group id or path")
@click.option("--token", default=None, help="PAT or service account token")
@click.option("--gitlab-url", default="https://gitlab.com", help="GitLab instance URL")
@click.option("--app-id", default=None, envvar="GITHUB_APP_ID", help="GitHub App ID")
@click.option(
    "--installation-id",
    default=None,
    envvar="GITHUB_INSTALLATION_ID",
    help="GitHub App installation ID",
)
@click.option(
    "--private-key",
    "private_key_path",
    default=None,
    envvar="GITHUB_PRIVATE_KEY_PATH",
    help="Path to GitHub App private key PEM",
)
@click.option("--max-repos", default=100, show_default=True, help="Maximum repos to scan")
@click.option(
    "--format",
    "output_format",
    default="table",
    type=click.Choice(["table", "json", "markdown"]),
)
@click.option("--comment", is_flag=True, help="Post PR/MR comments on findings (opt-in)")
@click.option("--output", "output_file", default=None, help="Save results to file")
@click.option("--verbose", is_flag=True, help="Show all findings by risk level")
def scan_org(
    platform,
    org,
    group,
    token,
    gitlab_url,
    app_id,
    installation_id,
    private_key_path,
    max_repos,
    output_format,
    comment,
    output_file,
    verbose,
):
    """
    Scan an entire GitHub organization or GitLab group.

    Examples:
      iris scm scan-org --platform github --org my-org
      export GITHUB_TOKEN=ghp_... && iris scm scan-org --platform github --org my-org
      iris scm scan-org --platform gitlab --group my-group --token $GITLAB_TOKEN
    """
    Entitlements().require(Feature.SCM_ORG_SCANNER, context="org-wide SCM scan")
    if comment:
        Entitlements().require(Feature.SCM_PR_COMMENTS, context="SCM PR comments")
    if platform == "github":
        if not org:
            console.print("[red]--org is required for GitHub scans[/red]")
            sys.exit(1)
        gh_token = token or os.environ.get("GITHUB_TOKEN")
        scanner = _github_scanner(org, gh_token, app_id, installation_id, private_key_path)
        if scanner is None:
            console.print(
                "[red]GitHub credentials required:[/red]\n"
                "  PAT: export GITHUB_TOKEN=... or --token\n"
                "  App: GITHUB_APP_ID, GITHUB_INSTALLATION_ID, GITHUB_PRIVATE_KEY_PATH"
            )
            sys.exit(1)
        result = scanner.scan_organization(max_repos=max_repos)
    else:
        if not group:
            console.print("[red]--group is required for GitLab scans[/red]")
            sys.exit(1)
        gl_token = token or os.environ.get("GITLAB_TOKEN")
        if not gl_token:
            console.print("[red]--token or GITLAB_TOKEN is required[/red]")
            sys.exit(1)
        from iris_scm import IrisGitLabScanner

        scanner = IrisGitLabScanner(token=gl_token, group=group, gitlab_url=gitlab_url)
        result = scanner.scan_group(max_projects=max_repos)

    if comment and result.findings:
        console.print("[yellow]Posting PR/MR comments (--comment flag enabled)...[/yellow]")
        for finding in result.findings:
            if finding.scm_platform == "github" and finding.line_number:
                pr_number = _infer_pr_number(finding)
                if pr_number:
                    scanner.post_pr_comment(finding.repo_name, pr_number, [finding])

    if output_format == "json":
        _write_output(result.to_json(), output_file)
    elif output_format == "markdown":
        _write_output(_to_markdown(result), output_file)
    else:
        _write_output(result.to_summary_table(verbose=verbose), output_file)

    if result.ungoverned_agents_found:
        sys.exit(1)


@scm.command("scan-repo")
@click.option("--platform", required=True, type=click.Choice(["github", "gitlab"]))
@click.option("--repo", required=True, help="Repository (org/repo) or GitLab project id")
@click.option("--token", default=None)
@click.option("--gitlab-url", default="https://gitlab.com")
@click.option("--app-id", default=None, envvar="GITHUB_APP_ID")
@click.option("--installation-id", default=None, envvar="GITHUB_INSTALLATION_ID")
@click.option("--private-key", "private_key_path", default=None, envvar="GITHUB_PRIVATE_KEY_PATH")
@click.option("--format", "output_format", default="table", type=click.Choice(["table", "json"]))
def scan_repo(
    platform,
    repo,
    token,
    gitlab_url,
    app_id,
    installation_id,
    private_key_path,
    output_format,
):
    """Scan a single repository or GitLab project."""
    if platform == "github":
        org = repo.split("/")[0] if "/" in repo else repo
        gh_token = token or os.environ.get("GITHUB_TOKEN")
        scanner = _github_scanner(org, gh_token, app_id, installation_id, private_key_path)
        if scanner is None:
            console.print("[red]GitHub credentials required[/red]")
            sys.exit(1)
        findings = scanner.scan_repository(repo)
        result_platform = "github"
        org_label = org
    else:
        gl_token = token or os.environ.get("GITLAB_TOKEN")
        if not gl_token:
            console.print("[red]--token or GITLAB_TOKEN is required[/red]")
            sys.exit(1)
        from iris_scm import IrisGitLabScanner

        scanner = IrisGitLabScanner(token=gl_token, group="", gitlab_url=gitlab_url)
        findings = scanner.scan_project(repo)
        result_platform = "gitlab"
        org_label = repo

    from iris_scm.models import SCMScanResult

    result = SCMScanResult(
        org_or_group=org_label,
        platform=result_platform,
        repos_scanned=1,
        files_scanned=len({f.file_path for f in findings}),
        findings=findings,
        ungoverned_agents_found=len({(f.repo_name, f.file_path) for f in findings}),
        high_risk_count=sum(1 for f in findings if f.risk_level == "HIGH"),
    )

    if output_format == "json":
        click.echo(result.to_json())
    else:
        click.echo(result.to_summary_table())

    if findings:
        sys.exit(1)


@scm.command("scan-local")
@click.option("--dir", "scan_dir", type=click.Path(exists=True, file_okay=False, path_type=Path), default=".")
@click.option("--format", "output_format", default="table", type=click.Choice(["table", "json"]))
def scan_local(scan_dir: Path, output_format: str):
    """Scan a local directory for ungoverned agents."""
    from iris_scm import IrisLocalScanner

    scanner = IrisLocalScanner(scan_dir.resolve())
    result = scanner.scan()

    if output_format == "json":
        click.echo(result.to_json())
    else:
        click.echo(result.to_summary_table())

    if result.ungoverned_agents_found:
        sys.exit(1)


@scm.command("org")
@click.option("--install", is_flag=True, help="Open GitHub App installation URL in browser")
@click.option("--status", is_flag=True, help="Show org-wide scan status")
@click.option("--scan", is_flag=True, help="Trigger re-scan of all org repos")
@click.option(
    "--api-url",
    default=None,
    envvar="IRIS_CONSOLE_API_URL",
    help="IRIS Cloud Console API base URL",
)
def scm_org(install, status, scan, api_url):
    """
    GitHub App org-wide agent scanning.

    Install once, scan every repo in your GitHub org automatically.
    Agents are discovered on every push.

    Examples:
      iris scm org --install    # Opens GitHub App install page
      iris scm org --status     # Show scan results across all repos
      iris scm org --scan       # Trigger manual re-scan
    """
    if not any([install, status, scan]):
        console.print("[yellow]Specify --install, --status, or --scan[/yellow]")
        return

    if install:
        import webbrowser

        app_url = "https://github.com/apps/iris-security"
        console.print("[bold]Opening GitHub App installation...[/bold]")
        console.print(f"[dim]URL: {app_url}[/dim]")
        webbrowser.open(app_url)
        console.print("[green]✓ Install IRIS Security on your GitHub org[/green]")
        console.print("[dim]After installation, run: iris scm org --status[/dim]")

    base_url = (api_url or "http://localhost:8000").rstrip("/")

    if status:
        console.print("[bold]GitHub App Org Scan Status[/bold]")
        try:
            import httpx

            resp = httpx.get(f"{base_url}/github/installations", timeout=10.0)
            if resp.status_code == 401:
                console.print("[dim]No installations found. Run: iris scm org --install[/dim]")
                return
            resp.raise_for_status()
            installations = resp.json()
            if not installations:
                console.print("[dim]No installations found. Run: iris scm org --install[/dim]")
                return
            for inst in installations:
                console.print(
                    f"  [cyan]{inst['org_name']}[/cyan] "
                    f"({inst['repos_scanned']} repos, "
                    f"{inst['ungoverned_found']} ungoverned, "
                    f"{inst['agents_found']} agents)"
                )
        except Exception:
            console.print("[dim]No installations found. Run: iris scm org --install[/dim]")

    if scan:
        console.print("[bold]Triggering org-wide scan...[/bold]")
        try:
            import httpx

            resp = httpx.get(f"{base_url}/github/installations", timeout=10.0)
            if resp.status_code != 200 or not resp.json():
                console.print("[dim]iris scm org --scan requires IRIS API running[/dim]")
                return
            for inst in resp.json():
                scan_resp = httpx.post(
                    f"{base_url}/github/installations/{inst['id']}/scan",
                    timeout=10.0,
                )
                if scan_resp.status_code == 200:
                    body = scan_resp.json()
                    console.print(
                        f"[green]✓ Queued scan for {inst['org_name']} "
                        f"({body.get('repos', 0)} repos)[/green]"
                    )
                else:
                    console.print(f"[red]Failed to queue scan for {inst['org_name']}[/red]")
        except Exception:
            console.print("[dim]iris scm org --scan requires IRIS API running[/dim]")


@scm.command("setup")
@click.option("--platform", required=True, type=click.Choice(["github", "gitlab"]))
@click.option("--org", default=None, help="GitHub organization name (for context)")
def setup(platform: str, org: str | None):
    """Print step-by-step setup instructions for GitHub App or GitLab service account."""
    if platform == "github":
        _print_github_setup(org)
    else:
        _print_gitlab_setup()


def _print_github_setup(org: str | None) -> None:
    org_name = org or "YOUR-ORG"
    guide = f"""
Setting up IRIS GitHub Integration (10 minutes)

Step 1: Go to github.com/organizations/{org_name}/settings/apps
Step 2: Click "New GitHub App"
Step 3: Fill in:
  Name: IRIS Governance
  Homepage URL: https://github.com/IRIS-Security/iris-sdk
  Webhook: leave unchecked for now
Step 4: Set permissions (read-only):
  Repository permissions:
    Contents: Read
    Metadata: Read
  If you want PR comments (optional):
    Pull requests: Read and Write
Step 5: Click "Create GitHub App"
Step 6: Generate a private key and save the .pem file
Step 7: Install the app on your organization
Step 8: Note your App ID and Installation ID
Step 9: Run:
  export GITHUB_APP_ID=your-app-id
  export GITHUB_INSTALLATION_ID=your-installation-id
  export GITHUB_PRIVATE_KEY_PATH=/path/to/key.pem
  iris scm scan-org --platform github --org {org_name}

For fastest setup (personal access token):
  export GITHUB_TOKEN=your-pat
  iris scm scan-org --platform github --org {org_name}
"""
    click.echo(guide.strip())


def _print_gitlab_setup() -> None:
    guide = """
Setting up IRIS GitLab Integration (10 minutes)

Step 1: Create a service account user in your GitLab group
Step 2: Give it Reporter role (read-only access to all repos)
Step 3: Generate a personal access token with read_api scope
Step 4: Run:
  export GITLAB_TOKEN=your-token
  iris scm scan-org --platform gitlab --group your-group
"""
    click.echo(guide.strip())


@scm.group()
def webhook():
    """Webhook server commands (optional automatic PR/MR scanning)."""
    pass


@webhook.command("start")
@click.option("--port", default=8765, show_default=True)
@click.option("--host", default="0.0.0.0", show_default=True)
def webhook_start(port, host):
    """Start the IRIS SCM webhook server."""
    from iris_scm.webhook_server import configure_handlers, run_server

    github_handler = None
    gitlab_handler = None

    app_id = os.environ.get("GITHUB_APP_ID")
    installation_id = os.environ.get("GITHUB_INSTALLATION_ID")
    private_key = os.environ.get("GITHUB_PRIVATE_KEY_PATH")
    org = os.environ.get("GITHUB_ORG", "")
    gitlab_token = os.environ.get("GITLAB_TOKEN")

    if app_id and installation_id and private_key:
        from iris_scm.github_app import IrisGitHubApp

        gh_app = IrisGitHubApp(
            org=org,
            app_id=app_id,
            private_key_path=private_key,
            installation_id=installation_id,
        )
        github_handler = gh_app.handle_webhook_event

    if gitlab_token:
        from iris_scm.gitlab_integration import IrisGitLabIntegration

        gl = IrisGitLabIntegration(
            gitlab_url=os.environ.get("GITLAB_URL", "https://gitlab.com"),
            access_token=gitlab_token,
        )
        gitlab_handler = gl.handle_webhook_event

    configure_handlers(
        github_handler=github_handler,
        gitlab_handler=gitlab_handler,
    )
    console.print(f"[bold blue]IRIS SCM webhook server on {host}:{port}[/bold blue]")
    run_server(host=host, port=port)


def _infer_pr_number(finding) -> int | None:
    return None


def _to_markdown(result) -> str:
    lines = [
        f"# IRIS SCM Scan: {result.org_or_group}",
        "",
        f"- Repos scanned: {result.repos_scanned}",
        f"- Files scanned: {result.files_scanned}",
        f"- Ungoverned agents: {result.ungoverned_agents_found}",
        "",
        "## Findings",
        "",
    ]
    for finding in result.top_findings(50):
        lines.append(f"### {finding.risk_level}: {finding.repo_name}/{finding.file_path}")
        lines.append(f"- Pattern: {finding.pattern_matched}")
        lines.append(f"- Fix: `{finding.suggested_command}`")
        lines.append("")
    return "\n".join(lines)
