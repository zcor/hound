#!/usr/bin/env python
"""
Example script demonstrating how to use the GitHub PR reporter.

This script shows how to integrate the GitHubPRReporter with the ReportGenerator
to post security findings directly to a GitHub Pull Request.

Usage:
    python examples/github_pr_comment.py PROJECT_NAME REPO PR_NUMBER [--token TOKEN]

Example:
    # Using GITHUB_TOKEN environment variable
    export GITHUB_TOKEN="ghp_..."
    python examples/github_pr_comment.py my-project owner/repo 42
    
    # Or pass token explicitly
    python examples/github_pr_comment.py my-project owner/repo 42 --token ghp_...
"""

import sys
from pathlib import Path

import click
from rich.console import Console

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis.report_generator import ReportGenerator
from analysis.reporters.github_pr import GitHubPRReporter
from commands.project import ProjectManager
from utils.config_loader import load_config

console = Console()


@click.command()
@click.argument('project_name')
@click.argument('repo_full_name')
@click.argument('pr_number', type=int)
@click.option('--token', '-t', help="GitHub access token (or use GITHUB_TOKEN env var)")
@click.option('--debug', is_flag=True, help="Enable debug mode")
def post_to_pr(project_name: str, repo_full_name: str, pr_number: int, token: str | None, debug: bool):
    """
    Post Hound security findings to a GitHub Pull Request.
    
    Args:
        PROJECT_NAME: Name of the Hound project
        REPO_FULL_NAME: Full repository name (e.g., "owner/repo")
        PR_NUMBER: Pull request number
    """
    console.print("[bold bright_cyan]Hound GitHub PR Commenter[/bold bright_cyan]\n")
    
    # 1. Load project
    console.print(f"[bright_cyan]Loading project:[/bright_cyan] {project_name}")
    manager = ProjectManager()
    project = manager.get_project(project_name)
    
    if not project:
        console.print(f"[red]Project '{project_name}' not found.[/red]")
        console.print("[yellow]Tip: Run 'hound project list' to see available projects[/yellow]")
        raise click.Exit(1)
    
    project_dir = Path(project["path"])
    
    # 2. Check for analysis data
    console.print("[bright_cyan]Checking for analysis data...[/bright_cyan]")
    graphs_dir = project_dir / "graphs"
    if not graphs_dir.exists() or not list(graphs_dir.glob("*.json")):
        console.print("[red]No graphs found. Run 'hound graph build' first.[/red]")
        raise click.Exit(1)
    
    hypothesis_file = project_dir / "hypotheses.json"
    if not hypothesis_file.exists():
        console.print("[yellow]No hypotheses found. Run 'hound agent run' first.[/yellow]")
        console.print("[yellow]Proceeding anyway (will report 0 findings)...[/yellow]")
    
    # 3. Initialize report generator to get findings
    console.print("[bright_cyan]Loading findings...[/bright_cyan]")
    config = load_config()
    
    generator = ReportGenerator(
        project_dir=project_dir,
        config=config,
        debug=debug,
        include_all=False  # Only confirmed findings
    )
    
    # Get confirmed findings
    findings = generator._get_confirmed_findings()
    
    if not findings:
        console.print("[yellow]No confirmed findings to report.[/yellow]")
        console.print("[yellow]Run 'hound agent run' to analyze the project first.[/yellow]")
        raise click.Exit(0)
    
    console.print(f"[bright_green]Found {len(findings)} confirmed finding(s)[/bright_green]")
    
    # Show findings summary
    for finding in findings:
        severity = finding.get('severity', 'unknown').upper()
        title = finding.get('title', 'Unknown')
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")
        console.print(f"  {emoji} [{severity}] {title}")
    
    console.print()
    
    # 4. Initialize GitHub PR reporter
    console.print(f"[bright_cyan]Connecting to GitHub:[/bright_cyan] {repo_full_name} PR#{pr_number}")
    
    try:
        reporter = GitHubPRReporter(
            repo_full_name=repo_full_name,
            pr_number=pr_number,
            token=token
        )
    except ValueError as e:
        console.print(f"[red]Failed to initialize GitHub reporter: {e}[/red]")
        raise click.Exit(1)
    
    # 5. Post findings to PR
    console.print("[bright_cyan]Posting findings to PR...[/bright_cyan]")
    
    result = reporter.report(findings)
    
    # 6. Show result
    if result["status"] == "success":
        console.print("\n[bold bright_green]✓ Successfully posted to GitHub PR![/bold bright_green]")
        console.print(f"[bright_green]Review ID: {result.get('review_id')}[/bright_green]")
        console.print(f"[bright_green]Comments posted: {result.get('comments_posted', 0)}[/bright_green]")
        console.print(f"[bright_green]Review event: {result.get('review_event')}[/bright_green]")
        
        # Add link to PR
        pr_url = f"https://github.com/{repo_full_name}/pull/{pr_number}"
        console.print(f"\n[bright_cyan]View PR: {pr_url}[/bright_cyan]")
    else:
        console.print("\n[bold red]✗ Failed to post to GitHub PR[/bold red]")
        console.print(f"[red]Error: {result.get('error', 'Unknown error')}[/red]")
        if debug:
            console.print(f"[red]Error type: {result.get('error_type')}[/red]")
        raise click.Exit(1)
    
    # Clean up
    reporter.close()


if __name__ == "__main__":
    post_to_pr()
