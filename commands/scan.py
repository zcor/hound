"""Surface scan command for lightweight security analysis."""

import os
import sys
import uuid
from datetime import datetime
from pathlib import Path

import click
from rich.console import Console

console = Console()


def _save_scan_to_database(result, tenant_id: int = 1) -> str | None:
    """Save scan result to database for admin panel tracking.
    
    Returns execution_id if saved successfully, None otherwise.
    """
    database_url = os.environ.get("DATABASE_URL", "")
    if not database_url:
        return None
    
    try:
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from database.models import ScanExecution
        
        engine = create_engine(database_url)
        Session = sessionmaker(bind=engine)
        db = Session()
        
        # Generate unique execution ID
        execution_id = f"scan_{uuid.uuid4().hex[:12]}_{int(datetime.now().timestamp())}"
        
        # Create scan execution record
        scan_exec = ScanExecution(
            execution_id=execution_id,
            tenant_id=tenant_id,
            repo_url=result.repo_url,
            repo_name=result.repo_name,
            status="completed" if not result.error else "failed",
            risk_score=result.risk_score,
            risk_level=result.risk_level,
            findings=[f.model_dump() for f in result.findings],
            quality_metrics=result.quality_metrics.model_dump(),
            summary=result.summary,
            scan_config={
                "llm_calls_used": result.llm_calls_used,
                "contracts_scanned": result.contracts_scanned,
            },
            llm_calls_made=result.llm_calls_used,
            contracts_scanned=result.contracts_scanned,
            contracts_total=result.contracts_total,
            error_message=result.error,
            started_at=result.scan_timestamp,
            completed_at=datetime.now(),
        )
        
        db.add(scan_exec)
        db.commit()
        db.close()
        
        return execution_id
    except Exception as e:
        console.print(f"[yellow]Warning: Failed to save scan to database: {e}[/yellow]")
        return None


@click.command()
@click.argument("target", required=False)
@click.option("--batch", "-b", type=click.Path(exists=True), help="CSV file with repo URLs for batch scanning")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--format", "-f", "output_format", type=click.Choice(["json", "html", "md", "csv"]), default="json", help="Output format")
@click.option("--budget", type=int, default=5, help="Maximum LLM calls per repo (default: 5)")
@click.option("--model", type=str, default=None, help="Override LLM model (default: gpt-4o-mini)")
@click.option("--quiet", "-q", is_flag=True, help="Suppress progress output")
@click.option("--no-llm", is_flag=True, help="Skip LLM verification (faster, less accurate)")
@click.option("--max-concurrent", type=int, default=10, help="Max concurrent scans for batch mode")
@click.option("--save", is_flag=True, help="Save scan results to database (requires DATABASE_URL)")
def scan(
    target: str | None,
    batch: str | None,
    output: str | None,
    output_format: str,
    budget: int,
    model: str | None,
    quiet: bool,
    no_llm: bool,
    max_concurrent: int,
    save: bool,
):
    """Fast preliminary security scan for smart contract repos.

    Performs lightweight static analysis and optional LLM verification
    to identify potential vulnerabilities in Solidity/Vyper contracts.

    Examples:

        # Scan a GitHub repo
        hound scan https://github.com/uniswap/v4-core

        # Scan a local directory
        hound scan /path/to/contracts

        # Generate HTML report
        hound scan https://github.com/org/repo --format html --output report.html

        # Batch scan from CSV
        hound scan --batch repos.csv --output results.csv --format csv

        # Fast scan without LLM
        hound scan /path/to/contracts --no-llm
    """
    from analysis.surface import SurfaceScanner
    from analysis.surface.report import ScanReportGenerator
    from utils.config_loader import load_config

    # Validate inputs
    if not target and not batch:
        console.print("[red]Error: Provide a target (URL or path) or use --batch for CSV input[/red]")
        sys.exit(1)

    # Load config
    try:
        config = load_config()
    except Exception:
        config = {}

    # Set LLM budget
    llm_budget = 0 if no_llm else budget

    # Initialize scanner
    scanner = SurfaceScanner(
        config=config,
        llm_budget=llm_budget,
        model=model,
        quiet=quiet,
    )

    # Batch mode
    if batch:
        batch_path = Path(batch)
        output_path = Path(output) if output else batch_path.with_suffix('.results.csv')

        console.print(f"[bold cyan]Hound Surface Scan - Batch Mode[/bold cyan]")
        console.print(f"[dim]Input: {batch_path}[/dim]")
        console.print(f"[dim]Output: {output_path}[/dim]")
        console.print()

        batch_result = scanner.scan_batch(
            csv_path=batch_path,
            output_path=output_path,
            max_concurrent=max_concurrent,
        )

        # Save batch results to database if requested
        if save:
            saved_count = 0
            for result in batch_result.results:
                if _save_scan_to_database(result):
                    saved_count += 1
            if not quiet:
                console.print(f"[dim]Saved {saved_count}/{len(batch_result.results)} scans to database[/dim]")

        # Also generate full report if HTML format requested
        if output_format == "html" and output:
            # Generate individual HTML reports in a directory
            output_dir = Path(output).parent / "reports"
            output_dir.mkdir(exist_ok=True)
            report_gen = ScanReportGenerator()
            for result in batch_result.results:
                if not result.error:
                    html = report_gen.generate_html(result)
                    report_path = output_dir / f"{result.repo_name}.html"
                    report_path.write_text(html)
            console.print(f"[green]HTML reports written to {output_dir}[/green]")

        return

    # Single repo mode
    if not quiet:
        console.print(f"[bold cyan]Hound Surface Scan[/bold cyan]")
        console.print()

    # Run scan
    result = scanner.scan(target)

    # Handle errors
    if result.error:
        console.print(f"[red]Error scanning {target}:[/red] {result.error}")
        sys.exit(1)

    # Save to database if requested (or if DATABASE_URL is set and --save flag used)
    if save:
        execution_id = _save_scan_to_database(result)
        if execution_id and not quiet:
            console.print(f"[dim]Saved to database: {execution_id}[/dim]")

    # Generate output
    report_gen = ScanReportGenerator()
    report_content = report_gen.generate(result, format=output_format)

    # Write or print output
    if output:
        output_path = Path(output)
        output_path.write_text(report_content)
        if not quiet:
            console.print(f"[green]Report written to {output_path}[/green]")
    else:
        if output_format == "json":
            console.print_json(report_content)
        else:
            console.print(report_content)

    # Print summary to console (unless quiet or writing to file)
    if not quiet and not output:
        _print_summary(result)


def _print_summary(result):
    """Print a summary table to console."""
    from rich.panel import Panel
    from rich.text import Text

    # Risk color
    risk_colors = {
        "critical": "red",
        "high": "orange1",
        "medium": "yellow",
        "low": "green",
    }
    risk_color = risk_colors.get(result.risk_level, "white")

    # Build summary
    counts = result.finding_counts

    summary_text = Text()
    summary_text.append(f"\nRisk Score: ", style="bold")
    summary_text.append(f"{result.risk_score}/100", style=f"bold {risk_color}")
    summary_text.append(f" ({result.risk_level.upper()})\n\n", style=risk_color)

    summary_text.append("Findings: ", style="bold")
    summary_text.append(f"{counts['critical']} critical, ", style="red")
    summary_text.append(f"{counts['high']} high, ", style="orange1")
    summary_text.append(f"{counts['medium']} medium, ", style="yellow")
    summary_text.append(f"{counts['low']} low\n\n", style="green")

    summary_text.append(result.summary + "\n", style="dim")

    panel = Panel(
        summary_text,
        title=f"[bold]{result.repo_name}[/bold]",
        border_style=risk_color,
    )
    console.print(panel)


def run_scan(
    target: str | None,
    batch: str | None,
    output: str | None,
    output_format: str,
    budget: int,
    model: str | None,
    quiet: bool,
):
    """Entry point for typer CLI wrapper."""
    ctx = click.Context(scan)
    ctx.params = {
        "target": target,
        "batch": batch,
        "output": output,
        "output_format": output_format,
        "budget": budget,
        "model": model,
        "quiet": quiet,
        "no_llm": False,
        "max_concurrent": 10,
    }
    try:
        scan.invoke(ctx)
    except SystemExit as e:
        if e.code != 0:
            raise
