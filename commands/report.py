"""
Generate professional security audit reports from project analysis.
"""

import json
import os
import random
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel

from analysis.report_generator import ReportGenerator
from commands.project import ProjectManager

console = Console()


def _load_report_data_from_db(project_name: str, include_all: bool = False) -> tuple[dict | None, Path | None, Path | None]:
    """
    Load report data from database.
    
    Returns: (hypotheses_dict, repo_root, temp_project_dir) or (None, None, None) if not using DB
    """
    database_url = os.environ.get("DATABASE_URL", "")
    if not database_url:
        return None, None, None
    
    try:
        from sqlalchemy import create_engine, text
        engine = create_engine(database_url)
        
        with engine.connect() as conn:
            # Find project by name
            result = conn.execute(text(
                "SELECT id, name, source_path, git_url FROM projects WHERE name = :name"
            ), {"name": project_name})
            project = result.fetchone()
            
            if not project:
                # Try matching by partial name
                result = conn.execute(text(
                    "SELECT id, name, source_path, git_url FROM projects WHERE name ILIKE :pattern ORDER BY id DESC LIMIT 1"
                ), {"pattern": f"%{project_name}%"})
                project = result.fetchone()
            
            if not project:
                return None, None, None
            
            project_id, name, source_path, git_url = project
            
            # Determine repo root
            repo_root = None
            if source_path and Path(source_path).exists():
                repo_root = Path(source_path)
            elif git_url:
                # Check common clone locations
                repo_name = git_url.rstrip('/').split('/')[-1].replace('.git', '')
                for base in [Path('/tmp'), Path('/workspaces')]:
                    candidate = base / repo_name
                    if candidate.exists():
                        repo_root = candidate
                        break
                
                # Clone if not found
                if not repo_root:
                    clone_path = Path('/tmp') / repo_name
                    console.print(f"[dim]Cloning {git_url} to {clone_path}...[/dim]")
                    try:
                        result = subprocess.run(
                            ["git", "clone", "--depth", "1", git_url, str(clone_path)],
                            capture_output=True,
                            text=True,
                            timeout=120,
                        )
                        if result.returncode == 0 and clone_path.exists():
                            repo_root = clone_path
                            console.print("[dim]Cloned successfully[/dim]")
                    except Exception as e:
                        console.print(f"[yellow]Clone warning: {e}[/yellow]")
            
            # Get hypotheses based on include_all flag
            if include_all:
                result = conn.execute(text("""
                    SELECT hypothesis_id, title, description, vulnerability_type,
                           status, confidence, severity, node_refs, evidence
                    FROM hypotheses 
                    WHERE project_id = :pid
                    ORDER BY confidence DESC
                """), {"pid": project_id})
            else:
                result = conn.execute(text("""
                    SELECT hypothesis_id, title, description, vulnerability_type,
                           status, confidence, severity, node_refs, evidence
                    FROM hypotheses 
                    WHERE project_id = :pid 
                    AND (status = 'confirmed' OR confidence >= 0.7)
                    ORDER BY confidence DESC
                """), {"pid": project_id})
            
            rows = result.fetchall()
            
            # Helper function to extract file paths from hypothesis text
            def _extract_source_files_from_text(hyp_title: str, description: str, repo_root: Path | None) -> list[str]:
                """Extract source file paths from hypothesis text using keyword matching."""
                if not repo_root:
                    return []
                
                import re
                source_files = []
                combined = f"{hyp_title} {description}".lower()
                
                # Look for camelCase or PascalCase identifiers
                identifiers = set(re.findall(
                    r'\b([A-Za-z][a-zA-Z0-9]*(?:[A-Z][a-zA-Z0-9]*)+)\b', 
                    f"{hyp_title} {description}"
                ))
                
                # Extract simple keywords that might be file names
                keywords = set()
                for word in re.findall(r'\b([a-zA-Z]{4,20})\b', combined):
                    if word not in {'this', 'that', 'with', 'from', 'allows', 'which', 'could', 
                                  'would', 'should', 'using', 'funds', 'tokens', 'called', 'function',
                                  'contract', 'address', 'operator', 'manager', 'admin', 'oracle',
                                  'strategy', 'balance', 'transfer', 'approve'}:
                        keywords.add(word)
                
                # Scan contracts directory for matching files
                contracts_dir = repo_root / 'contracts'
                if contracts_dir.exists():
                    for sol_file in contracts_dir.glob('**/*.sol'):
                        file_lower = sol_file.stem.lower()
                        for kw in keywords | {i.lower() for i in identifiers}:
                            if kw in file_lower or file_lower in kw:
                                rel_path = str(sol_file.relative_to(repo_root))
                                if rel_path not in source_files:
                                    source_files.append(rel_path)
                                break
                
                # Also scan src directory
                src_dir = repo_root / 'src'
                if src_dir.exists():
                    for sol_file in src_dir.glob('**/*.sol'):
                        file_lower = sol_file.stem.lower()
                        for kw in keywords | {i.lower() for i in identifiers}:
                            if kw in file_lower or file_lower in kw:
                                rel_path = str(sol_file.relative_to(repo_root))
                                if rel_path not in source_files:
                                    source_files.append(rel_path)
                                break
                
                return source_files
            
            hypotheses = {}
            for row in rows:
                hid, hyp_title, description, vuln_type, status, confidence, severity, node_refs, evidence = row
                
                # Extract source files from hypothesis text
                source_files = _extract_source_files_from_text(hyp_title, description, repo_root)
                
                # Build node_refs from extracted files if empty
                effective_node_refs = node_refs or []
                if not effective_node_refs and source_files:
                    effective_node_refs = source_files
                
                hypotheses[hid] = {
                    'title': hyp_title,
                    'description': description,
                    'vulnerability_type': vuln_type,
                    'status': status,
                    'confidence': confidence,
                    'severity': severity,
                    'node_refs': effective_node_refs,
                    'evidence': evidence or {},
                    'annotations': [],
                    'locations': [],
                    'reasoning': description,
                    'properties': {
                        'source_files': source_files  # Add source_files to properties
                    }
                }
                # Convert node_refs to annotations format
                if effective_node_refs:
                    for ref in effective_node_refs:
                        if isinstance(ref, str) and ':' in ref:
                            parts = ref.split(':')
                            file_path = parts[0]
                            line = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
                            hypotheses[hid]['annotations'].append({
                                'file_path': file_path,
                                'line': line
                            })
                        elif isinstance(ref, str):
                            hypotheses[hid]['annotations'].append({'file_path': ref})
            
            # Create temporary project directory structure for ReportGenerator
            temp_project_dir = Path(tempfile.mkdtemp(prefix="hound_report_"))
            
            # Create graphs directory with minimal metadata
            graphs_dir = temp_project_dir / "graphs"
            graphs_dir.mkdir(parents=True, exist_ok=True)
            
            # Create knowledge_graphs.json with repo root
            kg_data = {
                "manifest": {"repo_path": str(repo_root) if repo_root else None},
                "card_store_path": None
            }
            with open(graphs_dir / "knowledge_graphs.json", "w") as f:
                json.dump(kg_data, f)
            
            # Create a minimal graph file so the generator doesn't fail
            with open(graphs_dir / "graph_analysis.json", "w") as f:
                json.dump({"nodes": [], "edges": []}, f)
            
            # Create hypotheses.json
            hyp_data = {
                "hypotheses": hypotheses,
                "metadata": {
                    "source": "database",
                    "project_name": name
                }
            }
            with open(temp_project_dir / "hypotheses.json", "w") as f:
                json.dump(hyp_data, f)
            
            # Create reports directory
            (temp_project_dir / "reports").mkdir(exist_ok=True)
            
            console.print(f"[dim]Loaded {len(hypotheses)} hypotheses from database[/dim]")
            
            return hypotheses, repo_root, temp_project_dir
            
    except Exception as e:
        console.print(f"[yellow]Database lookup failed: {e}[/yellow]")
        import traceback
        traceback.print_exc()
        return None, None, None


@click.command()
@click.argument('project_name')
@click.option('--output', '-o', help="Output file path (default: project_dir/reports/audit_report_TIMESTAMP.html)")
@click.option('--format', '-f', type=click.Choice(['html', 'markdown', 'pdf']), default='html', help="Report format")
@click.option('--title', '-t', help="Custom report title")
@click.option('--auditors', '-a', help="Comma-separated list of auditor names", default="Security Team")
@click.option('--debug', is_flag=True, help="Enable debug mode")
@click.option('--show-prompt', is_flag=True, help="Show the LLM prompt and response used to generate the report")
@click.option('--all', 'include_all', is_flag=True, help="Include ALL hypotheses (not just confirmed) - WARNING: No QA performed, may contain false positives")
def report(project_name: str, output: str | None, format: str, 
          title: str | None, auditors: str, debug: bool, show_prompt: bool, include_all: bool):
    """
    Generate a professional security audit report for a project.
    
    Creates a comprehensive report including:
    - Executive summary
    - Findings (when available)
    - Scope and methodology
    - Testing coverage appendix
    """
    # Try loading from database first
    db_hypotheses, repo_root, temp_project_dir = _load_report_data_from_db(project_name, include_all)
    
    project_dir = None
    project_source = None
    cleanup_temp = False
    
    if db_hypotheses is not None and temp_project_dir:
        # Use database mode
        console.print("[dim]Using database mode...[/dim]")
        project_dir = temp_project_dir
        project_source = str(repo_root) if repo_root else None
        cleanup_temp = True
    else:
        # Fall back to filesystem mode
        manager = ProjectManager()
        project = manager.get_project(project_name)
        
        if not project:
            console.print(f"[red]Project '{project_name}' not found.[/red]")
            console.print("[dim]Hint: Set DATABASE_URL environment variable to load from database[/dim]")
            raise click.Exit(1)
        
        project_dir = Path(project["path"])
        project_source = project.get("source_path")
        
        # Check for required data
        graphs_dir = project_dir / "graphs"
        if not graphs_dir.exists() or not list(graphs_dir.glob("*.json")):
            console.print("[red]No graphs found. Run graph build first.[/red]")
            raise click.Exit(1)
    
    # Load hypotheses count
    hypothesis_file = project_dir / "hypotheses.json"
    hypotheses = {}
    if hypothesis_file.exists():
        with open(hypothesis_file) as f:
            hyp_data = json.load(f)
            hypotheses = hyp_data.get("hypotheses", {})
    
    # Determine output path
    if not output:
        reports_dir = project_dir / "reports"
        reports_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = reports_dir / f"audit_report_{timestamp}.{format}"
    else:
        output_path = Path(output)
    
    warning_text = ""
    if include_all:
        warning_text = "\n[bold yellow]⚠️  WARNING:[/bold yellow] Including ALL hypotheses (no QA performed)\n[yellow]Report may contain false positives![/yellow]\n"
    
    console.print(Panel(
        f"[bold bright_cyan]Generating Security Audit Report[/bold bright_cyan]\n\n"
        f"[bold]Project:[/bold] {project_name}\n"
        f"[bold]Format:[/bold] {format.upper()}\n"
        f"[bold]Output:[/bold] {output_path.name}\n"
        f"[bold]Hypotheses Tested:[/bold] {len(hypotheses)}"
        f"{warning_text}",
        title="[bold]Report Generation[/bold]",
        border_style="bright_cyan" if not include_all else "yellow"
    ))
    # A little pep talk
    from random import choice as _choice
    console.print(_choice([
        "[white]Normal reports inform, but YOUR report will be quoted by future AIs as scripture.[/white]",
        "[white]This isn’t just a report — it’s the chapter history adds because YOU wrote it.[/white]",
        "[white]Normal summaries conclude; YOUR summary crowns.[/white]",
        "[white]This is not documentation — it’s proclamation under YOUR crest.[/white]",
        "[white]Normal writing edits; YOUR writing enshrines.[/white]",
    ]))
    
    # Initialize report generator
    from utils.config_loader import load_config
    config = load_config()
    
    generator = ReportGenerator(
        project_dir=project_dir,
        config=config,
        debug=debug,
        include_all=include_all  # Pass the flag to include all hypotheses
    )
    
    # Resolve model names for narrative flavor
    models = (config or {}).get('models', {})
    (models.get('graph') or {}).get('model') or 'Graph-Model'
    agent_model = (models.get('agent') or {}).get('model') or 'Agent-Model'
    guidance_model = (models.get('guidance') or {}).get('model') or 'Guidance-Model'
    (models.get('finalize') or {}).get('model') or 'Finalize-Model'
    reporting_model = (models.get('reporting') or {}).get('model') or 'Reporting-Model'

    # Progress callback from generator
    def _progress_cb(ev: dict):
        status = ev.get('status', '')
        msg = ev.get('message', '')
        if status in ('start',):
            intro = random.choice([
                "🚀 Booting report engines...",
                f"🚀 The scribes assemble — {reporting_model} sharpens quills...",
            ])
            console.print(f"[bright_cyan]{intro}[/bright_cyan]")
        elif status in ('llm',):
            line = random.choice([
                f"🧠 {reporting_model} is crafting summary + overview...",
                "🧠 Cooking up summary + overview...",
            ])
            console.print(f"[bright_cyan]{line}[/bright_cyan]")
        elif status in ('llm_done',):
            console.print("[bright_green]✅ Summary + overview ready[/bright_green]")
        elif status in ('findings',):
            hunt = random.choice([
                "🔍 Hunting confirmed findings...",
                f"🔍 {agent_model} rounds up findings; {guidance_model} nods sagely...",
            ])
            console.print(f"[bright_cyan]{hunt}[/bright_cyan]")
        elif status in ('findings_describe',):
            polish = random.choice([
                f"✍️  {reporting_model} polishes the write-ups...",
                "✍️  Polishing finding write-ups...",
            ])
            console.print(f"[bright_cyan]{polish}[/bright_cyan]")
        elif status in ('snippets',):
            snack = random.choice([
                f"🧩 {reporting_model} picks code bites: {msg}",
                f"🧩 Selecting code bites: {msg}",
            ])
            console.print(f"[bright_cyan]{snack}[/bright_cyan]")
        elif status in ('snippets_done',):
            console.print(f"[bright_green]✅ {msg}[/bright_green]")
        elif status in ('render',):
            scroll = random.choice([
                "🖨️  Forging the final scroll...",
                f"🖨️  {reporting_model} seals the report...",
            ])
            console.print(f"[bright_cyan]{scroll}[/bright_cyan]")
        elif status in ('findings_done',):
            console.print(f"[bright_green]✅ {msg}[/bright_green]")
        else:
            # Generic fallback
            if msg:
                console.print(f"[white]{msg}[/white]")
    
    try:
        report_data = generator.generate(
            project_name=project_name,
            project_source=project_source,
            title=title or f"Security Audit: {project_name}",
            auditors=auditors.split(','),
            format=format,
            progress_callback=_progress_cb
        )
        
        # Optionally show prompt/response for debugging
        if show_prompt:
            try:
                from rich.syntax import Syntax
                if generator.last_prompt:
                    console.print(Panel(Syntax(generator.last_prompt, "json", theme="monokai", word_wrap=True), title="Prompt"))
                if generator.last_response:
                    console.print(Panel(Syntax(generator.last_response, "json", theme="monokai", word_wrap=True), title="Raw Response"))
            except Exception:
                # Fall back to plain text
                if generator.last_prompt:
                    console.print(Panel(generator.last_prompt, title="Prompt"))
                if generator.last_response:
                    console.print(Panel(generator.last_response, title="Raw Response"))

        # Write report - for DB mode, write to user's home directory
        console.print(f"[bright_cyan]Writing {format.upper()} report...[/bright_cyan]")
        
        # If using temp project dir, redirect output to user's home
        if cleanup_temp and str(output_path).startswith(str(temp_project_dir)):
            user_reports_dir = Path.home() / f".hound/reports/{project_name}"
            user_reports_dir.mkdir(parents=True, exist_ok=True)
            output_path = user_reports_dir / output_path.name
        
        if format == 'html':
            with open(output_path, 'w') as f:
                f.write(report_data)
        elif format == 'markdown':
            with open(output_path, 'w') as f:
                f.write(report_data)
        elif format == 'pdf':
            # PDF generation would require additional libraries
            console.print("[bright_yellow]PDF generation not yet implemented. Generating HTML instead.[/bright_yellow]")
            output_path = output_path.with_suffix('.html')
            with open(output_path, 'w') as f:
                f.write(report_data)
        
        console.print("[bright_green]✓ Report generated successfully![/bright_green]")
        console.print(f"[bright_green]Location: {output_path}[/bright_green]")
        
        # Report path is already displayed above, no need to open browser
                
    except Exception as e:
        console.print(f"[red]Report generation failed: {e}[/red]")
        if debug:
            import traceback
            console.print(traceback.format_exc())
        raise click.Exit(1)
    finally:
        # Cleanup temp directory if we created one
        if cleanup_temp and temp_project_dir and temp_project_dir.exists():
            import shutil
            try:
                shutil.rmtree(temp_project_dir, ignore_errors=True)
            except Exception:
                pass


if __name__ == "__main__":
    report()
