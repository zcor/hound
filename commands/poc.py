"""
Proof-of-Concept management for confirmed vulnerabilities
"""

import json
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

console = Console()

@dataclass
class PoCContext:
    """Context for PoC generation"""
    project_name: str
    hypothesis: dict[str, Any]
    affected_files: dict[str, str]  # filepath -> content
    manifest_data: dict[str, Any]
    repo_root: Path | None = None  # Optional repo root for direct file loading


def load_affected_files(hypothesis: dict[str, Any], manifest_data: dict[str, Any], repo_root: Path | None = None) -> dict[str, str]:
    """Load content of files affected by the vulnerability"""
    affected_files = {}
    
    # Get unique file paths from annotations
    file_paths = set()
    for annotation in hypothesis.get('annotations', []):
        if annotation.get('file_path'):
            file_paths.add(annotation['file_path'])
    
    # Also get files from locations if present
    for location in hypothesis.get('locations', []):
        if isinstance(location, dict) and location.get('file'):
            file_paths.add(location['file'])
    
    # Also check node_refs
    for ref in hypothesis.get('node_refs', []):
        if isinstance(ref, str):
            # Could be "file:line" or just "file"
            file_path = ref.split(':')[0] if ':' in ref else ref
            if file_path and not file_path.startswith('#'):
                file_paths.add(file_path)
    
    # Try to find files from hypothesis description/evidence using guess_relpaths
    if repo_root:
        try:
            from analysis.path_utils import guess_relpaths
            text_sources = [
                hypothesis.get('title', ''),
                hypothesis.get('description', ''),
            ]
            evidence = hypothesis.get('evidence') or {}
            for item in evidence.get('items', []):
                if isinstance(item, str):
                    text_sources.append(item)
                elif isinstance(item, dict):
                    text_sources.append(item.get('description', ''))
            
            guessed = guess_relpaths("\n".join(text_sources), repo_root)
            for rel in guessed:
                file_paths.add(rel)
        except Exception:
            pass
        
        # Scan repo for files containing keywords from hypothesis (if no paths found yet)
        if not file_paths:
            try:
                # Extract potential contract/function names from hypothesis text
                title = hypothesis.get('title', '').lower()
                description = hypothesis.get('description', '').lower()
                combined = f"{title} {description}"
                
                # Look for camelCase or PascalCase identifiers
                import re
                identifiers = set(re.findall(r'\b([A-Za-z][a-zA-Z0-9]*(?:[A-Z][a-zA-Z0-9]*)+)\b', f"{hypothesis.get('title', '')} {hypothesis.get('description', '')}"))
                
                # Also extract simple keywords that might be file names
                keywords = set()
                for word in re.findall(r'\b([a-zA-Z]{4,20})\b', combined):
                    if word not in {'this', 'that', 'with', 'from', 'allows', 'which', 'could', 'would', 'should', 'using', 'funds', 'tokens'}:
                        keywords.add(word)
                
                # Scan contracts directory for matching files
                contracts_dir = repo_root / 'contracts'
                if contracts_dir.exists():
                    for sol_file in contracts_dir.glob('*.sol'):
                        file_lower = sol_file.stem.lower()
                        # Check if any keyword matches
                        for kw in keywords | {i.lower() for i in identifiers}:
                            if kw in file_lower or file_lower in kw:
                                rel_path = sol_file.relative_to(repo_root)
                                file_paths.add(str(rel_path))
                                break
                
                # Also check src directory
                src_dir = repo_root / 'src'
                if src_dir.exists():
                    for ext in ['sol', 'rs', 'vy']:
                        for src_file in src_dir.rglob(f'*.{ext}'):
                            file_lower = src_file.stem.lower()
                            for kw in keywords | {i.lower() for i in identifiers}:
                                if kw in file_lower or file_lower in kw:
                                    rel_path = src_file.relative_to(repo_root)
                                    file_paths.add(str(rel_path))
                                    break
            except Exception:
                pass
    
    # Load file contents - try manifest first, then direct file read
    for file_path in file_paths:
        file_key = str(file_path)
        
        # Try manifest first
        if file_key in manifest_data.get('files', {}):
            file_info = manifest_data['files'][file_key]
            if isinstance(file_info, dict) and 'content' in file_info:
                affected_files[file_path] = file_info['content']
            elif isinstance(file_info, str):
                affected_files[file_path] = file_info
        # Try direct file read from repo_root
        elif repo_root:
            full_path = repo_root / file_path
            if full_path.exists() and full_path.is_file():
                try:
                    with open(full_path) as f:
                        content = f.read()
                        # Limit file size
                        if len(content) < 100000:
                            affected_files[file_path] = content
                except Exception:
                    pass
    
    return affected_files


def generate_poc_with_strategist(context: PoCContext, config: dict[str, Any]) -> str:
    """Use strategist model to generate PoC prompt"""
    
    from llm.unified_client import UnifiedLLMClient
    
    # Initialize strategist model
    llm = UnifiedLLMClient(cfg=config, profile="strategist")
    
    # Build context for strategist
    hypothesis = context.hypothesis
    
    # Build list of affected files (using project-relative paths)
    affected_files_list = list(context.affected_files.keys())
    
    # Format affected files for context
    files_context = ""
    for file_path, content in context.affected_files.items():
        # Include relevant portions of the file with project-relative path
        files_context += f"\n\n=== {file_path} ===\n"
        # Truncate very long files, focus on relevant parts
        if len(content) > 5000:
            # Try to find relevant sections based on annotations
            relevant_lines = set()
            for ann in hypothesis.get('annotations', []):
                if ann.get('file_path') == file_path and ann.get('line'):
                    # Include context around the line
                    line_num = ann['line']
                    for i in range(max(0, line_num - 20), min(len(content.split('\n')), line_num + 20)):
                        relevant_lines.add(i)
            
            if relevant_lines:
                lines = content.split('\n')
                files_context += "... (showing relevant sections) ...\n"
                for i in sorted(relevant_lines):
                    if i < len(lines):
                        files_context += f"{i+1}: {lines[i]}\n"
            else:
                # Just show first 100 lines if no specific annotations
                files_context += '\n'.join(content.split('\n')[:100])
                files_context += "\n... (truncated) ..."
        else:
            files_context += content
    
    # Create prompt for strategist
    strategist_prompt = f"""
You are a security expert creating a detailed prompt for a coding agent to generate a proof-of-concept exploit.

VULNERABILITY DETAILS:
Title: {hypothesis.get('title', 'Unknown')}
Type: {hypothesis.get('vulnerability_type', 'Unknown')}
Severity: {hypothesis.get('severity', 'Unknown')}
Confidence: {hypothesis.get('confidence', 0)}

DESCRIPTION:
{hypothesis.get('description', '')}

REASONING:
{hypothesis.get('reasoning', '')}

PROJECT STRUCTURE - EXISTING FILES CONTAINING THE VULNERABILITY:
The following files ALREADY EXIST in the project (paths shown relative to project root):
{chr(10).join('- ' + f for f in affected_files_list)}

IMPORTANT: These files are ALREADY PRESENT in the project filesystem at the paths shown above. 
DO NOT ask the coding agent to create or recreate these files.
The coding agent should ONLY create a NEW test/exploit file that interacts with these existing vulnerable files.

RELEVANT CODE FROM AFFECTED FILES:
{files_context}

Your task is to create a comprehensive prompt for a coding agent (like Claude Code) that will:
1. Generate a NEW proof-of-concept test/exploit file that demonstrates the vulnerability
2. The PoC must interact with the EXISTING vulnerable code (DO NOT recreate the vulnerable contracts/files)
3. Include all necessary setup, attack sequence, and verification steps
4. Be well-commented to explain each step of the exploit
5. Work in the appropriate language/framework for the codebase

CRITICAL INSTRUCTIONS for your prompt:
- Start with: "The following files ALREADY EXIST in the project and contain the vulnerability: [list files]"
- Then say: "DO NOT create or modify these existing files. They are the TARGET of our exploit."
- Then say: "Your task is to CREATE A NEW test/exploit file that demonstrates the vulnerability in these existing files."
- Be explicit about which file to CREATE (e.g., "Create a new file called test/ExploitPoC.sol")
- List the specific vulnerable functions/methods to TARGET (not create) in the existing files
- Describe how the new PoC file should interact with the existing vulnerable code
- Include expected outcomes and success criteria

Your prompt MUST make this distinction crystal clear:
- EXISTING FILES (contain vulnerability, DO NOT create): [list with full paths]
- NEW FILE TO CREATE (the PoC): [specify name and location]

Format your response as a complete prompt that can be directly given to a coding agent.
Start with the clarification about existing vs new files before any other instructions.
"""
    
    # Get response from strategist
    response = llm.raw(system="You are a security expert creating detailed proof-of-concept prompts. ALWAYS make it clear that the vulnerable files already exist and should NOT be created - only the PoC file should be created.", user=strategist_prompt)
    
    return response


def _load_hypotheses_from_db(project_name: str, hypothesis_id: str | None = None) -> tuple[dict, dict, Path | None]:
    """
    Load hypotheses from database.
    
    Returns: (hypotheses_dict, manifest_data, repo_root)
    """
    import os
    from sqlalchemy import create_engine, text
    
    database_url = os.environ.get("DATABASE_URL", "")
    if not database_url:
        return None, {}, None
    
    try:
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
                return None, {}, None
            
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
                    import subprocess
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
                            console.print(f"[dim]Cloned successfully[/dim]")
                        else:
                            console.print(f"[yellow]Clone failed: {result.stderr[:100]}[/yellow]")
                    except Exception as e:
                        console.print(f"[yellow]Clone error: {e}[/yellow]")
            
            # Get hypotheses
            if hypothesis_id:
                result = conn.execute(text("""
                    SELECT hypothesis_id, title, description, vulnerability_type, 
                           status, confidence, severity, node_refs, evidence
                    FROM hypotheses 
                    WHERE project_id = :pid AND hypothesis_id = :hid
                """), {"pid": project_id, "hid": hypothesis_id})
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
            
            hypotheses = {}
            for row in rows:
                hid, title, description, vuln_type, status, confidence, severity, node_refs, evidence = row
                hypotheses[hid] = {
                    'title': title,
                    'description': description,
                    'vulnerability_type': vuln_type,
                    'status': status,
                    'confidence': confidence,
                    'severity': severity,
                    'node_refs': node_refs or [],
                    'evidence': evidence or {},
                    'annotations': [],  # Build from node_refs
                    'locations': [],
                }
                # Convert node_refs to annotations format
                if node_refs:
                    for ref in node_refs:
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
            
            return hypotheses, {}, repo_root
            
    except Exception as e:
        console.print(f"[yellow]Database lookup failed: {e}[/yellow]")
        return None, {}, None


def make_prompt(project_name: str, hypothesis_id: str | None = None, config: dict[str, Any] | None = None):
    """Generate PoC prompts for vulnerabilities"""
    
    # Try loading from database first
    db_hypotheses, manifest_data, repo_root = _load_hypotheses_from_db(project_name, hypothesis_id)
    
    # Fall back to filesystem
    from pathlib import Path
    home_dir = Path.home()
    project_dir = home_dir / f".hound/projects/{project_name}"
    
    if db_hypotheses is not None:
        # Use database data
        console.print(f"[dim]Loading from database...[/dim]")
        hypotheses = db_hypotheses
        
        # Create output directory - use project_dir if exists, else temp
        if project_dir.exists():
            output_dir = project_dir / "poc_prompts"
        else:
            output_dir = Path.home() / f".hound/poc_prompts/{project_name}"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Load manifest from repo if available
        if repo_root:
            manifest_file = repo_root / "manifest.json"
            if manifest_file.exists():
                with open(manifest_file) as f:
                    manifest_data = json.load(f)
            # Also try loading file contents directly from repo
            for hid, hyp in hypotheses.items():
                for ann in hyp.get('annotations', []):
                    file_path = ann.get('file_path')
                    if file_path and file_path not in manifest_data.get('files', {}):
                        full_path = repo_root / file_path
                        if full_path.exists():
                            try:
                                with open(full_path) as f:
                                    if 'files' not in manifest_data:
                                        manifest_data['files'] = {}
                                    manifest_data['files'][file_path] = f.read()
                            except Exception:
                                pass
    else:
        # Use filesystem
        if not project_dir.exists():
            console.print(f"[red]Project '{project_name}' not found[/red]")
            console.print("[dim]Checked: filesystem and database[/dim]")
            sys.exit(1)
        
        # Load hypotheses
        store_file = project_dir / "hypotheses.json"
        if not store_file.exists():
            console.print("[red]No hypotheses found for project[/red]")
            sys.exit(1)
        
        with open(store_file) as f:
            data = json.load(f)
        
        # Load manifest
        manifest_file = project_dir / "manifest" / "manifest.json"
        manifest_data = {}
        if manifest_file.exists():
            with open(manifest_file) as f:
                manifest_data = json.load(f)
        else:
            console.print("[yellow]Warning: No manifest found[/yellow]")
        
        # Filter hypotheses
        if hypothesis_id:
            # Generate for specific hypothesis
            if hypothesis_id not in data.get('hypotheses', {}):
                console.print(f"[red]Hypothesis {hypothesis_id} not found[/red]")
                sys.exit(1)
            hypotheses = {hypothesis_id: data['hypotheses'][hypothesis_id]}
        else:
            # Generate for all confirmed vulnerabilities
            hypotheses = {
                hid: hyp for hid, hyp in data.get('hypotheses', {}).items()
                if hyp.get('status') == 'confirmed'
            }
        
        output_dir = project_dir / "poc_prompts"
        output_dir.mkdir(exist_ok=True)
    
    # Check if we have hypotheses
    if not hypotheses:
        # If no confirmed, let user select from high-confidence ones
        if db_hypotheses is None:
            # Filesystem mode - try high confidence
            high_conf = {
                hid: hyp for hid, hyp in data.get('hypotheses', {}).items()
                if hyp.get('confidence', 0) >= 0.7
            }
        else:
            # Database mode - already filtered
            high_conf = db_hypotheses
        
        if high_conf:
            console.print("[yellow]No confirmed vulnerabilities. High-confidence hypotheses:[/yellow]")
            for hid, hyp in high_conf.items():
                console.print(f"  {hid}: {hyp.get('title', '')[:60]} (conf: {hyp.get('confidence', 0):.2f})")
            
            hypothesis_id = Prompt.ask("Select hypothesis ID to generate PoC for")
            if hypothesis_id in high_conf:
                hypotheses = {hypothesis_id: high_conf[hypothesis_id]}
            else:
                console.print("[red]Invalid hypothesis ID[/red]")
                sys.exit(1)
        else:
            console.print("[red]No vulnerabilities found suitable for PoC generation[/red]")
            sys.exit(1)
    
    # Generate prompts
    console.print(f"\n[bold]Generating PoC prompts for {len(hypotheses)} vulnerabilit{'y' if len(hypotheses) == 1 else 'ies'}...[/bold]\n")
    
    for hid, hypothesis in hypotheses.items():
        console.print(f"Processing {hid}: [cyan]{hypothesis.get('title', '')[:60]}[/cyan]")
        
        # Load affected files (pass repo_root if available)
        affected_files = load_affected_files(hypothesis, manifest_data, repo_root)
        console.print(f"  Loading {len(affected_files)} affected files...")
        
        # Create context
        context = PoCContext(
            project_name=project_name,
            hypothesis=hypothesis,
            affected_files=affected_files,
            manifest_data=manifest_data,
            repo_root=repo_root
        )
        
        # Generate prompt using strategist
        console.print("  Generating prompt with strategist model...")
        try:
            prompt = generate_poc_with_strategist(context, config or {})
            
            # Save prompt
            output_file = output_dir / f"{hid}_poc_prompt.md"
            with open(output_file, 'w') as f:
                f.write(f"# PoC Generation Prompt for {hid}\n\n")
                f.write(f"**Project:** {project_name}\n")
                f.write(f"**Vulnerability:** {hypothesis.get('title', 'Unknown')}\n")
                f.write(f"**Type:** {hypothesis.get('vulnerability_type', 'Unknown')}\n")
                f.write(f"**Severity:** {hypothesis.get('severity', 'Unknown')}\n\n")
                f.write("---\n\n")
                f.write(prompt)
            
            console.print(f"  [green]✓[/green] Saved to {output_file}")
            
            # If single hypothesis, also display the prompt
            if len(hypotheses) == 1:
                console.print(Panel(prompt, title="Generated PoC Prompt", border_style="green"))
                console.print(f"\n[dim]Prompt saved to: {output_file}[/dim]")
                console.print("[dim]Copy this prompt to Claude Code or another coding agent to generate the PoC.[/dim]")
            
        except Exception as e:
            console.print(f"  [red]✗ Error generating prompt: {e}[/red]")
            continue
    
    if len(hypotheses) > 1:
        console.print(f"\n[green]✓ Generated {len(hypotheses)} PoC prompts in {output_dir}[/green]")
        console.print("[dim]Copy these prompts to Claude Code or another coding agent to generate the PoCs.[/dim]")


def import_poc(project_name: str, hypothesis_id: str, files: list[str], description: str | None = None):
    """Import PoC files for a specific hypothesis"""
    
    # Load project data
    home_dir = Path.home()
    project_dir = home_dir / f".hound/projects/{project_name}"
    if not project_dir.exists():
        console.print(f"[red]Project '{project_name}' not found[/red]")
        sys.exit(1)
    
    # Load hypotheses to validate hypothesis ID
    store_file = project_dir / "hypotheses.json"
    if not store_file.exists():
        console.print("[red]No hypotheses found for project[/red]")
        sys.exit(1)
    
    with open(store_file) as f:
        data = json.load(f)
    
    if hypothesis_id not in data.get('hypotheses', {}):
        console.print(f"[red]Hypothesis {hypothesis_id} not found[/red]")
        # Show available hypotheses
        console.print("\n[yellow]Available hypotheses:[/yellow]")
        for hid, hyp in data.get('hypotheses', {}).items():
            status = hyp.get('status', 'active')
            conf = hyp.get('confidence', 0)
            console.print(f"  {hid}: {hyp.get('title', '')[:60]} (status: {status}, conf: {conf:.2f})")
        sys.exit(1)
    
    hypothesis = data['hypotheses'][hypothesis_id]
    
    # Create PoC directory for this hypothesis
    poc_dir = project_dir / "poc" / hypothesis_id
    poc_dir.mkdir(parents=True, exist_ok=True)
    
    # Load or create metadata
    metadata_file = poc_dir / "metadata.json"
    if metadata_file.exists():
        with open(metadata_file) as f:
            metadata = json.load(f)
    else:
        metadata = {
            "hypothesis_id": hypothesis_id,
            "title": hypothesis.get('title', 'Unknown'),
            "files": [],
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
    
    # Import files
    imported_files = []
    for file_path in files:
        source = Path(file_path)
        if not source.exists():
            console.print(f"[red]File not found: {file_path}[/red]")
            continue
        
        # Copy file to PoC directory
        dest = poc_dir / source.name
        
        # Handle duplicate names
        if dest.exists():
            # Ask user what to do
            action = Prompt.ask(
                f"File {source.name} already exists. Choose action",
                choices=["overwrite", "rename", "skip"],
                default="skip"
            )
            
            if action == "skip":
                console.print(f"  Skipping {source.name}")
                continue
            elif action == "rename":
                # Generate unique name
                base = source.stem
                ext = source.suffix
                counter = 1
                while dest.exists():
                    dest = poc_dir / f"{base}_{counter}{ext}"
                    counter += 1
        
        shutil.copy2(source, dest)
        imported_files.append(dest.name)
        console.print(f"  Imported: {source.name} -> {dest.name}")
        
        # Add to metadata
        file_entry = {
            "name": dest.name,
            "original_path": str(source.absolute()),
            "imported_at": datetime.now().isoformat(),
            "description": description
        }
        
        # Check if file already in metadata and update or append
        existing = next((f for f in metadata['files'] if f['name'] == dest.name), None)
        if existing:
            existing.update(file_entry)
        else:
            metadata['files'].append(file_entry)
    
    # Update metadata
    metadata['updated_at'] = datetime.now().isoformat()
    
    # Save metadata
    with open(metadata_file, 'w') as f:
        json.dump(metadata, f, indent=2)
    
    console.print(f"\n[green]Successfully imported {len(imported_files)} file(s) for hypothesis {hypothesis_id}[/green]")
    console.print(f"[dim]PoC files stored in: {poc_dir}[/dim]")
    
    return imported_files


def list_pocs(project_name: str):
    """List all PoCs for a project"""
    
    home_dir = Path.home()
    project_dir = home_dir / f".hound/projects/{project_name}"
    if not project_dir.exists():
        console.print(f"[red]Project '{project_name}' not found[/red]")
        sys.exit(1)
    
    poc_base_dir = project_dir / "poc"
    if not poc_base_dir.exists():
        console.print("[yellow]No PoCs found for this project[/yellow]")
        return
    
    # Create table
    table = Table(title=f"PoCs for project: {project_name}")
    table.add_column("Hypothesis ID", style="cyan")
    table.add_column("Title", style="white")
    table.add_column("Files", style="green")
    table.add_column("Last Updated", style="dim")
    
    # Scan PoC directories
    for hyp_dir in sorted(poc_base_dir.iterdir()):
        if not hyp_dir.is_dir():
            continue
        
        hypothesis_id = hyp_dir.name
        metadata_file = hyp_dir / "metadata.json"
        
        if metadata_file.exists():
            with open(metadata_file) as f:
                metadata = json.load(f)
            
            title = metadata.get('title', 'Unknown')[:40]
            num_files = len(metadata.get('files', []))
            updated = metadata.get('updated_at', 'Unknown')
            
            # Format the date if possible
            try:
                dt = datetime.fromisoformat(updated)
                updated = dt.strftime("%Y-%m-%d %H:%M")
            except Exception:
                pass
            
            table.add_row(hypothesis_id, title, str(num_files), updated)
    
    console.print(table)


def run(project_name: str, hypothesis_id: str | None = None, config: dict[str, Any] | None = None, subcommand: str = "make-prompt", files: list[str] | None = None, description: str | None = None):
    """Main entry point for PoC commands"""
    
    if subcommand == "make-prompt":
        make_prompt(project_name, hypothesis_id, config)
    elif subcommand == "import":
        if not hypothesis_id:
            console.print("[red]--hypothesis/-h is required for import command[/red]")
            sys.exit(1)
        if not files:
            console.print("[red]No files specified to import[/red]")
            sys.exit(1)
        import_poc(project_name, hypothesis_id, files, description)
    elif subcommand == "list":
        list_pocs(project_name)
    else:
        console.print(f"[red]Unknown subcommand: {subcommand}[/red]")
        console.print("Available subcommands: make-prompt, import, list")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        console.print("Usage: python poc.py <project_name> <subcommand> [options]")
        console.print("Subcommands: make-prompt, import, list")
        sys.exit(1)
    
    project = sys.argv[1]
    subcommand = sys.argv[2]
    
    if subcommand == "make-prompt":
        hyp_id = sys.argv[3] if len(sys.argv) > 3 else None
        run(project, hyp_id, subcommand=subcommand)
    elif subcommand == "import":
        if len(sys.argv) < 5:
            console.print("Usage: python poc.py <project_name> import <hypothesis_id> <file1> [file2 ...]")
            sys.exit(1)
        hyp_id = sys.argv[3]
        files = sys.argv[4:]
        run(project, hyp_id, subcommand=subcommand, files=files)
    elif subcommand == "list":
        run(project, subcommand=subcommand)
    else:
        console.print(f"Unknown subcommand: {subcommand}")
        sys.exit(1)
