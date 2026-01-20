"""
Celery tasks for Hound SaaS worker.

Contains the main background tasks for running audits and surface scans.
These tasks are executed by the Celery worker fleet, separate from the web server.
"""

import os
import sys
import json
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# Ensure the app root is in Python path for imports (needed for Celery fork workers)
_app_root = Path(__file__).parent.parent
if str(_app_root) not in sys.path:
    sys.path.insert(0, str(_app_root))

from celery import Task
from celery.exceptions import SoftTimeLimitExceeded

from .celery_app import celery_app
from .redis_publisher import RedisPublisher


class AuditTask(Task):
    """
    Base class for audit tasks with shared setup and error handling.
    
    Provides:
    - Automatic Redis publisher setup
    - Database session management
    - Error reporting
    """
    
    _db_engine = None
    
    @property
    def db_engine(self):
        """Lazy database engine initialization."""
        if self._db_engine is None:
            from database.models import create_db_engine
            db_url = os.environ.get("DATABASE_URL", "sqlite:///hound.db")
            self._db_engine = create_db_engine(db_url)
        return self._db_engine
    
    def get_db_session(self):
        """Get a database session."""
        from database.models import create_db_session
        return create_db_session(self.db_engine)
    
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Handle task failure - update database and publish error."""
        scan_id = kwargs.get('scan_id') or (args[1] if len(args) > 1 else None)
        if scan_id:
            publisher = RedisPublisher(scan_id)
            publisher.publish_status("failed", str(exc))
            publisher.publish_error(str(exc), "task_failure")
            publisher.close()
            
            # Update database
            self._update_scan_status(scan_id, "failed", error_message=str(exc))
    
    def on_success(self, retval, task_id, args, kwargs):
        """Handle task success."""
        scan_id = kwargs.get('scan_id') or (args[1] if len(args) > 1 else None)
        if scan_id:
            publisher = RedisPublisher(scan_id)
            publisher.publish_status("completed", "Audit completed successfully")
            publisher.close()
    
    def _update_scan_status(
        self,
        scan_id: str,
        status: str,
        error_message: Optional[str] = None,
        **extra_fields
    ):
        """Update scan execution status in database."""
        try:
            from database.models import ScanExecution, AuditSession
            
            db = self.get_db_session()
            try:
                # Try ScanExecution first (for surface scans)
                scan = db.query(ScanExecution).filter_by(execution_id=scan_id).first()
                if scan:
                    scan.status = status
                    if error_message:
                        scan.error_message = error_message
                    if status == "completed":
                        scan.completed_at = datetime.now(timezone.utc)
                    for key, value in extra_fields.items():
                        if hasattr(scan, key):
                            setattr(scan, key, value)
                    db.commit()
                    return
                
                # Try AuditSession (for full audits)
                session = db.query(AuditSession).filter_by(session_id=scan_id).first()
                if session:
                    session.status = status
                    if status == "completed":
                        session.end_time = datetime.now(timezone.utc)
                    db.commit()
            finally:
                db.close()
        except Exception as e:
            # Log but don't fail the task
            print(f"Failed to update scan status: {e}")


@celery_app.task(bind=True, base=AuditTask, name="worker.tasks.execute_audit_task")
def execute_audit_task(
    self,
    repo_url: str,
    scan_id: str,
    tenant_id: int,
    project_id: Optional[int] = None,
    config: Optional[dict] = None,
    max_iterations: int = 50,
    investigation_prompt: Optional[str] = None,
    installation_id: Optional[int] = None,
    pr_number: Optional[int] = None,
    repo_full_name: Optional[str] = None,
) -> dict:
    """
    Execute a full autonomous security audit.
    
    This task:
    1. Clones the repository (with GitHub App auth if installation_id provided)
    2. Builds knowledge graphs
    3. Runs the AutonomousAgent investigation loop
    4. Publishes live updates to Redis
    5. Stores results in the database
    6. Posts findings to PR (if pr_number provided)
    
    Args:
        repo_url: Git repository URL or local path
        scan_id: Unique identifier for this audit (session_id)
        tenant_id: Tenant ID for multi-tenancy
        project_id: Optional project ID if linked to existing project
        config: LLM configuration dict
        max_iterations: Maximum agent iterations
        investigation_prompt: Custom investigation prompt
        installation_id: GitHub App installation ID for private repo access
        pr_number: PR number to post findings to (optional)
        repo_full_name: Repository full name (owner/repo) for PR comments
        
    Returns:
        dict with audit results summary
    """
    import tempfile
    import shutil
    
    publisher = RedisPublisher(scan_id)
    temp_dir = None
    
    try:
        # Publish start status
        publisher.publish_status("running", "Starting audit...")
        self._update_scan_status(scan_id, "running")
        
        # Step 1: Resolve repository path
        publisher.publish_thought("Resolving repository location...", iteration=0)
        
        if repo_url.startswith(("http://", "https://", "git@")):
            # Clone repository
            temp_dir = tempfile.mkdtemp(prefix="hound_audit_")
            repo_path = Path(temp_dir) / "repo"
            
            # If installation_id provided, use GitHub App authentication
            clone_url = repo_url
            if installation_id and repo_url.startswith("https://"):
                try:
                    from integrations.github_auth import get_clone_url_with_token
                    clone_url = get_clone_url_with_token(repo_url, installation_id)
                    publisher.publish_thought(
                        "Using GitHub App authentication for private repository",
                        iteration=0
                    )
                except Exception as auth_err:
                    publisher.publish_thought(
                        f"Auth setup failed, trying public clone: {auth_err}",
                        iteration=0
                    )
            
            publisher.publish_thought(f"Cloning repository: {repo_url}", iteration=0)
            
            import subprocess
            result = subprocess.run(
                ["git", "clone", "--depth", "1", clone_url, str(repo_path)],
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout for clone
            )
            
            if result.returncode != 0:
                raise RuntimeError(f"Git clone failed: {result.stderr}")
        else:
            repo_path = Path(repo_url)
            if not repo_path.exists():
                raise FileNotFoundError(f"Repository path not found: {repo_url}")
        
        # Step 2: Create project structure
        publisher.publish_thought("Setting up project structure...", iteration=0)
        
        project_dir = Path(temp_dir or repo_path.parent) / f".hound_project_{scan_id}"
        project_dir.mkdir(parents=True, exist_ok=True)
        
        graphs_dir = project_dir / "graphs"
        manifest_dir = project_dir / "manifest"
        graphs_dir.mkdir(exist_ok=True)
        manifest_dir.mkdir(exist_ok=True)
        
        from utils.config_loader import load_config
        from database.models import Graph, create_db_engine, create_db_session
        
        # Load config
        if config is None:
            config = load_config()
        
        # Check if graphs already exist in database for this project
        existing_graphs = []
        if project_id:
            try:
                db_url = os.environ.get("DATABASE_URL", "sqlite:///hound.db")
                engine = create_db_engine(db_url)
                db = create_db_session(engine)
                existing_graphs = db.query(Graph).filter(Graph.project_id == project_id).all()
                db.close()
            except Exception as e:
                publisher.publish_thought(f"Warning: Could not check existing graphs: {e}", iteration=0)
        
        knowledge_graphs_path = graphs_dir / "knowledge_graphs.json"
        
        # Always create manifest first - we need it for code access
        from ingest.manifest import RepositoryManifest
        from ingest.bundles import AdaptiveBundler
        
        publisher.publish_thought("Creating repository manifest...", iteration=0)
        manifest = RepositoryManifest(repo_path, config)
        manifest.walk_repository()
        manifest.save_manifest(manifest_dir)
        
        if existing_graphs and len(existing_graphs) >= 2:
            # Graphs already exist - load from database instead of rebuilding
            publisher.publish_thought(
                f"Found {len(existing_graphs)} existing graphs in database, skipping graph build phase...",
                iteration=0
            )
            publisher.publish_status("running", "Loading existing graphs")
            
            # Write graphs to disk from database
            graphs_index = {}
            for graph in existing_graphs:
                graph_name = graph.internal_name or graph.name.lower().replace(" ", "_")
                graph_path = graphs_dir / f"graph_{graph_name}.json"
                with open(graph_path, "w") as f:
                    json.dump(graph.data, f, indent=2)
                graphs_index[graph_name] = str(graph_path)
            
            # Create knowledge_graphs.json index
            with open(knowledge_graphs_path, "w") as f:
                json.dump({"graphs": graphs_index}, f, indent=2)
            
            publisher.publish_thought(
                f"Loaded {len(existing_graphs)} graphs from database - ready for audit",
                iteration=0
            )
        else:
            # No existing graphs - build them from scratch
            publisher.publish_thought("Building knowledge graphs...", iteration=0)
            publisher.publish_status("running", "Building knowledge graphs")
            
            from analysis.graph_builder import GraphBuilder
            
            # Create bundles
            bundler = AdaptiveBundler(manifest.cards, manifest.files, config)
            bundles = bundler.create_bundles()
            
            publisher.publish_thought(f"Created {len(bundles)} code bundles, building full knowledge graphs...", iteration=0)
            
            # Build graphs - always do full build (not init_only) for comprehensive coverage
            builder = GraphBuilder(config=config)
            
            # Create a progress callback for graph building
            def graph_progress_callback(update: dict):
                """Forward graph builder progress to Redis."""
                msg_type = update.get('type', 'progress')
                message = update.get('message', '')
                if msg_type == 'graph_started':
                    publisher.publish_thought(f"Building graph: {update.get('graph_name', 'unknown')}", iteration=0)
                elif msg_type == 'graph_completed':
                    publisher.publish_thought(f"Completed graph: {update.get('graph_name', 'unknown')}", iteration=0)
                elif msg_type == 'refinement':
                    publisher.publish_thought(f"Refining: {message}", iteration=0)
                else:
                    publisher.publish_thought(message or "Processing graphs...", iteration=0)
            
            builder.build(
                manifest_dir=manifest_dir,
                output_dir=graphs_dir,
                max_iterations=5,  # Full refinement iterations
                max_graphs=3,      # SystemArchitecture + AssetFlow + PermissionChecks
                progress_callback=graph_progress_callback,
            )
            
            # Create knowledge_graphs.json index
            graph_files = list(graphs_dir.glob("graph_*.json"))
            graphs_index = {
                gf.stem.replace("graph_", ""): str(gf)
                for gf in graph_files
            }
            
            with open(knowledge_graphs_path, "w") as f:
                json.dump({"graphs": graphs_index}, f, indent=2)
            
            publisher.publish_thought(
                f"Built {len(graph_files)} knowledge graphs",
                iteration=0
            )
            
            # Store graphs in database if project_id provided
            if project_id:
                try:
                    db_url = os.environ.get("DATABASE_URL", "sqlite:///hound.db")
                    engine = create_db_engine(db_url)
                    db = create_db_session(engine)
                    
                    for gf in graph_files:
                        with open(gf, "r") as f:
                            graph_data = json.load(f)
                        
                        graph_name = gf.stem.replace("graph_", "")
                        
                        # Check if graph already exists for this project
                        existing = db.query(Graph).filter(
                            Graph.project_id == project_id,
                            Graph.internal_name == graph_name
                        ).first()
                        
                        if existing:
                            # Update existing graph
                            existing.data = graph_data
                            existing.updated_at = datetime.now()
                        else:
                            # Create new graph
                            db_graph = Graph(
                                project_id=project_id,
                                name=graph_name.replace("_", " ").title(),
                                internal_name=graph_name,
                                data=graph_data,
                            )
                            db.add(db_graph)
                    
                    db.commit()
                    db.close()
                    publisher.publish_thought(f"Stored {len(graph_files)} graphs in database", iteration=0)
                except Exception as e:
                    publisher.publish_thought(f"Warning: Failed to store graphs in DB: {e}", iteration=0)
        
        # Step 4: Initialize and run autonomous agent
        publisher.publish_status("running", "Starting autonomous investigation")
        
        from analysis.agent_core import AutonomousAgent
        
        agent = AutonomousAgent(
            graphs_metadata_path=knowledge_graphs_path,
            manifest_path=manifest_dir,
            agent_id=f"worker_{scan_id}",
            config=config,
            debug=False,
            session_id=scan_id,
            redis_publisher=publisher,  # Pass publisher for internal Redis updates
        )
        
        # Set up progress callback that publishes to Redis
        def progress_callback(update: dict):
            """Forward agent progress to Redis."""
            status = update.get("status", "")
            iteration = update.get("iteration", 0)
            message = update.get("message", "")
            
            print(f"[ProgressCallback] status={status}, iteration={iteration}, msg={message[:50] if message else ''}")
            
            if status == "decision":
                publisher.publish_decision(
                    action=update.get("action", ""),
                    reasoning=update.get("reasoning", ""),
                    parameters=update.get("parameters", {}),
                    iteration=iteration,
                )
            elif status == "result":
                publisher.publish_action_result(
                    action=update.get("action", ""),
                    result=update.get("result", {}),
                    iteration=iteration,
                )
            elif status == "hypothesis_formed":
                # Extract hypothesis details if available
                publisher.publish_thought(message, iteration=iteration)
            elif status == "usage":
                # Parse usage message for token info
                publisher.publish_thought(f"Context: {message}", iteration=iteration)
            elif status == "analyzing":
                publisher.publish_thought(message, iteration=iteration)
            elif status == "executing":
                publisher.publish_action_start(update.get("action", ""), iteration=iteration)
            elif status == "complete":
                publisher.publish_status("completing", message)
            else:
                publisher.publish_thought(message, iteration=iteration)
        
        # Default investigation prompt
        if not investigation_prompt:
            investigation_prompt = """
            Perform a comprehensive security audit of this codebase.
            
            Focus on:
            1. Access control vulnerabilities
            2. Input validation issues
            3. State management problems
            4. Economic/financial exploits (if applicable)
            5. Logic errors and edge cases
            
            Form hypotheses for any potential vulnerabilities found.
            Prioritize high-severity issues.
            """
        
        # Run investigation
        publisher.publish_thought("Starting investigation...", iteration=1)
        
        print(f"[DEBUG] Calling agent.investigate with max_iterations={max_iterations}")
        
        result = agent.investigate(
            prompt=investigation_prompt,
            max_iterations=max_iterations,
            progress_callback=progress_callback,
        )
        
        # Log investigation result for debugging
        iterations_completed = result.get("iterations_completed", 0)
        print(f"[DEBUG] Investigation completed after {iterations_completed} iterations")
        print(f"[DEBUG] Graphs analyzed: {result.get('graphs_analyzed', [])}")
        print(f"[DEBUG] Nodes analyzed: {result.get('nodes_analyzed', 0)}")
        print(f"[DEBUG] Hypotheses summary: {result.get('hypotheses', {})}")
        
        # Step 5: Collect and store results
        # detailed_hypotheses contains the actual list, hypotheses is just a summary dict
        hypotheses = result.get("detailed_hypotheses", [])
        print(f"[DEBUG] detailed_hypotheses count: {len(hypotheses)}")
        if hypotheses:
            print(f"[DEBUG] First hypothesis sample: {hypotheses[0]}")
        
        # Store hypotheses in database
        print(f"[DEBUG] Storing {len(hypotheses)} hypotheses to DB for project_id={project_id}")
        _store_hypotheses_in_db(
            self.get_db_session,
            project_id,
            hypotheses,
            scan_id,
        )
        print(f"[DEBUG] Hypothesis storage complete")
        
        # Step 6: Post findings to PR if requested
        pr_result = None
        if installation_id and pr_number and repo_full_name and hypotheses:
            try:
                from integrations.pr_bot import post_findings_to_pr
                
                # Convert hypotheses to findings format
                findings = _convert_hypotheses_to_findings(hypotheses)
                
                publisher.publish_thought(
                    f"Posting {len(findings)} findings to PR #{pr_number}",
                    iteration=result.get("iterations", 0)
                )
                
                pr_result = post_findings_to_pr(
                    installation_id=installation_id,
                    repo_full_name=repo_full_name,
                    pr_number=pr_number,
                    findings=findings,
                    scan_id=scan_id,
                )
                
                publisher.publish_thought(
                    f"PR comments posted: {pr_result.get('inline_comments_posted', 0)} inline, "
                    f"summary: {pr_result.get('summary_posted', False)}",
                    iteration=result.get("iterations", 0)
                )
            except Exception as pr_err:
                publisher.publish_thought(
                    f"Failed to post PR comments: {pr_err}",
                    iteration=result.get("iterations", 0)
                )
        
        # Update final status
        self._update_scan_status(
            scan_id,
            "completed",
            findings=hypotheses,
            summary=f"Found {len(hypotheses)} potential issues",
        )
        
        publisher.publish_status(
            "completed",
            f"Audit complete. Found {len(hypotheses)} potential vulnerabilities."
        )
        
        return {
            "status": "completed",
            "scan_id": scan_id,
            "hypotheses_count": len(hypotheses),
            "iterations": result.get("iterations_completed", 0),
            "hypotheses": hypotheses,
            "pr_result": pr_result,
        }
        
    except SoftTimeLimitExceeded:
        publisher.publish_error("Audit timed out", "timeout")
        publisher.publish_status("failed", "Audit exceeded time limit")
        self._update_scan_status(scan_id, "failed", error_message="Time limit exceeded")
        raise
        
    except Exception as e:
        error_msg = f"{type(e).__name__}: {str(e)}"
        publisher.publish_error(error_msg, "execution_error")
        publisher.publish_status("failed", error_msg)
        self._update_scan_status(scan_id, "failed", error_message=error_msg)
        
        # Log full traceback for debugging
        print(f"Audit task failed: {error_msg}")
        traceback.print_exc()
        
        raise
        
    finally:
        # Cleanup
        publisher.close()
        
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
            except Exception:
                pass


@celery_app.task(bind=True, base=AuditTask, name="worker.tasks.execute_scan_task")
def execute_scan_task(
    self,
    repo_url: str,
    scan_id: str,
    tenant_id: int,
    llm_budget: int = 5,
    model: Optional[str] = None,
) -> dict:
    """
    Execute a lightweight surface scan.
    
    This is faster and cheaper than a full audit, designed for
    lead generation and preliminary assessment.
    
    Args:
        repo_url: Git repository URL or local path
        scan_id: Unique identifier for this scan
        tenant_id: Tenant ID for multi-tenancy
        llm_budget: Maximum LLM calls (default: 5)
        model: LLM model to use (default: gpt-4o-mini)
        
    Returns:
        dict with scan results
    """
    publisher = RedisPublisher(scan_id)
    
    try:
        publisher.publish_status("running", "Starting surface scan...")
        self._update_scan_status(scan_id, "running")
        
        from analysis.surface import SurfaceScanner
        from utils.config_loader import load_config
        
        config = load_config()
        
        scanner = SurfaceScanner(
            config=config,
            llm_budget=llm_budget,
            model=model or "gpt-4o-mini",
            quiet=True,
        )
        
        # Run scan
        publisher.publish_thought(f"Scanning repository: {repo_url}", iteration=1)
        result = scanner.scan(repo_url)
        
        # Convert result to dict
        result_dict = result.model_dump() if hasattr(result, "model_dump") else result.dict()
        
        # Update database
        self._update_scan_status(
            scan_id,
            "completed",
            risk_score=result_dict.get("risk_score"),
            risk_level=result_dict.get("risk_level"),
            findings=result_dict.get("findings"),
            quality_metrics=result_dict.get("quality_metrics"),
            summary=result_dict.get("summary"),
            contracts_scanned=result_dict.get("contracts_scanned", 0),
            contracts_total=result_dict.get("contracts_total", 0),
        )
        
        publisher.publish_status(
            "completed",
            f"Scan complete. Risk score: {result_dict.get('risk_score', 0)}"
        )
        
        return {
            "status": "completed",
            "scan_id": scan_id,
            **result_dict,
        }
        
    except Exception as e:
        error_msg = str(e)
        publisher.publish_error(error_msg, "scan_error")
        publisher.publish_status("failed", error_msg)
        self._update_scan_status(scan_id, "failed", error_message=error_msg)
        raise
        
    finally:
        publisher.close()


def _store_hypotheses_in_db(
    get_db_session,
    project_id: Optional[int],
    hypotheses: list,
    session_id: str,
):
    """Store hypotheses in the database."""
    print(f"[DEBUG _store_hypotheses_in_db] Called with project_id={project_id}, hypotheses_count={len(hypotheses) if hypotheses else 0}")
    if not project_id or not hypotheses:
        print(f"[DEBUG _store_hypotheses_in_db] Early return: project_id={project_id}, hypotheses={bool(hypotheses)}")
        return
    
    try:
        from database.models import Hypothesis
        
        db = get_db_session()
        try:
            for i, hyp in enumerate(hypotheses):
                print(f"[DEBUG _store_hypotheses_in_db] Storing hypothesis {i}: {hyp.get('description', '')[:50]}...")
                db_hyp = Hypothesis(
                    project_id=project_id,
                    hypothesis_id=hyp.get("id") or f"{session_id}_hyp_{i}",
                    title=hyp.get("description", "Unknown")[:512],
                    description=hyp.get("description", ""),
                    vulnerability_type=hyp.get("vulnerability_type", "unknown"),
                    status=hyp.get("status", "proposed"),
                    confidence=float(hyp.get("confidence", 0.5)),
                    severity=hyp.get("severity", "medium"),
                    node_refs=hyp.get("node_ids", []),
                    evidence={"items": hyp.get("evidence", [])},
                )
                db.add(db_hyp)
            
            db.commit()
            print(f"[DEBUG _store_hypotheses_in_db] Successfully committed {len(hypotheses)} hypotheses to DB")
        finally:
            db.close()
    except Exception as e:
        print(f"Failed to store hypotheses: {e}")
        import traceback
        traceback.print_exc()


def _convert_hypotheses_to_findings(hypotheses: list) -> list[dict]:
    """
    Convert agent hypotheses to findings format expected by PR bot.
    
    Args:
        hypotheses: List of hypothesis dicts from agent
        
    Returns:
        List of finding dicts for PR bot
    """
    findings = []
    
    for hyp in hypotheses:
        # Only include confirmed/high-confidence findings
        status = hyp.get("status", "proposed")
        confidence = hyp.get("confidence", 0.5)
        
        # Include confirmed or high-confidence hypotheses
        if status not in ("confirmed", "high_confidence") and confidence < 0.7:
            continue
        
        finding = {
            "id": hyp.get("id", ""),
            "title": hyp.get("title") or hyp.get("description", "")[:80],
            "description": hyp.get("description", ""),
            "severity": hyp.get("severity", "medium"),
            "type": hyp.get("vulnerability_type", "unknown"),
            "confidence": confidence,
            "affected": hyp.get("node_ids", []) or hyp.get("node_refs", []),
            "code_samples": [],
        }
        
        # Extract code samples from evidence if available
        evidence = hyp.get("evidence", [])
        for ev in evidence[:3]:  # Limit to 3 samples
            if isinstance(ev, dict) and "code" in ev:
                finding["code_samples"].append({
                    "path": ev.get("file", ""),
                    "code": ev.get("code", ""),
                    "start_line": ev.get("line"),
                })
            elif isinstance(ev, str) and ":" in ev:
                # Node reference format
                finding["code_samples"].append({
                    "path": ev.split(":")[0],
                    "code": "",
                    "start_line": int(ev.split(":")[1]) if ev.split(":")[1].isdigit() else None,
                })
        
        findings.append(finding)
    
    return findings


@celery_app.task(bind=True, base=AuditTask, name="worker.tasks.build_graphs_task")
def build_graphs_task(
    self,
    repo_url: str,
    scan_id: str,
    tenant_id: int,
    project_id: Optional[int] = None,
    config: Optional[dict] = None,
    max_iterations: int = 5,
    num_graphs: int = 3,
    init_only: bool = False,
    installation_id: Optional[int] = None,
) -> dict:
    """
    Build knowledge graphs for a repository without running the full audit.
    
    This is a prerequisite step that can be run separately from the audit.
    Useful for:
    - Pre-building graphs for faster subsequent audits
    - Inspecting the codebase structure before committing to full audit
    - Building graphs with custom configuration
    
    Args:
        repo_url: Git repository URL or local path
        scan_id: Unique identifier for this build
        tenant_id: Tenant ID for multi-tenancy
        project_id: Optional project ID to link to
        config: Optional LLM configuration override
        max_iterations: Maximum graph refinement iterations
        num_graphs: Number of graphs to build (2 = SystemArchitecture + 1)
        init_only: If True, only build SystemArchitecture graph
        installation_id: GitHub App installation ID for private repos
        
    Returns:
        dict with status, graphs_path, and graph_count
    """
    import shutil
    import subprocess
    import tempfile
    
    publisher = RedisPublisher(scan_id)
    temp_dir = None
    
    try:
        publisher.publish_status("running", "Starting graph build")
        publisher.publish_thought("Initializing graph build task...", iteration=0)
        
        # Step 1: Clone or locate repository
        if repo_url.startswith(("http://", "https://", "git@")):
            publisher.publish_thought(f"Cloning repository: {repo_url}", iteration=0)
            temp_dir = tempfile.mkdtemp(prefix="hound_graphs_")
            repo_path = Path(temp_dir) / "repo"
            
            # Get GitHub App token if installation_id provided
            clone_url = repo_url
            if installation_id:
                try:
                    from integrations.github_auth import get_installation_token
                    token = get_installation_token(installation_id)
                    if token and "github.com" in repo_url:
                        clone_url = repo_url.replace(
                            "https://github.com",
                            f"https://x-access-token:{token}@github.com"
                        )
                except Exception as e:
                    publisher.publish_thought(f"Warning: Could not get GitHub token: {e}", iteration=0)
            
            result = subprocess.run(
                ["git", "clone", "--depth", "1", clone_url, str(repo_path)],
                capture_output=True,
                text=True,
                timeout=300,
            )
            
            if result.returncode != 0:
                raise RuntimeError(f"Git clone failed: {result.stderr}")
        else:
            repo_path = Path(repo_url).expanduser().resolve()
            if not repo_path.exists():
                raise ValueError(f"Repository path does not exist: {repo_path}")
        
        publisher.publish_thought(f"Repository ready at: {repo_path}", iteration=0)
        
        # Step 2: Create output structure
        project_dir = Path(temp_dir or repo_path.parent) / f".hound_graphs_{scan_id}"
        project_dir.mkdir(parents=True, exist_ok=True)
        
        graphs_dir = project_dir / "graphs"
        manifest_dir = project_dir / "manifest"
        graphs_dir.mkdir(exist_ok=True)
        manifest_dir.mkdir(exist_ok=True)
        
        # Step 3: Build manifest
        publisher.publish_status("running", "Scanning repository")
        publisher.publish_thought("Creating repository manifest...", iteration=0)
        
        from utils.config_loader import load_config
        from ingest.manifest import RepositoryManifest
        from ingest.bundles import AdaptiveBundler
        from analysis.graph_builder import GraphBuilder
        
        if config is None:
            config = load_config()
        
        manifest = RepositoryManifest(repo_path, config)
        manifest.walk_repository()
        manifest.save_manifest(manifest_dir)
        
        file_count = len(manifest.cards) if hasattr(manifest, 'cards') else 0
        publisher.publish_thought(f"Manifest created with {file_count} cards", iteration=0)
        
        # Step 4: Create bundles
        publisher.publish_status("running", "Creating code bundles")
        publisher.publish_thought("Bundling code for analysis...", iteration=0)
        
        bundler = AdaptiveBundler(manifest.cards, manifest.files, config)
        bundles = bundler.create_bundles()
        
        publisher.publish_thought(f"Created {len(bundles)} bundles", iteration=0)
        
        # Step 5: Build graphs
        publisher.publish_status("running", "Building knowledge graphs")
        
        if init_only:
            publisher.publish_thought("Building SystemArchitecture graph only (init mode)...", iteration=0)
            actual_num_graphs = 1
        else:
            publisher.publish_thought(f"Building {num_graphs} knowledge graphs...", iteration=0)
            actual_num_graphs = num_graphs
        
        builder = GraphBuilder(config=config)
        
        build_result = builder.build(
            manifest_dir=manifest_dir,
            output_dir=graphs_dir,
            max_iterations=max_iterations,
            max_graphs=actual_num_graphs,
        )
        
        # Step 6: Create knowledge_graphs.json index
        graph_files = list(graphs_dir.glob("graph_*.json"))
        graphs_index = {
            gf.stem.replace("graph_", ""): str(gf)
            for gf in graph_files
        }
        
        knowledge_graphs_path = graphs_dir / "knowledge_graphs.json"
        with open(knowledge_graphs_path, "w") as f:
            json.dump({"graphs": graphs_index}, f, indent=2)
        
        publisher.publish_thought(
            f"Successfully built {len(graph_files)} knowledge graphs",
            iteration=0
        )
        
        # Step 7: Store graphs in database if project_id provided
        if project_id:
            try:
                from database.models import Graph, create_db_engine, create_db_session
                
                db_url = os.environ.get("DATABASE_URL", "sqlite:///hound.db")
                engine = create_db_engine(db_url)
                db = create_db_session(engine)
                
                for gf in graph_files:
                    with open(gf) as f:
                        graph_data = json.load(f)
                    
                    graph_name = gf.stem.replace("graph_", "")
                    
                    # Check if graph already exists
                    existing = db.query(Graph).filter_by(
                        project_id=project_id,
                        internal_name=graph_name
                    ).first()
                    
                    if existing:
                        existing.data = graph_data
                        existing.updated_at = datetime.now(timezone.utc)
                    else:
                        db_graph = Graph(
                            project_id=project_id,
                            name=graph_data.get("name", graph_name),
                            internal_name=graph_name,
                            data=graph_data,
                        )
                        db.add(db_graph)
                
                db.commit()
                db.close()
                
                publisher.publish_thought(
                    f"Stored {len(graph_files)} graphs in database",
                    iteration=0
                )
            except Exception as e:
                publisher.publish_thought(f"Warning: Could not store graphs in DB: {e}", iteration=0)
        
        publisher.publish_status("completed", f"Built {len(graph_files)} graphs successfully")
        
        return {
            "status": "completed",
            "scan_id": scan_id,
            "graphs_path": str(graphs_dir),
            "graph_count": len(graph_files),
            "graph_names": list(graphs_index.keys()),
        }
        
    except Exception as e:
        error_msg = str(e)
        publisher.publish_status("failed", error_msg)
        publisher.publish_error(error_msg, "build_graphs_error")
        
        # Log full traceback
        import traceback
        tb = traceback.format_exc()
        print(f"Graph build task failed: {tb}")
        
        return {
            "status": "failed",
            "scan_id": scan_id,
            "error": error_msg,
        }
        
    finally:
        publisher.close()
        
        # Note: We don't clean up temp_dir here as the graphs may be needed
        # Cleanup should happen after audit completes or via scheduled task
