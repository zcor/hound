"""
Celery tasks for Hound SaaS worker.

Contains the main background tasks for running audits and surface scans.
These tasks are executed by the Celery worker fleet, separate from the web server.
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure the app root is in Python path for imports (needed for Celery fork workers)
_app_root = Path(__file__).parent.parent
if str(_app_root) not in sys.path:
    sys.path.insert(0, str(_app_root))

from celery import Task  # noqa: E402
from celery.exceptions import SoftTimeLimitExceeded  # noqa: E402

from .celery_app import celery_app  # noqa: E402
from .redis_publisher import RedisPublisher  # noqa: E402

from llm.token_tracker import set_token_context, clear_token_context  # noqa: E402


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
            
            # Refund credit if this scan consumed one
            self._refund_if_credit_used(scan_id)
        
        # Clear token context on failure
        clear_token_context()
    
    def _refund_if_credit_used(self, scan_id: str):
        """Refund a scan credit if the failed scan consumed one."""
        try:
            from database.models import ScanExecution
            from server.tier_enforcement import refund_scan_credit
            
            db = self.get_db_session()
            try:
                scan = db.query(ScanExecution).filter_by(execution_id=scan_id).first()
                if scan and scan.scan_config and scan.scan_config.get("uses_credit"):
                    refund_scan_credit(db, scan.tenant_id, scan_id)
                    print(f"Refunded scan credit for tenant {scan.tenant_id} (scan {scan_id})")
            finally:
                db.close()
        except Exception as e:
            print(f"Failed to refund scan credit: {e}")
    
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
        error_message: str | None = None,
        **extra_fields
    ):
        """Update scan execution status in database."""
        try:
            from database.models import AuditSession, ScanExecution
            
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
    project_id: int | None = None,
    config: dict | None = None,
    max_iterations: int = 30,
    investigation_prompt: str | None = None,
    installation_id: int | None = None,
    pr_number: int | None = None,
    repo_full_name: str | None = None,
    time_limit_minutes: int = 120,
    mode: str = "sweep",
    plan_n: int = 5,
) -> dict:
    """
    Execute a full autonomous security audit with planning loop.
    
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
    import shutil
    import tempfile
    
    publisher = RedisPublisher(scan_id)
    temp_dir = None
    
    try:
        # Set token tracking context for cost attribution
        set_token_context(
            project_id=project_id,
            session_id=scan_id,
            tenant_id=tenant_id,
            endpoint="audit",
        )
        
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
            clone_result = subprocess.run(
                ["git", "clone", "--depth", "1", clone_url, str(repo_path)],
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout for clone
            )
            
            if clone_result.returncode != 0:
                raise RuntimeError(f"Git clone failed: {clone_result.stderr}")
        else:
            repo_path = Path(repo_url).expanduser().resolve()
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
        
        from database.models import Graph, create_db_engine, create_db_session
        from utils.config_loader import load_config
        
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
        from ingest.bundles import AdaptiveBundler
        from ingest.manifest import RepositoryManifest
        
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
                        with open(gf) as f:
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
        
        # Step 4: Initialize and run autonomous agent with planning loop
        # This mirrors the CLI's AgentRunner behavior with Strategist planning
        publisher.publish_status("running", f"Starting autonomous investigation (mode={mode})")
        
        from analysis.agent_core import AutonomousAgent
        from analysis.strategist import Strategist
        
        agent = AutonomousAgent(
            graphs_metadata_path=knowledge_graphs_path,
            manifest_path=manifest_dir,
            agent_id=f"worker_{scan_id}",
            config=config,
            debug=False,
            session_id=scan_id,
            redis_publisher=publisher,
        )
        
        # Initialize strategist for planning investigations
        strategist = Strategist(config=config, debug=False, session_id=scan_id)
        
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
                publisher.publish_thought(message, iteration=iteration)
            elif status == "usage":
                publisher.publish_thought(f"Context: {message}", iteration=iteration)
            elif status == "analyzing":
                publisher.publish_thought(message, iteration=iteration)
            elif status == "executing":
                publisher.publish_action_start(update.get("action", ""), iteration=iteration)
            elif status == "complete":
                publisher.publish_status("completing", message)
            else:
                publisher.publish_thought(message, iteration=iteration)
        
        # Planning loop - mirrors CLI's AgentRunner.run() behavior
        import time as time_module
        start_overall = time_module.time()
        completed_investigations = []
        all_hypotheses = []
        planned_round = 0
        total_iterations = 0
        consecutive_empty_rounds = 0
        last_round_goals = set()
        
        # Default investigation prompt for strategist context
        if not investigation_prompt:
            investigation_prompt = """
            Perform a comprehensive security audit of this codebase.
            Focus on: access control, input validation, state management,
            economic/financial exploits, and logic errors.
            """
        
        publisher.publish_thought(f"Starting {mode} mode audit with {time_limit_minutes} minute time limit", iteration=0)
        
        while True:
            # Time limit check
            elapsed_minutes = (time_module.time() - start_overall) / 60.0
            if elapsed_minutes >= time_limit_minutes:
                publisher.publish_thought(f"Time limit reached ({time_limit_minutes} minutes) — stopping audit", iteration=total_iterations)
                break
            
            planned_round += 1
            publisher.publish_thought(f"Planning round {planned_round} ({mode} mode, {elapsed_minutes:.1f}/{time_limit_minutes} min)", iteration=total_iterations)
            
            # Get coverage stats for strategist context
            try:
                coverage = agent.get_coverage_stats() if hasattr(agent, 'get_coverage_stats') else {}
            except Exception:
                coverage = {}
            
            # Determine phase based on mode
            phase = 'Coverage' if mode == 'sweep' else 'Saliency'
            
            # Build context for strategist - use available_graphs for complete list
            graphs_summary = []
            try:
                # First add the auto-loaded system graph
                if agent.loaded_data.get('system_graph'):
                    sys_graph = agent.loaded_data['system_graph']
                    data = sys_graph.get('data', {})
                    nodes = data.get('nodes', []) or []
                    edges = data.get('edges', []) or []
                    graphs_summary.append(f"{sys_graph['name']}: {len(nodes)} nodes, {len(edges)} edges")
                
                # Then add any other available graphs
                for graph_name, graph_meta in (agent.available_graphs or {}).items():
                    # Skip if already added as system graph
                    if agent.loaded_data.get('system_graph') and graph_name == agent.loaded_data['system_graph']['name']:
                        continue
                    # Load graph data to get node/edge counts
                    try:
                        graph_path = Path(graph_meta['path'])
                        if graph_path.exists():
                            with open(graph_path) as f:
                                gdata = json.load(f)
                            nodes = gdata.get('nodes', []) or []
                            edges = gdata.get('edges', []) or []
                            graphs_summary.append(f"{graph_name}: {len(nodes)} nodes, {len(edges)} edges")
                    except Exception:
                        graphs_summary.append(f"{graph_name}: (available)")
            except Exception as e:
                print(f"[DEBUG] Error building graphs_summary: {e}")
            
            print(f"[DEBUG] Graphs summary for strategist: {graphs_summary}")
            
            # Get planning from strategist
            try:
                # Build graphs summary string
                graphs_summary_str = "\n".join(graphs_summary) if graphs_summary else "(no graphs loaded)"
                
                # Get hypotheses summary
                hyp_summary = f"{len(all_hypotheses)} hypotheses found so far"
                if all_hypotheses:
                    recent = [h.get('title', '') for h in all_hypotheses[-3:] if isinstance(h, dict)]
                    if recent:
                        hyp_summary += f" (recent: {', '.join(recent)})"
                
                # Coverage summary
                cov_summary = ""
                try:
                    nodes_cov = coverage.get('nodes', {})
                    cov_summary = f"Nodes: {nodes_cov.get('visited', 0)}/{nodes_cov.get('total', 0)} ({nodes_cov.get('percent', 0):.0f}%)"
                except Exception:
                    cov_summary = "(no coverage data)"
                
                items = strategist.plan_next(
                    graphs_summary=graphs_summary_str,
                    completed=completed_investigations,
                    n=plan_n,
                    hypotheses_summary=hyp_summary,
                    coverage_summary=cov_summary,
                    phase_hint=phase,
                )
                
                if not items:
                    publisher.publish_thought("No further investigations suggested — checking completion", iteration=total_iterations)
                    consecutive_empty_rounds += 1
                    if consecutive_empty_rounds >= 2:
                        publisher.publish_thought(f"{mode.capitalize()} mode complete - no new targets", iteration=total_iterations)
                        break
                else:
                    consecutive_empty_rounds = 0
                    publisher.publish_thought(f"Strategist planned {len(items)} investigations", iteration=total_iterations)
                    
            except Exception as e:
                publisher.publish_thought(f"Strategist planning failed: {e}, falling back to default", iteration=total_iterations)
                import traceback
                traceback.print_exc()
                # Fallback: create a default investigation
                items = [{'goal': investigation_prompt, 'priority': 1}]
            
            # Check for planning loop (same goals repeated)
            current_round_goals = set(it.get('goal', '') if isinstance(it, dict) else getattr(it, 'goal', '') for it in items)
            if current_round_goals == last_round_goals and last_round_goals:
                consecutive_empty_rounds += 1
                if consecutive_empty_rounds >= 2:
                    publisher.publish_thought(f"Detected planning loop - {mode} mode complete", iteration=total_iterations)
                    break
            else:
                last_round_goals = current_round_goals
            
            # Execute each planned investigation
            for i, item in enumerate(items):
                # Time check before each investigation
                elapsed_minutes = (time_module.time() - start_overall) / 60.0
                if elapsed_minutes >= time_limit_minutes:
                    publisher.publish_thought("Time limit reached during investigation", iteration=total_iterations)
                    break
                
                goal = item.get('goal', '') if isinstance(item, dict) else getattr(item, 'goal', '')
                item.get('priority', 0) if isinstance(item, dict) else getattr(item, 'priority', 0)
                
                if goal in completed_investigations:
                    continue  # Skip already completed
                
                publisher.publish_thought(f"Investigation {i+1}/{len(items)}: {goal[:100]}", iteration=total_iterations)
                
                try:
                    # Reset agent state for new investigation
                    agent.reset_for_new_investigation()
                    
                    # Run investigation
                    result = agent.investigate(
                        prompt=goal,
                        max_iterations=max_iterations,
                        progress_callback=progress_callback,
                    )
                    
                    total_iterations += result.get("iterations_completed", 0)
                    
                    # Collect hypotheses
                    hyps = result.get("detailed_hypotheses", [])
                    all_hypotheses.extend(hyps)
                    
                    completed_investigations.append(goal)
                    publisher.publish_thought(f"Investigation complete: {len(hyps)} hypotheses found", iteration=total_iterations)
                    
                except Exception as e:
                    publisher.publish_thought(f"Investigation failed: {e}", iteration=total_iterations)
                    completed_investigations.append(goal)  # Mark as done to avoid retry
            
            # Sweep mode completion check
            if mode == 'sweep' and planned_round > 1:
                # Check if we've covered all major components
                try:
                    sys_graph = agent.loaded_data.get('graphs', {}).get('SystemArchitecture', {})
                    gdata = sys_graph.get('data', {}) if isinstance(sys_graph, dict) else {}
                    nodes = gdata.get('nodes', []) or []
                    # Count high-level components
                    comp_types = {'contract', 'component', 'module', 'class', 'service'}
                    components = [n for n in nodes if n.get('type', '').lower() in comp_types]
                    
                    if components and len(completed_investigations) >= len(components):
                        publisher.publish_thought(f"Sweep mode: all {len(components)} components analyzed", iteration=total_iterations)
                        break
                except Exception:
                    pass
            
            # Debug: log why we're continuing or breaking
            elapsed_minutes = (time_module.time() - start_overall) / 60.0
            print(f"[DEBUG] End of round {planned_round}: elapsed={elapsed_minutes:.1f}min, limit={time_limit_minutes}min, completed={len(completed_investigations)}, continuing to next round...")
        
        # Log investigation result for debugging
        print(f"[DEBUG] Full audit completed after {total_iterations} total iterations, {planned_round} rounds")
        print(f"[DEBUG] Investigations completed: {len(completed_investigations)}")
        print(f"[DEBUG] Total hypotheses: {len(all_hypotheses)}")
        
        # Deduplicate hypotheses by description (detailed_hypotheses uses 'description' not 'title')
        seen_descriptions = set()
        hypotheses = []
        for h in all_hypotheses:
            # Use description for dedup (title field may not exist in detailed_hypotheses format)
            desc = h.get('description', '') if isinstance(h, dict) else ''
            if desc and desc not in seen_descriptions:
                seen_descriptions.add(desc)
                hypotheses.append(h)
        
        print(f"[DEBUG] After dedup: {len(hypotheses)} unique hypotheses")
        
        # Store hypotheses in database
        print(f"[DEBUG] Storing {len(hypotheses)} hypotheses to DB for project_id={project_id}")
        _store_hypotheses_in_db(
            self.get_db_session,
            project_id,
            hypotheses,
            scan_id,
        )
        print("[DEBUG] Hypothesis storage complete")
        
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
            "iterations": total_iterations,
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
        clear_token_context()
        
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
    model: str | None = None,
    pr_number: int | None = None,
    repo_full_name: str | None = None,
    installation_id: int | None = None,
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
        
        # Set token tracking context for cost attribution
        set_token_context(
            session_id=scan_id,
            tenant_id=tenant_id,
            endpoint="scan",
        )
        
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

        # Redact then truncate scan log
        raw_log = result_dict.get("scan_log") or ""
        from analysis.surface.scanner import _redact_log, _truncate_log
        safe_log = _truncate_log(_redact_log(raw_log)) if raw_log else None

        # If scanner returned an error, mark as failed
        scan_error = result_dict.get("error")
        final_status = "failed" if scan_error else "completed"

        # Update database
        self._update_scan_status(
            scan_id,
            final_status,
            risk_score=result_dict.get("risk_score"),
            risk_level=result_dict.get("risk_level"),
            findings=result_dict.get("findings"),
            quality_metrics=result_dict.get("quality_metrics"),
            summary=result_dict.get("summary"),
            contracts_scanned=result_dict.get("contracts_scanned", 0),
            contracts_total=result_dict.get("contracts_total", 0),
            scan_log=safe_log,
            error_message=scan_error,
        )

        publisher.publish_status(
            final_status,
            scan_error or f"Scan complete. Risk score: {result_dict.get('risk_score', 0)}"
        )

        # Post findings to PR if this was triggered by a PR event
        if pr_number and repo_full_name and installation_id:
            try:
                from integrations.pr_bot import PRCommentBot
                bot = PRCommentBot(
                    installation_id=installation_id,
                    repo_full_name=repo_full_name,
                    pr_number=pr_number,
                )
                # Convert surface findings to the format PRCommentBot expects
                pr_findings = []
                for f in result_dict.get("findings", []):
                    pr_findings.append({
                        "title": f.get("title", ""),
                        "severity": f.get("severity", "medium"),
                        "type": f.get("category", "vulnerability"),
                        "confidence": f.get("confidence", 0.5),
                        "description": f.get("description", ""),
                        "location": f.get("location", ""),
                    })
                bot.post_findings(
                    pr_findings,
                    scan_id=scan_id,
                    include_inline=False,  # v1: summary only
                    include_summary=True,
                    delete_previous=False,  # We use find-and-update instead
                )
                publisher.publish_thought("PR comment posted", iteration=1)
            except Exception as e:
                # Non-fatal: scan succeeded even if PR comment fails
                print(f"Failed to post PR comment: {e}")

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
        clear_token_context()


def _store_hypotheses_in_db(
    get_db_session,
    project_id: int | None,
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
    project_id: int | None = None,
    config: dict | None = None,
    max_iterations: int = 5,
    num_graphs: int = 3,
    init_only: bool = False,
    installation_id: int | None = None,
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
    import subprocess
    import tempfile
    
    publisher = RedisPublisher(scan_id)
    temp_dir = None
    
    try:
        publisher.publish_status("running", "Starting graph build")
        publisher.publish_thought("Initializing graph build task...", iteration=0)
        
        # Set token tracking context for cost attribution
        set_token_context(
            project_id=project_id,
            session_id=scan_id,
            tenant_id=tenant_id,
            endpoint="build_graphs",
        )
        
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
        
        from analysis.graph_builder import GraphBuilder
        from ingest.bundles import AdaptiveBundler
        from ingest.manifest import RepositoryManifest
        from utils.config_loader import load_config
        
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
        
        builder.build(
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
        clear_token_context()
        
        # Note: We don't clean up temp_dir here as the graphs may be needed
        # Cleanup should happen after audit completes or via scheduled task
