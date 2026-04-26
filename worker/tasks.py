"""
Celery tasks for Hound SaaS worker.

Contains the main background tasks for running audits and surface scans.
These tasks are executed by the Celery worker fleet, separate from the web server.
"""

import asyncio
import json
import os
import re
import sys
import time
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Ensure the app root is in Python path for imports (needed for Celery fork workers)
_app_root = Path(__file__).parent.parent
if str(_app_root) not in sys.path:
    sys.path.insert(0, str(_app_root))

from celery import Task  # noqa: E402
from celery.exceptions import SoftTimeLimitExceeded  # noqa: E402

from integrations.telegram import (  # noqa: E402
    notify_deep_audit_completed,
    notify_deep_audit_flagged,
)
from llm.token_tracker import clear_token_context, set_token_context  # noqa: E402

from .celery_app import celery_app  # noqa: E402
from .redis_publisher import RedisPublisher  # noqa: E402


def resolve_scan_github_token(
    db_session_factory,
    tenant_id: int,
    installation_id: int | None = None,
    github_user_id: int | None = None,
) -> str | None:
    """Resolve the best GitHub token for a surface scan.

    Prefer a GitHub App installation token for private org repos. If no
    installation is available, fall back to the acting user's stored GitHub OAuth
    token, but only within the same tenant.
    """
    if installation_id:
        from integrations.github_auth import get_installation_token

        return get_installation_token(installation_id)

    if not github_user_id:
        return None

    from database.models import User
    from server.token_crypto import decrypt_token

    db = db_session_factory()
    try:
        user = db.query(User).filter(
            User.id == github_user_id,
            User.tenant_id == tenant_id,
        ).first()
        if not user or not user.github_token_encrypted:
            return None
        return decrypt_token(user.github_token_encrypted)
    finally:
        db.close()


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
        """Handle task success — read actual status from DB before publishing."""
        scan_id = kwargs.get('scan_id') or (args[1] if len(args) > 1 else None)
        if scan_id:
            # Read actual status — task may have set in_review or failed early
            actual_status = "completed"
            try:
                from database.models import AuditSession, ScanExecution
                db = self.get_db_session()
                try:
                    scan = db.query(ScanExecution).filter_by(execution_id=scan_id).first()
                    if scan:
                        actual_status = scan.status
                    else:
                        session = db.query(AuditSession).filter_by(session_id=scan_id).first()
                        if session:
                            actual_status = session.status
                finally:
                    db.close()
            except Exception:
                pass

            # Don't publish success for scans that already set a terminal status
            if actual_status == "failed":
                return

            msg = {
                "in_review": "Audit complete — results under review",
                "completed": "Audit completed successfully",
            }.get(actual_status, f"Audit finished with status: {actual_status}")

            publisher = RedisPublisher(scan_id)
            publisher.publish_status(actual_status, msg)
            publisher.close()
    
    def _update_scan_status(
        self,
        scan_id: str,
        status: str,
        error_message: str | None = None,
        **extra_fields
    ):
        """Update scan execution status in database.

        Updates BOTH ScanExecution and AuditSession in one transaction.
        Deep audits have both records; surface scans only have ScanExecution.
        """
        try:
            from database.models import AuditSession, ScanExecution

            db = self.get_db_session()
            try:
                scan = db.query(ScanExecution).filter_by(execution_id=scan_id).first()
                if scan:
                    scan.status = status
                    if error_message:
                        scan.error_message = error_message
                    if status in ("completed", "in_review"):
                        scan.completed_at = datetime.now(timezone.utc)
                    for key, value in extra_fields.items():
                        if hasattr(scan, key):
                            setattr(scan, key, value)

                session = db.query(AuditSession).filter_by(session_id=scan_id).first()
                if session:
                    session.status = status
                    if status in ("completed", "in_review"):
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
    branch: str | None = None,
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

    # Resolve project_name for Telegram notifications
    project_name = None
    if project_id:
        try:
            from database.models import Project, create_db_engine, create_db_session as _create_session
            _engine = create_db_engine(os.environ.get("DATABASE_URL", "sqlite:///hound.db"))
            _db = _create_session(_engine)
            _project = _db.query(Project).filter(Project.id == project_id).first()
            if _project:
                project_name = _project.name
            _db.close()
        except Exception:
            pass
    if not project_name:
        # Fallback: extract repo name from URL
        project_name = repo_url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git") if repo_url else None

    # --- Idempotency guard: skip if already done or partially persisted ---
    db = self.get_db_session()
    try:
        from database.models import ScanExecution
        scan = db.query(ScanExecution).filter_by(execution_id=scan_id).first()
        if scan and scan.status in ("completed", "in_review"):
            print(f"[IDEMPOTENCY] Scan {scan_id} already {scan.status}, skipping redelivered task")
            return {"status": "already_done", "scan_id": scan_id}

        # Detect partial persistence from a crashed prior run.
        # Crash window: hypotheses written to DB, but ScanExecution.findings/status
        # not yet updated. A redelivered task would re-run the full audit.
        if scan and scan.status == "running" and project_id and scan.started_at:
            from database.models import Hypothesis
            orphan_count = db.query(Hypothesis).filter(
                Hypothesis.project_id == project_id,
                Hypothesis.created_at >= scan.started_at,
            ).count()
            if orphan_count > 0:
                error_msg = f"Aborted: {orphan_count} findings from crashed prior run. Manual review needed."
                print(f"[IDEMPOTENCY] Scan {scan_id} has {orphan_count} orphan hypotheses from crashed prior run")
                self._update_scan_status(scan_id, "failed", error_message=error_msg)
                # Publish terminal event so WebSocket/polling consumers see the failure
                publisher.publish_status("failed", error_msg)
                publisher.close()
                return {"status": "partial_crash", "scan_id": scan_id}
    finally:
        db.close()

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
            
            ref_disp = f" @ {branch}" if branch else ""
            publisher.publish_thought(f"Cloning repository: {repo_url}{ref_disp}", iteration=0)

            import subprocess
            clone_env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
            clone_cmd = ["git", "clone", "--depth", "1"]
            if branch:
                clone_cmd.extend(["--branch", branch])
            clone_cmd.extend([clone_url, str(repo_path)])
            clone_result = subprocess.run(
                clone_cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout for clone
                env=clone_env,
            )

            if clone_result.returncode != 0:
                stderr = clone_result.stderr or ""
                # Distinguish missing branch from other clone failures so the
                # worker-level handler (below) can refund the credit and toast
                # a branch-specific error to the user.
                if branch and "Remote branch" in stderr and "not found in upstream origin" in stderr:
                    raise RuntimeError(
                        f"REPO_BRANCH_NOT_FOUND: Branch '{branch}' not found in repository"
                    )
                raise RuntimeError(f"Git clone failed: {stderr}")
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
            
            # Store graphs in database
            if project_id or scan_id:
                try:
                    db_url = os.environ.get("DATABASE_URL", "sqlite:///hound.db")
                    engine = create_db_engine(db_url)
                    db = create_db_session(engine)
                    
                    for gf in graph_files:
                        with open(gf) as f:
                            graph_data = json.load(f)
                        
                        graph_name = gf.stem.replace("graph_", "")
                        
                        if project_id:
                            # Check if graph already exists for this project
                            existing = db.query(Graph).filter(
                                Graph.project_id == project_id,
                                Graph.internal_name == graph_name
                            ).first()
                        else:
                            # Agent audit: check by session_id
                            existing = db.query(Graph).filter(
                                Graph.session_id == scan_id,
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
                                session_id=scan_id if not project_id else None,
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

        # --- Curation pipeline: filter → dedup → rerank BEFORE persistence ---
        raw_count = len(all_hypotheses)
        audit_config = config or {}

        # Step A: Exact-string dedup (cheap, always run)
        seen_descriptions = set()
        hypotheses = []
        for h in all_hypotheses:
            desc = h.get('description', '') if isinstance(h, dict) else ''
            if desc and desc not in seen_descriptions:
                seen_descriptions.add(desc)
                hypotheses.append(h)
        print(f"[DEBUG] After exact dedup: {len(hypotheses)} unique hypotheses")

        # Step B: Filter test contract noise
        hypotheses = _filter_test_contract_findings(hypotheses)
        print(f"[DEBUG] After test contract filter: {len(hypotheses)}")

        # Step C: Semantic dedup (LLM)
        if audit_config.get("deep_audit_semantic_dedup", True) and len(hypotheses) > 5:
            publisher.publish_thought(
                f"Running semantic dedup on {len(hypotheses)} findings...",
                iteration=total_iterations,
            )
            hypotheses = _semantic_dedup_hypotheses(hypotheses, audit_config)

        # Step D: Severity re-ranking (LLM)
        if audit_config.get("deep_audit_severity_rerank", True) and hypotheses:
            publisher.publish_thought(
                f"Re-ranking severity for {len(hypotheses)} findings...",
                iteration=total_iterations,
            )
            hypotheses = _rerank_severities(hypotheses, audit_config)

        # Step E: Severity fallback — if >80% uniform with >10 findings, demote low-confidence
        if len(hypotheses) > 10:
            from collections import Counter
            severity_counts = Counter(h.get("severity") for h in hypotheses)
            dominant_sev, dominant_count = severity_counts.most_common(1)[0]
            if dominant_count / len(hypotheses) > 0.8:
                print(f"[DEBUG] Severity fallback: {dominant_count}/{len(hypotheses)} are '{dominant_sev}', demoting low-confidence")
                for h in hypotheses:
                    if h.get("confidence", 0.5) < 0.5:
                        h["severity"] = "low"

        print(f"[DEBUG] Final curated: {len(hypotheses)} findings (from {raw_count} raw)")

        # Step F (firepan-8kv): per-pattern template FP filter. Drops
        # "Missing access control on X.Y" hypotheses whose cited function
        # already has a modifier. Non-fatal — a failed verifier falls through
        # with the hypothesis kept.
        template_filter_stats = {
            "candidates_checked": 0,
            "rejected": [],
            "kept": len(hypotheses),
            "verifier_model": None,
            "skipped_reason": "not_run",
        }
        try:
            hypotheses, template_filter_stats = _filter_template_fps(
                hypotheses, repo_path, audit_config
            )
            if template_filter_stats.get("rejected"):
                publisher.publish_thought(
                    f"Dropped {len(template_filter_stats['rejected'])} access-control "
                    f"false positives after verifier check (firepan-8kv)",
                    iteration=total_iterations,
                )
        except Exception as e:
            print(f"[DEBUG] Template FP filter failed (non-fatal): {e}")
            traceback.print_exc()

        # --- Persist curated hypotheses ---
        print(f"[DEBUG] Storing {len(hypotheses)} curated hypotheses to DB for project_id={project_id}")
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

                findings = _convert_hypotheses_to_findings(hypotheses)

                publisher.publish_thought(
                    f"Posting {len(findings)} findings to PR #{pr_number}",
                    iteration=total_iterations,
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
                    iteration=total_iterations,
                )
            except Exception as pr_err:
                publisher.publish_thought(
                    f"Failed to post PR comments: {pr_err}",
                    iteration=total_iterations,
                )

        # Normalize for ScanExecution storage
        normalized_findings, risk_score, risk_level = _normalize_hypotheses_for_scan(hypotheses)

        # Build overview from ALREADY-CURATED hypotheses (same data as persisted)
        overview = None
        try:
            overview = _compute_deep_audit_overview(
                raw_count=raw_count,
                curated_hypotheses=hypotheses,
                config=audit_config,
            )
            print(f"[DEBUG] Deep audit overview: assessment={overview.get('assessment_level')}, "
                  f"credible={overview.get('credible_findings_count')}/{raw_count} raw")
        except Exception as e:
            print(f"[DEBUG] Failed to compute deep audit overview: {e}")
            traceback.print_exc()

        # firepan-ygy: detect template-FP storm (yieldnest-style confabulation loop)
        # and stamp the overview. Non-fatal — if detection fails, proceed without the flag.
        flagged, flag_reason = False, None
        if overview is not None:
            try:
                flagged, flag_reason = _detect_confabulation_pattern(hypotheses)
                if flagged:
                    overview["needs_manual_review"] = True
                    overview["review_reason"] = flag_reason
                    print(f"[DEBUG] Deep audit FLAGGED for manual review: {flag_reason}")
                else:
                    overview["needs_manual_review"] = False
            except Exception as e:
                print(f"[DEBUG] Confabulation detection failed (non-fatal): {e}")

        # firepan-8kv: stamp template FP filter stats on the overview for
        # observability. Always attached so postmortem analysis can see when
        # the filter was disabled / skipped.
        if overview is not None:
            try:
                overview["template_fp_filter"] = template_filter_stats
            except Exception as e:
                print(f"[DEBUG] Failed to stamp template_filter_stats on overview: {e}")

        # firepan-apn: stamp symbol-exists gate stats on the overview. The
        # agent records rejections as it forms hypotheses; we pull the
        # session-scoped counter here.
        if overview is not None and hasattr(agent, "get_symbol_gate_stats"):
            try:
                overview["symbol_exists_gate"] = agent.get_symbol_gate_stats()
                if overview["symbol_exists_gate"].get("rejected_count", 0) > 0:
                    publisher.publish_thought(
                        f"Symbol-exists gate rejected "
                        f"{overview['symbol_exists_gate']['rejected_count']} "
                        f"hypotheses that cited symbols not in the repo "
                        f"(firepan-apn)",
                        iteration=total_iterations,
                    )
            except Exception as e:
                print(f"[DEBUG] Failed to stamp symbol_exists_gate stats: {e}")

        # Build summary
        if overview:
            summary_text = overview.get("headline", f"Deep audit found {len(hypotheses)} potential issues")
        else:
            summary_text = f"Deep audit found {len(hypotheses)} potential issues"

        # Count contracts from manifest
        contracts_total = 0
        try:
            manifest_files_path = manifest_dir / "files.json"
            if manifest_files_path.exists():
                manifest_files = json.loads(manifest_files_path.read_text())
                contracts_total = len([
                    f for f in manifest_files
                    if f.get("relpath", "").endswith((".sol", ".vy"))
                ])
                print(f"[DEBUG] Contracts from manifest: {contracts_total}")
        except Exception as e:
            print(f"[DEBUG] Failed to count contracts from manifest: {e}")

        # Update status to in_review (human can finalize to completed)
        update_fields = dict(
            findings=normalized_findings,
            summary=summary_text,
            risk_score=risk_score,
            risk_level=risk_level,
            contracts_scanned=contracts_total,
            contracts_total=contracts_total,
        )
        if overview:
            update_fields["deep_audit_overview"] = overview

        self._update_scan_status(scan_id, "in_review", **update_fields)

        # Send Telegram notification (fire-and-forget)
        try:
            assessment = overview.get("assessment_level") if overview else None
            asyncio.run(notify_deep_audit_completed(
                repo_url=repo_url, session_id=scan_id, tenant_id=tenant_id,
                status="in_review", findings_count=len(hypotheses),
                risk_level=risk_level, risk_score=risk_score,
                assessment_level=assessment,
                project_name=project_name,
            ))
        except Exception:
            pass  # non-critical

        # firepan-ygy: second, louder alert when the confabulation detector fires
        if flagged:
            try:
                confirmed_total = sum(
                    1 for h in hypotheses if h.get("status") == "confirmed"
                )
                asyncio.run(notify_deep_audit_flagged(
                    repo_url=repo_url,
                    session_id=scan_id,
                    tenant_id=tenant_id,
                    reason=flag_reason or "Confabulation pattern detected",
                    findings_count=confirmed_total,
                    project_name=project_name,
                ))
            except Exception:
                pass  # non-critical

        # Lifecycle: stamp first_deep_audit_at + last_activity_at, send transactional email
        try:
            from database.models import Tenant
            _db = self.get_db_session()
            try:
                _tenant = _db.query(Tenant).filter(Tenant.id == tenant_id).first()
                if _tenant:
                    now_ts = datetime.now(timezone.utc)
                    if _tenant.first_deep_audit_at is None:
                        _tenant.first_deep_audit_at = now_ts
                    _tenant.last_activity_at = now_ts
                    _db.commit()

                    if _tenant.contact_email:
                        from integrations.lifecycle_emails import EmailCode, safe_dispatch
                        asyncio.run(safe_dispatch(
                            EmailCode.DEEP_AUDIT_DONE,
                            _tenant,
                            _db,
                            dedup_key=f"audit:{scan_id}",
                            extra_data={
                                "project_name": project_name or "your repository",
                                "findings_count": len(hypotheses),
                                "assessment_level": (assessment or "COMPLETE").upper(),
                                "session_id": scan_id,
                            },
                            force_send=True,  # transactional — ignore email_unsubscribed
                        ))
            finally:
                _db.close()
        except Exception as e:
            print(f"[DEBUG] Lifecycle hook (deep audit complete) failed (non-critical): {e}")

        publisher.publish_status(
            "in_review",
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
        try:
            asyncio.run(notify_deep_audit_completed(
                repo_url=repo_url, session_id=scan_id, tenant_id=tenant_id,
                status="failed", error_message="Time limit exceeded",
                project_name=project_name,
            ))
        except Exception:
            pass  # non-critical
        raise
        
    except Exception as e:
        error_msg = f"{type(e).__name__}: {str(e)}"
        publisher.publish_error(error_msg, "execution_error")
        publisher.publish_status("failed", error_msg)
        self._update_scan_status(scan_id, "failed", error_message=error_msg)
        try:
            asyncio.run(notify_deep_audit_completed(
                repo_url=repo_url, session_id=scan_id, tenant_id=tenant_id,
                status="failed", error_message=error_msg,
                project_name=project_name,
            ))
        except Exception:
            pass  # non-critical

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
    github_user_id: int | None = None,
    branch: str | None = None,
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
        branch: Git ref (branch/tag/SHA) to scan; defaults to repo HEAD

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
        scan_github_token = None
        if installation_id or github_user_id:
            try:
                scan_github_token = resolve_scan_github_token(
                    self.get_db_session,
                    tenant_id=tenant_id,
                    installation_id=installation_id,
                    github_user_id=github_user_id,
                )
            except Exception as e:
                token_source = "installation token" if installation_id else "user GitHub token"
                publisher.publish_thought(
                    f"Warning: could not get {token_source}: {e}",
                    iteration=1,
                )
        
        scanner = SurfaceScanner(
            config=config,
            llm_budget=llm_budget,
            model=model or "gpt-4o-mini",
            quiet=True,
            github_token=scan_github_token,
        )
        
        # Run scan
        ref_disp = f" @ {branch}" if branch else ""
        publisher.publish_thought(f"Scanning repository: {repo_url}{ref_disp}", iteration=1)
        result = scanner.scan(repo_url, ref=branch)
        
        # Convert result to dict
        result_dict = result.model_dump() if hasattr(result, "model_dump") else result.dict()

        # Redact then truncate scan log
        raw_log = result_dict.get("scan_log") or ""
        from analysis.surface.scanner import _redact_log, _truncate_log
        safe_log = _truncate_log(_redact_log(raw_log)) if raw_log else None

        # If scanner returned an error, mark as failed
        scan_error = result_dict.get("error")

        # Handle auth failures: structured error + credit refund
        if scan_error and "REPO_AUTH_REQUIRED" in scan_error:
            self._update_scan_status(scan_id, "failed", error_message="insufficient_github_scope", scan_log=safe_log)
            self._refund_if_credit_used(scan_id)
            publisher.publish_status("failed", "insufficient_github_scope")
            publisher.close()
            return result_dict
        elif scan_error and "REPO_TOKEN_INVALID" in scan_error:
            self._update_scan_status(scan_id, "failed", error_message="github_token_invalid", scan_log=safe_log)
            self._refund_if_credit_used(scan_id)
            publisher.publish_status("failed", "github_token_invalid")
            publisher.close()
            return result_dict
        elif scan_error and "REPO_BRANCH_NOT_FOUND" in scan_error:
            # Surface the full sentinel string so the frontend can extract the branch name.
            self._update_scan_status(scan_id, "failed", error_message=scan_error, scan_log=safe_log)
            self._refund_if_credit_used(scan_id)
            publisher.publish_status("failed", scan_error)
            publisher.close()
            return result_dict

        final_status = "failed" if scan_error else "completed"

        # Generate executive summary overview
        overview = None
        if not scan_error and result_dict.get("findings"):
            try:
                overview = _compute_surface_scan_overview(
                    findings=result_dict["findings"],
                    quality_metrics=result_dict.get("quality_metrics", {}),
                    risk_score=result_dict.get("risk_score", 0),
                    risk_level=result_dict.get("risk_level", "low"),
                    repo_name=result_dict.get("repo_name", repo_url),
                    config=config,
                )
            except Exception as e:
                print(f"[execute_scan_task] Overview generation failed: {e}")

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
            deep_audit_overview=overview,
        )

        publisher.publish_status(
            final_status,
            scan_error or f"Scan complete. Risk score: {result_dict.get('risk_score', 0)}"
        )

        # Lifecycle: stamp first_scan_at + last_activity_at so the Beat tick can
        # fire FIRST_SCAN_CELEBRATION 30min later. Only on success.
        if final_status == "completed":
            try:
                from datetime import datetime, timezone

                from database.models import Tenant
                _db = self.get_db_session()
                try:
                    _tenant = _db.query(Tenant).filter(Tenant.id == tenant_id).first()
                    if _tenant:
                        now_ts = datetime.now(timezone.utc)
                        if _tenant.first_scan_at is None:
                            _tenant.first_scan_at = now_ts
                        _tenant.last_activity_at = now_ts
                        _db.commit()
                finally:
                    _db.close()
            except Exception as e:
                print(f"[DEBUG] Lifecycle stamp (first_scan_at) failed (non-critical): {e}")

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


KNOWN_TEST_CONTRACTS = {"MockHook", "MockERC20", "MockToken", "TestHelper", "MockOracle"}


def _filter_test_contract_findings(hypotheses: list) -> list:
    """Remove findings about known test/mock contracts."""
    def _is_test_finding(h):
        desc = h.get("description", "")
        title = h.get("title", "")
        text = f"{title} {desc}"
        return any(tc in text for tc in KNOWN_TEST_CONTRACTS)

    filtered = [h for h in hypotheses if not _is_test_finding(h)]
    removed = len(hypotheses) - len(filtered)
    if removed:
        print(f"[test_filter] Removed {removed} test contract findings")
    return filtered


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
        from database.models import Hypothesis, ScanExecution

        db = get_db_session()
        try:
            # firepan-dar: resolve session_id (= ScanExecution.execution_id) to
            # the integer PK so we can write the new scan_execution_id FK.
            # Falls back to None on lookup failure — the column is nullable
            # for exactly this reason (legacy rows + race-y AuditSession path).
            scan_exec_id: int | None = None
            if session_id:
                scan_row = (
                    db.query(ScanExecution.id)
                    .filter(ScanExecution.execution_id == session_id)
                    .first()
                )
                if scan_row:
                    scan_exec_id = scan_row[0]

            for i, hyp in enumerate(hypotheses):
                print(f"[DEBUG _store_hypotheses_in_db] Storing hypothesis {i}: {hyp.get('description', '')[:50]}...")
                # firepan-281: persist model provenance so we can answer
                # "which model generated/verified this finding?" after the fact.
                # Without this, the yieldnest-shape postmortem ("DeepSeek
                # verifying DeepSeek") can't be detected from the DB.
                db_hyp = Hypothesis(
                    project_id=project_id,
                    scan_execution_id=scan_exec_id,
                    hypothesis_id=hyp.get("id") or f"{session_id}_hyp_{i}",
                    title=hyp.get("description", "Unknown")[:512],
                    description=hyp.get("description", ""),
                    vulnerability_type=hyp.get("vulnerability_type", "unknown"),
                    status=hyp.get("status", "proposed"),
                    confidence=float(hyp.get("confidence", 0.5)),
                    severity=hyp.get("severity", "medium"),
                    node_refs=hyp.get("node_ids", []),
                    evidence={"items": hyp.get("evidence", [])},
                    reported_by_model=(
                        hyp.get("reported_by_model")
                        or hyp.get("senior_model")
                        or hyp.get("junior_model")
                    ),
                    junior_model=hyp.get("junior_model"),
                    senior_model=hyp.get("senior_model"),
                )
                db.add(db_hyp)

            db.commit()
            print(f"[DEBUG _store_hypotheses_in_db] Successfully committed {len(hypotheses)} hypotheses to DB")
        finally:
            db.close()
    except Exception as e:
        print(f"Failed to store hypotheses: {e}")
        traceback.print_exc()


def _semantic_dedup_hypotheses(hypotheses: list, config: dict | None = None) -> list:
    """Semantically deduplicate hypotheses using LLM.

    Sends all findings in a single pass for comprehensive cross-finding
    comparison. Falls back to chunked processing only for very large sets (500+).
    Operates on a copy — does not mutate the input list.
    """
    if len(hypotheses) <= 5:
        return list(hypotheses)

    try:
        from analysis.hypothesis_dedup import _get_lightweight_client
    except ImportError:
        print("[deep_audit_dedup] hypothesis_dedup not available, skipping semantic dedup")
        return list(hypotheses)

    client = _get_lightweight_client(config or {})
    if not client:
        print("[deep_audit_dedup] No LLM client available, skipping semantic dedup")
        return list(hypotheses)

    def _dedup_batch(batch: list, offset: int = 0) -> set[int]:
        """Send a batch to LLM for dedup, return global indices to keep."""
        items_text = []
        for i, h in enumerate(batch):
            idx = offset + i
            title = h.get("title") or h.get("description", "")[:80]
            sev = h.get("severity", "medium")
            conf = h.get("confidence", 0.5)
            items_text.append(f"[{idx}] sev={sev} conf={conf} | {title}")

        system = (
            "You are a security finding deduplication assistant.\n"
            "Given numbered security findings, identify ALL clusters of semantically identical "
            "or near-identical findings (same root cause, just different wording).\n"
            "Examples of duplicates:\n"
            "- 'No emergency pause mechanism' ≈ 'No emergency pause or circuit breaker mechanism'\n"
            "- 'Treasury immutability prevents recovery' ≈ 'Treasury address immutable after deployment'\n"
            "- 'Integer overflow in commission' ≈ 'Potential integer overflow in commission calculation'\n"
            "- 'Missing reentrancy guard' ≈ 'No reentrancy protection on external calls'\n\n"
            "For each cluster, keep ONLY the best representative (most specific, highest confidence).\n"
            "For unique findings (no duplicates), include their index too.\n"
            "Be aggressive — if two findings describe the same underlying issue, they are duplicates.\n"
            "Return JSON: {\"keep\": [0, 3, 7, ...]}"
        )
        user = "FINDINGS:\n" + "\n".join(items_text)

        try:
            response = client.raw(system=system, user=user)
            text = response if isinstance(response, str) else str(response)
            match = re.search(r'\{[\s\S]*"keep"[\s\S]*\}', text)
            if match:
                result = json.loads(match.group())
                max_valid = offset + len(batch)
                return {idx for idx in result.get("keep", [])
                        if isinstance(idx, int) and offset <= idx < max_valid}
        except Exception as e:
            print(f"[deep_audit_dedup] LLM dedup failed: {e}")

        # Fallback: keep all
        return {offset + i for i in range(len(batch))}

    # Single-pass for up to 500 findings (compact one-liners fit in context)
    if len(hypotheses) <= 500:
        keep_indices = _dedup_batch(hypotheses, offset=0)
    else:
        # Chunked with cross-chunk merge for very large sets
        chunk_size = 200
        keep_indices: set[int] = set()
        chunks = [hypotheses[i:i + chunk_size] for i in range(0, len(hypotheses), chunk_size)]

        # Pass 1: dedup within each chunk
        chunk_representatives: list[tuple[int, dict]] = []
        for chunk_idx, chunk in enumerate(chunks):
            offset = chunk_idx * chunk_size
            chunk_keep = _dedup_batch(chunk, offset=offset)
            for idx in sorted(chunk_keep):
                chunk_representatives.append((idx, hypotheses[idx]))

        # Pass 2: dedup across chunk representatives
        if len(chunk_representatives) > 5:
            rep_batch = [h for _, h in chunk_representatives]
            cross_keep = _dedup_batch(rep_batch, offset=0)
            # Map back to original indices
            for i in cross_keep:
                if i < len(chunk_representatives):
                    keep_indices.add(chunk_representatives[i][0])
        else:
            keep_indices = {idx for idx, _ in chunk_representatives}

    if not keep_indices:
        return list(hypotheses)

    deduped = [hypotheses[i] for i in sorted(keep_indices)]
    print(f"[deep_audit_dedup] Semantic dedup: {len(hypotheses)} → {len(deduped)}")
    return deduped


def _rerank_severities(hypotheses: list, config: dict | None = None) -> list:
    """Re-rank severity of hypotheses using LLM.

    Sends the finding list to an LLM to reassess severity based on actual
    impact rather than default "medium" for everything. Returns a new list
    with updated severity fields.
    """
    if not hypotheses:
        return list(hypotheses)

    try:
        from analysis.hypothesis_dedup import _get_lightweight_client
    except ImportError:
        return list(hypotheses)

    client = _get_lightweight_client(config or {})
    if not client:
        return list(hypotheses)

    # Build compact finding summaries
    items_text = []
    for i, h in enumerate(hypotheses):
        title = h.get("title") or h.get("description", "")[:80]
        desc = h.get("description", "")[:200]
        nodes = ", ".join(str(n) for n in (h.get("node_ids") or [])[:3])
        items_text.append(f"[{i}] {title}\n  {desc}\n  nodes: {nodes}")

    system = (
        "You are a senior security auditor. Reassess the severity of each finding.\n"
        "Apply these criteria strictly:\n"
        "- critical: Direct loss of funds, protocol-breaking, exploitable by anyone\n"
        "- high: Significant value at risk, requires specific but realistic conditions\n"
        "- medium: Moderate impact, complex exploitation path, or limited scope\n"
        "- low: Informational, best practice violations, theoretical issues, design opinions\n\n"
        "Most automated findings are incorrectly rated as medium. Be honest — "
        "missing input validation on a simple payment splitter is low, not medium.\n"
        "Return JSON: {\"severities\": [{\"index\": 0, \"severity\": \"low\"}, ...]}"
    )
    user = "FINDINGS TO REASSESS:\n" + "\n\n".join(items_text)

    try:
        response = client.raw(system=system, user=user)
        text = response if isinstance(response, str) else str(response)
        import json as _json
        match = re.search(r'\{[\s\S]*"severities"[\s\S]*\}', text)
        if match:
            result = _json.loads(match.group())
            reranked = [dict(h) for h in hypotheses]  # shallow copy each dict
            valid_severities = {"critical", "high", "medium", "low"}
            for item in result.get("severities", []):
                idx = item.get("index")
                sev = item.get("severity", "").lower()
                if isinstance(idx, int) and 0 <= idx < len(reranked) and sev in valid_severities:
                    reranked[idx]["severity"] = sev
            print(f"[deep_audit_rerank] Severity reranking complete for {len(reranked)} findings")
            return reranked
    except Exception as e:
        print(f"[deep_audit_rerank] Severity reranking failed: {e}")

    return list(hypotheses)


def _generate_deep_audit_headline(
    raw_count: int,
    credible: list,
    top_concerns: list,
    assessment_level: str,
    config: dict | None = None,
) -> str:
    """Generate an auditor-quality headline paragraph for the deep audit overview.

    Tries LLM first, falls back to deterministic summary.
    """
    # Build deterministic fallback first
    if len(credible) == 0:
        fallback = (
            f"Deep audit reviewed {raw_count} potential issues. "
            f"No findings met the credibility threshold for confirmed vulnerabilities."
        )
    else:
        sev_counts: dict[str, int] = {}
        for h in credible:
            s = h.get("severity", "medium")
            sev_counts[s] = sev_counts.get(s, 0) + 1
        sev_parts = []
        for s in ["critical", "high", "medium", "low"]:
            if sev_counts.get(s):
                sev_parts.append(f"{sev_counts[s]} {s}")
        fallback = (
            f"Deep audit identified {len(credible)} credible findings "
            f"({', '.join(sev_parts)}) out of {raw_count} candidates reviewed."
        )

    # Try LLM headline
    try:
        from analysis.hypothesis_dedup import _get_lightweight_client
        client = _get_lightweight_client(config or {})
        if not client:
            return fallback

        concerns_text = "\n".join(
            f"- [{tc.get('severity', 'medium')}] {tc.get('title', '')}"
            for tc in top_concerns
        )

        system = (
            "You are a senior smart contract security auditor writing a post-audit assessment. "
            "Write a single paragraph (3-5 sentences) summarizing the security posture after a deep audit. "
            "Be specific. Auditor tone. Mention what the contract does, key risks, and overall assessment. "
            "Do not list individual findings. Prose only — no bullet points, no headers."
        )

        user = (
            f"Deep audit reviewed {raw_count} candidates, {len(credible)} credible findings remain.\n"
            f"Assessment level: {assessment_level}.\n"
            f"Top concerns:\n{concerns_text}\n\n"
            f"Write the assessment paragraph."
        )

        result = client.raw(system=system, user=user)
        result = result.strip().strip('"').strip("'") if isinstance(result, str) else str(result).strip()
        if result and len(result) > 50:
            return result
    except Exception as e:
        print(f"[deep_audit_overview] LLM headline failed: {e}")

    return fallback


def _compute_deep_audit_overview(raw_count: int, curated_hypotheses: list, config: dict | None = None) -> dict:
    """Compute a curated deep audit overview from hypotheses.

    Returns a dict suitable for storage in ScanExecution.deep_audit_overview.
    """
    # Triage counts
    triage_counts = {
        "confirmed": 0,
        "investigating": 0,
        "proposed": 0,
        "rejected": 0,
        "uncertain": 0,
    }
    for h in curated_hypotheses:
        status = h.get("status", "proposed")
        if status in triage_counts:
            triage_counts[status] += 1
        else:
            triage_counts["proposed"] += 1

    # Credible findings: confirmed + investigating + high-confidence unconfirmed
    credible = []
    for h in curated_hypotheses:
        status = h.get("status", "proposed")
        confidence = float(h.get("confidence", 0.5))
        if status in ("confirmed", "high_confidence", "investigating"):
            credible.append(h)
        elif confidence > 0.7:
            credible.append(h)

    # Top concerns: up to 3 most severe credible findings
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    sorted_credible = sorted(
        credible,
        key=lambda h: (severity_rank.get(h.get("severity", "medium"), 2), float(h.get("confidence", 0.5))),
        reverse=True,
    )
    top_concerns = []
    for h in sorted_credible[:3]:
        top_concerns.append({
            "title": h.get("title") or h.get("description", "")[:80],
            "description": h.get("description", ""),
            "severity": h.get("severity", "medium"),
            "confidence": float(h.get("confidence", 0.5)),
            "hypothesis_id": h.get("id", ""),
        })

    # Assessment level from credible findings only
    credible_severity_weights = {"critical": 25, "high": 15, "medium": 5, "low": 1}
    credible_score = min(100, sum(
        credible_severity_weights.get(h.get("severity", "medium"), 5)
        for h in credible
    ))
    assessment_level = (
        "critical" if credible_score >= 75
        else "high" if credible_score >= 50
        else "medium" if credible_score >= 25
        else "low"
    )

    # Review note
    preliminary_count = raw_count - len(credible)
    review_note = None
    if preliminary_count > 0 and raw_count > 5:
        review_note = (
            f"{preliminary_count} of {raw_count} findings are preliminary "
            f"and may not represent real vulnerabilities."
        )

    # Headline: LLM-generated auditor paragraph, with deterministic fallback
    headline = _generate_deep_audit_headline(
        raw_count, credible, top_concerns, assessment_level, config
    )

    # Credible findings list with hypothesis_id for frontend filtering
    credible_findings = []
    for h in sorted_credible:
        credible_findings.append({
            "hypothesis_id": h.get("id", ""),
            "title": h.get("title") or h.get("description", "")[:80],
            "severity": h.get("severity", "medium"),
            "confidence": float(h.get("confidence", 0.5)),
        })

    return {
        "headline": headline,
        "top_concerns": top_concerns,
        "triage_counts": triage_counts,
        "credible_findings_count": len(credible),
        "credible_findings": credible_findings,
        "raw_findings_count": raw_count,
        "assessment_level": assessment_level,
        "review_note": review_note,
        # firepan-oi4: unverified by default — the assessment card hides
        # headline/assessment_level/risk_score until a human or stronger-model
        # verifier flips this to True. Backfill treats missing key as False.
        "admin_verified": False,
    }


# firepan-ygy: catches the "pipeline is in a confabulation loop" meta-pattern.
# yieldnest scan 77 produced 11 of 13 FPs matching the "Missing access control on X.Y"
# template because DeepSeek grepped for `function set*` without following the modifier
# chain. Two thresholds catch the meta-pattern without requiring per-pattern filters:
#
#   1. >10 confirmed access-control findings — high absolute volume implies the model
#      is generating the same FP repeatedly.
#   2. >50% of confirmed findings matching a single regex template — high relative
#      share implies the model is fixated on one pattern (would have caught yieldnest
#      even if total was lower).
#
# Complement to the per-pattern template filter (firepan-8kv) which catches individual
# FPs; this catches the systemic failure. When triggered, the finalize step stamps
# `needs_manual_review=True` + `review_reason` into the overview JSONB and pages ops
# on Telegram. The admin_verified gate (firepan-oi4) already hides the assessment card;
# this adds a louder "don't just verify this one, investigate" signal.
_ACCESS_CONTROL_TEMPLATE_RE = re.compile(
    r"(missing|lack(?:s|ing)?|no|without|improper)\s+"
    r"(access\s*control|role(?:-based)?\s+access\s+control|authorization)"
    r"|unauthorized"
    r"|missing\s+role",
    re.IGNORECASE,
)


# firepan-8kv: per-pattern template FP filter. Complement to firepan-ygy.
# Picks off individual access-control false positives before persistence; ygy
# still catches systemic storms that slip past (e.g., template variants this
# regex doesn't hit).
_FUNCTION_NAME_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_CONTRACT_DOT_FN_RE = re.compile(r"\b([A-Z][A-Za-z0-9_]*)\.([a-zA-Z_][A-Za-z0-9_]*)\b")
_MODIFIER_HINTS = (
    "onlyOwner", "onlyRole", "onlyAdmin", "onlyGovernance", "onlyGuardian",
    "onlyOperator", "onlyManager", "onlyAuthorized", "onlyMinter", "onlyPauser",
    "auth ", "auth\n", "restricted", "requiresAuth",
)

# firepan-7nu: view/pure functions can't mutate state, so "missing access control"
# on them is a category error. Lexical match on the declaration line.
_VIEW_PURE_HINTS = (
    " view ", " view\n", " view{", " view returns",
    " pure ", " pure\n", " pure{", " pure returns",
    " constant ", " constant\n",
    "@view", "@pure",
)

# firepan-7nu: constructors/__init__ run once at deploy by msg.sender=deployer —
# AC modifiers on them are nonsense.
_CONSTRUCTOR_NAMES = ("constructor", "__init__")

# firepan-7nu: rounding/overcharge/precision-loss claims on pure helpers are
# only meaningful with a numeric gap (per firepan-vff "no finding without a
# numeric gap in its PoC"). When a hypothesis fits this template AND lacks
# numeric-gap markers, drop it.
_ROUNDING_TEMPLATE_RE = re.compile(
    r"(rounding|truncation|precision\s+loss|overcharge|undercharge|off-by-one)",
    re.IGNORECASE,
)
_NUMERIC_GAP_RE = re.compile(
    r"\d+\s*wei|\d+e\d+|expected\s+\d+|actual\s+\d+|\d+\s+vs\s+\d+|gap\s+of\s+\d+",
    re.IGNORECASE,
)


def _parse_contract_fn_from_hypothesis(h: dict) -> tuple[str | None, str | None]:
    """Extract (contract_name, function_name) from a hypothesis.

    Tries Title/description for "Contract.fn" shape first, then falls back to
    bare function name. Returns (None, None) when nothing parseable.
    """
    text = " ".join([
        (h.get("title") or ""),
        (h.get("description") or "")[:500],
    ])
    m = _CONTRACT_DOT_FN_RE.search(text)
    if m:
        return m.group(1), m.group(2)
    m2 = _FUNCTION_NAME_RE.search(text)
    if m2:
        return None, m2.group(1)
    # firepan-7nu: bare keyword forms — "constructor" / "__init__" rarely appear
    # with a paren in hypothesis prose ("Missing access control on constructor").
    for kw in _CONSTRUCTOR_NAMES:
        if re.search(rf"\b{kw}\b", text):
            return None, kw
    return None, None


def _fetch_function_declaration(
    repo_path: Path,
    contract_name: str | None,
    function_name: str,
    max_lines_after: int = 5,
) -> str | None:
    """Return declaration line + up to `max_lines_after` trailing lines.

    Scans .sol/.vy files under repo_path; excludes vendored libs. Returns None
    if no candidate file is found or the function signature can't be located.
    """
    if not function_name or not repo_path or not repo_path.exists():
        return None

    excluded = ("node_modules", ".git", "lib/forge-std", "lib/openzeppelin-contracts",
                "lib/solmate", "test/", "tests/", ".hound")
    candidate_files: list[Path] = []
    for ext in (".sol", ".vy"):
        for p in repo_path.rglob(f"*{ext}"):
            rel = str(p.relative_to(repo_path))
            if any(ex in rel for ex in excluded):
                continue
            if contract_name:
                # Prefer files whose name matches the contract
                if contract_name.lower() in p.stem.lower():
                    candidate_files.insert(0, p)
                else:
                    candidate_files.append(p)
            else:
                candidate_files.append(p)

    sig_re = re.compile(
        rf"(?:function|def)\s+{re.escape(function_name)}\s*\(",
        re.IGNORECASE if function_name[0].isalpha() else 0,
    )

    for f in candidate_files[:200]:  # cap for cost
        try:
            lines = f.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            continue
        for i, line in enumerate(lines):
            if sig_re.search(line):
                # firepan-7nu: include up to 3 preceding decorator lines so Vyper
                # `@view` / `@pure` modifiers are visible to template checks.
                start = i
                for j in range(1, 4):
                    if i - j < 0:
                        break
                    prev = lines[i - j].lstrip()
                    if prev.startswith("@"):
                        start = i - j
                    else:
                        break
                slice_end = min(len(lines), i + 1 + max_lines_after)
                return "\n".join(lines[start:slice_end])
    return None


def _verifier_same_as_generator(config: dict | None) -> bool:
    """Return True if template_verifier profile resolves to the same model as scout/strategist.

    Invariant from firepan-jyo: don't self-verify — a DeepSeek verifier on
    DeepSeek-generated findings can't catch DeepSeek's bias.
    """
    if not isinstance(config, dict):
        return True
    models = (config or {}).get("models") or {}
    tv = models.get("template_verifier") or {}
    scout = models.get("scout") or models.get("agent") or models.get("graph") or {}
    strategist = models.get("strategist") or models.get("guidance") or {}
    if not tv:
        return True  # no profile → fall back → skip
    tv_key = (tv.get("provider"), tv.get("model"))
    for other in (scout, strategist):
        if not other:
            continue
        if (other.get("provider"), other.get("model")) == tv_key:
            return True
    return False


def _filter_template_fps(
    hypotheses: list,
    repo_path: Path | None,
    config: dict | None,
) -> tuple[list, dict]:
    """Drop template-FP hypotheses that fail an adversarial-verifier check.

    For every hypothesis matching _ACCESS_CONTROL_TEMPLATE_RE, parse the
    "Contract.function" reference, grep the declaration, and ask a verifier
    model (must be a different provider/model tier than the generator — see
    firepan-jyo) whether the function already has an access-control modifier.
    If yes, remove the hypothesis from the returned list. The hypothesis DB
    status enum is never extended — rejected rows are dropped entirely, and
    observability data is stamped into overview["template_fp_filter"].

    Returns (kept_hypotheses, stats_dict). stats_dict is the exact shape to
    stamp onto the overview JSONB.
    """
    stats = {
        "candidates_checked": 0,
        "rejected": [],
        "kept": len(hypotheses),
        "verifier_model": None,
        "skipped_reason": None,
    }

    if not hypotheses:
        return list(hypotheses), stats

    audit_config = config or {}
    if not audit_config.get("deep_audit_template_fp_filter", True):
        stats["skipped_reason"] = "disabled_by_config"
        return list(hypotheses), stats

    if not repo_path or not Path(repo_path).exists():
        stats["skipped_reason"] = "no_repo_path"
        return list(hypotheses), stats

    if _verifier_same_as_generator(audit_config):
        stats["skipped_reason"] = "verifier_matches_generator"
        print("[template_fp_filter] Skipped: verifier profile matches generator — "
              "would be self-verification. See firepan-jyo.")
        return list(hypotheses), stats

    # Instantiate verifier client lazily; falling back to None if the profile
    # can't be built (missing API key, etc.) is a safe no-op.
    try:
        from llm.unified_client import UnifiedLLMClient
        verifier = UnifiedLLMClient(cfg=audit_config, profile="template_verifier")
        stats["verifier_model"] = f"{verifier.provider_name}:{verifier.model}"
    except Exception as e:
        stats["skipped_reason"] = f"verifier_init_failed:{e}"
        print(f"[template_fp_filter] Verifier init failed: {e}")
        return list(hypotheses), stats

    def _record_reject(h: dict, reason: str, function_name: str | None,
                       contract_name: str | None, model: str = "lexical") -> None:
        stats["rejected"].append({
            "title": h.get("title") or h.get("description", "")[:80],
            "verifier_reason": reason,
            "verifier_model": model,
            "node_refs": h.get("node_ids") or h.get("node_refs") or [],
            "function": function_name,
            "contract": contract_name,
        })

    kept: list = []
    for h in hypotheses:
        text = (h.get("title") or "") + " " + (h.get("description") or "")
        is_access_control = bool(_ACCESS_CONTROL_TEMPLATE_RE.search(text))
        is_rounding = bool(_ROUNDING_TEMPLATE_RE.search(text))

        if not (is_access_control or is_rounding):
            kept.append(h)
            continue

        stats["candidates_checked"] += 1
        contract_name, function_name = _parse_contract_fn_from_hypothesis(h)
        if not function_name:
            # Can't parse — pass through rather than drop a possibly-real finding
            kept.append(h)
            continue

        # firepan-7nu: constructor/__init__ AC claims are category errors, drop
        # without even fetching the declaration.
        if is_access_control and function_name in _CONSTRUCTOR_NAMES:
            _record_reject(h, "constructor_function", function_name, contract_name)
            continue

        decl = _fetch_function_declaration(Path(repo_path), contract_name, function_name)
        if not decl:
            kept.append(h)
            continue

        # firepan-7nu: view/pure helpers don't mutate state — "missing access
        # control" doesn't apply. Scan only the signature + any preceding
        # decorator lines; the trailing body slice may bleed into the next
        # function (e.g. ` view ` from getBalance() right below setFee()).
        decl_lines = decl.split("\n")
        sig_idx = next(
            (idx for idx, ln in enumerate(decl_lines)
             if re.search(r"\b(?:function|def)\b", ln)),
            0,
        )
        header_slice = "\n".join(decl_lines[: sig_idx + 1])
        is_view_or_pure = any(hint in header_slice for hint in _VIEW_PURE_HINTS)
        if is_access_control and is_view_or_pure:
            _record_reject(h, "view_or_pure_function", function_name, contract_name)
            continue

        # firepan-7nu: rounding/overcharge claims on pure helpers without a
        # concrete numeric gap are template noise. Real findings cite expected
        # vs actual wei. Conservative: only fire when the function is pure/view
        # AND the hypothesis text shows no numeric markers.
        if is_rounding and is_view_or_pure and not _NUMERIC_GAP_RE.search(text):
            _record_reject(h, "rounding_no_numeric_gap", function_name, contract_name)
            continue

        # If the hypothesis matched _only_ the rounding regex (not access-control)
        # and we got past the pure/view + numeric-gap gate, no further checks apply.
        if not is_access_control:
            kept.append(h)
            continue

        # Cheap lexical shortcut: if the signature obviously has a modifier,
        # we can reject without the LLM call. Use the header slice — checking
        # the full body slice can spill into the next function and falsely
        # reject (firepan-7nu fix).
        if any(hint in header_slice for hint in _MODIFIER_HINTS):
            _record_reject(h, "lexical_modifier_match", function_name, contract_name)
            continue

        system = (
            "You are a Solidity/Vyper access-control reviewer. "
            "Return ONLY a single JSON object (no prose): "
            '{"has_access_control": true|false, "reason": "<short>"}'
        )
        user = (
            f"Function declaration (line 1 is the signature):\n"
            f"```\n{decl}\n```\n\n"
            "Does this function have an access-control modifier that restricts WHO can "
            "call it (onlyOwner, onlyRole, onlyAdmin, auth, restricted, or an equivalent "
            "require/if-revert check on msg.sender)?\n"
            "Note: nonReentrant is NOT access control. Pure/view helpers that "
            "return data need no access control. Answer only based on the snippet."
        )

        try:
            response = verifier.raw(system=system, user=user)
        except Exception as e:
            print(f"[template_fp_filter] Verifier call failed for {function_name}: {e}")
            kept.append(h)
            continue

        text_resp = response if isinstance(response, str) else str(response)
        match = re.search(r'\{[^{}]*"has_access_control"[^{}]*\}', text_resp)
        if not match:
            kept.append(h)
            continue
        try:
            import json as _json
            parsed = _json.loads(match.group())
        except Exception:
            kept.append(h)
            continue

        if bool(parsed.get("has_access_control")):
            _record_reject(
                h,
                str(parsed.get("reason", ""))[:500],
                function_name,
                contract_name,
                model=stats["verifier_model"] or "unknown",
            )
        else:
            kept.append(h)

    stats["kept"] = len(kept)
    print(f"[template_fp_filter] checked={stats['candidates_checked']} "
          f"rejected={len(stats['rejected'])} kept={stats['kept']} "
          f"verifier={stats['verifier_model']}")
    return kept, stats


def _detect_confabulation_pattern(
    curated_hypotheses: list,
) -> tuple[bool, str | None]:
    """Return (should_flag, reason) if confirmed findings look like a template-FP storm.

    Signals drawn from the yieldnest postmortem (2026-04-21):
      - Absolute volume: >10 confirmed access-control findings.
      - Relative share: >50% of confirmed findings match the access-control template
        AND at least 5 confirmed total (below that, the % is noise).
    """
    confirmed = [
        h for h in curated_hypotheses
        if h.get("status") == "confirmed"
    ]
    total_confirmed = len(confirmed)
    if total_confirmed == 0:
        return (False, None)

    access_control_hits = sum(
        1 for h in confirmed
        if _ACCESS_CONTROL_TEMPLATE_RE.search(
            (h.get("title") or "") + " " + (h.get("description") or "")
        )
    )

    # Threshold 1: absolute volume of access-control confirms
    if access_control_hits > 10:
        return (
            True,
            f"{access_control_hits} confirmed access-control findings exceed threshold (>10). "
            "yieldnest-style template-FP storm suspected; manual review required.",
        )

    # Threshold 2: relative share (need a minimum sample size to avoid noise)
    if total_confirmed >= 5 and access_control_hits / total_confirmed > 0.5:
        share_pct = int(round(100 * access_control_hits / total_confirmed))
        return (
            True,
            f"{access_control_hits} of {total_confirmed} confirmed findings ({share_pct}%) "
            "match the access-control template; fixated-on-one-pattern storm suspected.",
        )

    return (False, None)


def _generate_surface_scan_headline(
    findings: list[dict],
    credible: list[dict],
    top_concerns: list[dict],
    assessment_level: str,
    repo_name: str,
    quality_metrics: dict,
    config: dict | None = None,
) -> str:
    """Generate an auditor-quality headline for a surface scan overview.

    Tries LLM first, falls back to deterministic summary.
    """
    # Deterministic fallback
    if not credible:
        fallback = (
            f"Surface scan of {repo_name} reviewed {len(findings)} potential issues. "
            f"No findings met the threshold for notable vulnerabilities."
        )
    else:
        sev_counts: dict[str, int] = {}
        for f in credible:
            s = f.get("severity", "medium")
            sev_counts[s] = sev_counts.get(s, 0) + 1
        sev_parts = []
        for s in ["critical", "high", "medium", "low"]:
            if sev_counts.get(s):
                sev_parts.append(f"{sev_counts[s]} {s}")
        contract_count = quality_metrics.get("contract_count", 0)
        total_loc = quality_metrics.get("total_loc", 0)
        fallback = (
            f"Surface scan identified {len(credible)} notable findings "
            f"({', '.join(sev_parts)}) across {contract_count} contracts "
            f"({total_loc} LOC)."
        )

    # Try LLM headline
    try:
        from analysis.hypothesis_dedup import _get_lightweight_client
        client = _get_lightweight_client(config or {})
        if not client:
            return fallback

        concerns_text = "\n".join(
            f"- [{tc.get('severity', 'medium')}] {tc.get('title', '')}"
            for tc in top_concerns
        )

        system = (
            "You are a senior smart contract security auditor writing a pre-audit surface scan assessment. "
            "Write a single paragraph (3-5 sentences) summarizing the security posture after an automated surface scan. "
            "Be specific. Auditor tone. Mention what the contract does, key risks, and overall assessment. "
            "Do not list individual findings. Prose only — no bullet points, no headers."
        )

        user = (
            f"Surface scan of {repo_name} reviewed {len(findings)} patterns, "
            f"{len(credible)} notable findings remain.\n"
            f"Assessment level: {assessment_level}.\n"
            f"Contracts: {quality_metrics.get('contract_count', 0)}, "
            f"LOC: {quality_metrics.get('total_loc', 0)}\n"
            f"Top concerns:\n{concerns_text}\n\n"
            f"Write the assessment paragraph."
        )

        result = client.raw(system=system, user=user)
        result = result.strip().strip('"').strip("'") if isinstance(result, str) else str(result).strip()
        if result and len(result) > 50:
            return result
    except Exception as e:
        print(f"[surface_scan_overview] LLM headline failed: {e}")

    return fallback


def _compute_surface_scan_overview(
    findings: list[dict],
    quality_metrics: dict,
    risk_score: int,
    risk_level: str,
    repo_name: str,
    config: dict | None = None,
) -> dict | None:
    """Compute a curated overview for surface scans.

    Returns a dict compatible with DeepAuditOverview TypeScript type,
    or None if there are no findings.
    """
    if not findings:
        return None

    # Triage counts: map severity to the existing confirmed/investigating/proposed buckets
    # so the frontend renders correctly without changes
    triage_counts = {
        "confirmed": 0,
        "investigating": 0,
        "proposed": 0,
        "rejected": 0,
        "uncertain": 0,
    }

    for f in findings:
        severity = f.get("severity", "medium")
        llm_verified = f.get("llm_verified", False)
        confidence = float(f.get("confidence", 0.5))

        if llm_verified and confidence >= 0.7:
            triage_counts["confirmed"] += 1
        elif llm_verified:
            triage_counts["investigating"] += 1
        else:
            triage_counts["proposed"] += 1

    # Credible findings: LLM-verified high-confidence, or critical/high severity
    credible = []
    for f in findings:
        severity = f.get("severity", "medium")
        llm_verified = f.get("llm_verified", False)
        confidence = float(f.get("confidence", 0.5))

        if llm_verified and confidence >= 0.7:
            credible.append(f)
        elif severity in ("critical", "high"):
            credible.append(f)

    # Top concerns: up to 3 most severe
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    sorted_credible = sorted(
        credible,
        key=lambda f: (severity_rank.get(f.get("severity", "medium"), 2), float(f.get("confidence", 0.5))),
        reverse=True,
    )
    top_concerns = []
    for f in sorted_credible[:3]:
        top_concerns.append({
            "title": f.get("title") or f.get("description", "")[:80],
            "description": f.get("description", ""),
            "severity": f.get("severity", "medium"),
            "confidence": float(f.get("confidence", 0.5)),
            "hypothesis_id": f.get("pattern_id", ""),
        })

    # Assessment level
    credible_severity_weights = {"critical": 25, "high": 15, "medium": 5, "low": 1}
    credible_score = min(100, sum(
        credible_severity_weights.get(f.get("severity", "medium"), 5)
        for f in credible
    ))
    assessment_level = (
        "critical" if credible_score >= 75
        else "high" if credible_score >= 50
        else "medium" if credible_score >= 25
        else "low"
    )

    # Review note
    unverified_count = len(findings) - len(credible)
    review_note = None
    if unverified_count > 0 and len(findings) > 3:
        review_note = (
            f"{unverified_count} of {len(findings)} findings are pattern-matched "
            f"and may need manual verification."
        )

    # Headline
    headline = _generate_surface_scan_headline(
        findings, credible, top_concerns, assessment_level,
        repo_name, quality_metrics, config,
    )

    # Credible findings list
    credible_findings = []
    for f in sorted_credible:
        credible_findings.append({
            "hypothesis_id": f.get("pattern_id", ""),
            "title": f.get("title") or f.get("description", "")[:80],
            "severity": f.get("severity", "medium"),
            "confidence": float(f.get("confidence", 0.5)),
        })

    return {
        "headline": headline,
        "top_concerns": top_concerns,
        "triage_counts": triage_counts,
        "credible_findings_count": len(credible),
        "credible_findings": credible_findings,
        "raw_findings_count": len(findings),
        "assessment_level": assessment_level,
        "review_note": review_note,
    }


def _normalize_hypotheses_for_scan(hypotheses: list) -> tuple[list, int, str]:
    """Normalize deep-audit hypotheses into SurfaceFinding-compatible shape.

    Returns (normalized_findings, risk_score, risk_level).
    The frontend serializer expects: pattern_id, title, severity,
    category, confidence, location, code_snippet, description, llm_verified.
    """
    severity_weights = {"critical": 25, "high": 15, "medium": 5, "low": 1}
    risk_score = min(100, sum(
        severity_weights.get(h.get("severity", "medium"), 5)
        for h in hypotheses
    ))
    risk_level = (
        "critical" if risk_score >= 75
        else "high" if risk_score >= 50
        else "medium" if risk_score >= 25
        else "low"
    )

    normalized = []
    for h in hypotheses:
        node_ids = h.get("node_ids", []) or []
        location = ", ".join(str(n) for n in node_ids[:3]) if node_ids else ""
        evidence = h.get("evidence", [])
        code_snippet = ""
        if isinstance(evidence, list):
            for ev in evidence[:1]:
                if isinstance(ev, dict) and "code" in ev:
                    code_snippet = ev["code"][:500]

        normalized.append({
            "pattern_id": h.get("id", ""),
            "title": h.get("title") or h.get("description", "")[:80],
            "severity": h.get("severity", "medium"),
            "category": h.get("vulnerability_type", "vulnerability"),
            "confidence": float(h.get("confidence", 0.5)),
            "location": location,
            "code_snippet": code_snippet,
            "description": h.get("description", ""),
            "llm_verified": True,
            "llm_notes": None,
        })

    return normalized, risk_score, risk_level


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
    branch: str | None = None,
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
            
            graph_clone_cmd = ["git", "clone", "--depth", "1"]
            if branch:
                graph_clone_cmd.extend(["--branch", branch])
            graph_clone_cmd.extend([clone_url, str(repo_path)])
            result = subprocess.run(
                graph_clone_cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode != 0:
                stderr = result.stderr or ""
                if branch and "Remote branch" in stderr and "not found in upstream origin" in stderr:
                    raise RuntimeError(
                        f"REPO_BRANCH_NOT_FOUND: Branch '{branch}' not found in repository"
                    )
                raise RuntimeError(f"Git clone failed: {stderr}")
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


@celery_app.task(name="worker.tasks.send_funnel_digest_task")
def send_funnel_digest_task():
    """Weekly funnel stats digest to internal Telegram channel."""
    import logging

    from sqlalchemy import func as sqlfunc

    from database.models import PageView, ScanExecution, Tenant, User, create_db_engine, create_db_session
    from integrations.telegram import notify_funnel_digest

    logger = logging.getLogger(__name__)

    db_url = os.environ.get("DATABASE_URL", "sqlite:///hound.db")
    engine = create_db_engine(db_url)
    db = create_db_session(engine)

    BOT_SUBSTRINGS = [
        "bot", "crawler", "spider", "slurp", "curl", "wget",
        "python", "uptimerobot", "facebookexternalhit",
    ]

    def _is_human(pv):
        if not pv.visitor_id:
            return False
        ua = (pv.user_agent or "").lower()
        return not any(b in ua for b in BOT_SUBSTRINGS)

    try:
        now = datetime.now(timezone.utc)
        seven_days_ago = now - timedelta(days=7)
        thirty_days_ago = now - timedelta(days=30)

        # Stage 1: Page views (bot-filtered)
        raw_7d = db.query(PageView).filter(PageView.created_at >= seven_days_ago).all()
        human_7d = [pv for pv in raw_7d if _is_human(pv)]
        visitors_7d = len(human_7d)
        visitors_unique_7d = len(set(pv.visitor_id for pv in human_7d))

        raw_30d = db.query(PageView).filter(PageView.created_at >= thirty_days_ago).all()
        human_30d = [pv for pv in raw_30d if _is_human(pv)]
        visitors_30d = len(human_30d)
        visitors_unique_30d = len(set(pv.visitor_id for pv in human_30d))

        # Stage 2: Signups
        signups_7d = db.query(sqlfunc.count(User.id)).filter(User.created_at >= seven_days_ago).scalar() or 0
        signups_30d = db.query(sqlfunc.count(User.id)).filter(User.created_at >= thirty_days_ago).scalar() or 0

        # Stage 3: Scans started
        scans_7d = db.query(sqlfunc.count(ScanExecution.id)).filter(
            ScanExecution.created_at >= seven_days_ago,
        ).scalar() or 0
        scans_30d = db.query(sqlfunc.count(ScanExecution.id)).filter(
            ScanExecution.created_at >= thirty_days_ago,
        ).scalar() or 0

        # Stage 4: Paid conversions
        PAID_PLANS = ['starter', 'professional', 'enterprise']
        new_paid_7d = db.query(sqlfunc.count(Tenant.id)).filter(
            Tenant.first_paid_at >= seven_days_ago,
        ).scalar() or 0
        new_paid_30d = db.query(sqlfunc.count(Tenant.id)).filter(
            Tenant.first_paid_at >= thirty_days_ago,
        ).scalar() or 0

        # All-time footer
        active_paid = db.query(sqlfunc.count(Tenant.id)).filter(
            Tenant.plan.in_(PAID_PLANS),
        ).scalar() or 0
        ever_paid = db.query(sqlfunc.count(Tenant.id)).filter(
            Tenant.first_paid_at.isnot(None),
        ).scalar() or 0
        total_users = db.query(sqlfunc.count(User.id)).scalar() or 0
        total_scans = db.query(sqlfunc.count(ScanExecution.id)).scalar() or 0

        # Build period label
        period_end = now.strftime("%b %d")
        period_start = seven_days_ago.strftime("%b %d")
        period_label = f"Week of {period_start}\u2013{period_end}"

        asyncio.run(notify_funnel_digest(
            period_label=period_label,
            visitors_7d=visitors_7d,
            visitors_unique_7d=visitors_unique_7d,
            signups_7d=signups_7d,
            scans_7d=scans_7d,
            new_paid_7d=new_paid_7d,
            visitors_30d=visitors_30d,
            visitors_unique_30d=visitors_unique_30d,
            signups_30d=signups_30d,
            scans_30d=scans_30d,
            new_paid_30d=new_paid_30d,
            active_paid=active_paid,
            ever_paid=ever_paid,
            total_users=total_users,
            total_scans=total_scans,
        ))
        logger.info("Funnel digest sent successfully")
    except Exception:
        logger.exception("Failed to send funnel digest")
    finally:
        db.close()


@celery_app.task(name="worker.tasks.check_stripe_webhook_health_task")
def check_stripe_webhook_health_task():
    """Daily digest: one-line Stripe health + open Beads tasks."""
    import logging

    import httpx

    from integrations.telegram import notify_daily_digest

    logger = logging.getLogger(__name__)

    # --- Stripe health (one-liner) ---
    stripe_status = "OK"
    stripe_issues: list[str] = []
    api_base = os.environ.get("API_BASE_URL", "http://api:8000")
    try:
        resp = httpx.get(f"{api_base}/health/stripe", timeout=15.0)
        data = resp.json()
        config_ok = data.get("config_ok", False)
        probe = data.get("webhook_probe", {})
        age_days = data.get("last_event_days_ago")

        if not config_ok:
            stripe_issues.extend(data.get("issues", ["config error"]))
        if probe.get("status") != "ok":
            stripe_issues.append(f"probe: {probe.get('detail', 'failed')}")

        if stripe_issues:
            stripe_status = "Issues detected"
        elif age_days is not None:
            stripe_status = f"OK \u2022 last event {age_days}d ago"
        else:
            stripe_status = "OK \u2022 no events yet"
    except Exception as e:
        logger.error("Failed to reach /health/stripe: %s", e)
        stripe_status = "Unreachable"
        stripe_issues.append(str(e))

    # --- Beads tasks ---
    # New file shape: {"total": int, "top": [ {id, title, priority, assignee, status}, ... ]}
    # Old shape (list-only) kept for backwards compat during rollout.
    beads_tasks: list[dict] | None = None
    beads_total: int | None = None
    # Path is under /config/state/ (directory mount), not /config/ directly.
    # See docker-compose.yml worker volumes and gotcha #62 in CLAUDE.md
    # for the single-file-bind-mount inode-pinning issue this avoids.
    beads_summary_path = "/config/state/beads_summary.json"
    try:
        mtime = os.path.getmtime(beads_summary_path)
        age_hours = (time.time() - mtime) / 3600.0
        if age_hours > 25:
            logger.warning("beads summary is %.1fh old — treating as unavailable", age_hours)
            # Leave beads_tasks=None so the renderer shows "bd summary unavailable".
            # The age is logged; not surfacing in the digest to keep the Stripe
            # health line honest (a stale bd cache ≠ a Stripe problem).
        else:
            with open(beads_summary_path) as f:
                data = json.load(f)
            if isinstance(data, dict):
                beads_tasks = data.get("top") or []
                beads_total = data.get("total")
            elif isinstance(data, list):
                beads_tasks = data
                beads_total = len(data)
            else:
                logger.warning("Unexpected beads summary shape: %s", type(data).__name__)
    except FileNotFoundError:
        logger.info("No beads summary at %s", beads_summary_path)
    except Exception as e:
        logger.warning("Failed to read beads summary: %s", e)

    # --- Send digest ---
    asyncio.run(notify_daily_digest(
        stripe_status=stripe_status,
        beads_tasks=beads_tasks,
        stripe_issues=stripe_issues if stripe_issues else None,
        total_open=beads_total,
    ))


@celery_app.task(name="worker.tasks.auto_finalize_reviews_task")
def auto_finalize_reviews_task():
    """Auto-finalize in_review scans older than 24 hours."""
    import logging

    logger = logging.getLogger(__name__)

    from database.models import AuditSession, ScanExecution, create_db_engine, create_db_session

    db_url = os.environ.get("DATABASE_URL", "sqlite:///hound.db")
    engine = create_db_engine(db_url)
    db = create_db_session(engine)

    try:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        stale = db.query(ScanExecution).filter(
            ScanExecution.status == "in_review",
            ScanExecution.completed_at < cutoff,
        ).all()

        if not stale:
            logger.info("auto_finalize: no stale in_review scans")
            return

        scan_ids = []
        for scan in stale:
            scan.status = "completed"
            scan_ids.append(scan.execution_id)

        if scan_ids:
            db.query(AuditSession).filter(
                AuditSession.session_id.in_(scan_ids),
            ).update({"status": "completed"}, synchronize_session="fetch")

        db.commit()
        logger.info("auto_finalize: finalized %d scans: %s", len(scan_ids), scan_ids)
    except Exception:
        logger.exception("auto_finalize: failed")
        db.rollback()
    finally:
        db.close()


# ============================================================================
# Lifecycle email Beat tasks
# ============================================================================
# See integrations/lifecycle_emails.py for the dispatcher contract.
# Invariants (see module docstring there):
#   1. dispatch() never retries failed rows.
#   2. Beat owns ALL retry/backoff behavior.
#   3. _perform_send_and_update_status() is the only writer of attempt_count.
#   4. metadata_json contains everything needed for byte-equivalent resend.


def _backoff_minutes(attempt_count: int) -> int:
    """Step-function backoff: 1→15min, 2→60min, 3→240min (4h), 4→720min (12h), >=5→1440min (24h)."""
    if attempt_count <= 1:
        return 15
    if attempt_count == 2:
        return 60
    if attempt_count == 3:
        return 240
    if attempt_count == 4:
        return 720
    return 1440


@celery_app.task(name="worker.tasks.run_lifecycle_tick_task")
def run_lifecycle_tick_task():
    """Evaluate time-gated lifecycle-email rules and dispatch due sends.

    MVP rules:
      - rule_getting_started: 1h post email_verified_at
      - rule_first_scan_celebration: 30min post first_scan_at (skipped if deep-audit already ran)

    Follow-up PR will append more rules to the RULES list inside this task.
    """
    import asyncio as _asyncio
    import logging

    from database.models import SentEmail, Tenant, create_db_engine, create_db_session
    from integrations.lifecycle_emails import EmailCode, dispatch

    logger = logging.getLogger(__name__)
    db_url = os.environ.get("DATABASE_URL", "sqlite:///hound.db")
    engine = create_db_engine(db_url)
    db = create_db_session(engine)

    try:
        now = datetime.now(timezone.utc)
        # Narrow scan: only tenants with at least one trigger stamp in the last 30 days.
        # Keeps the query cheap even at scale; follow-up rules with longer windows
        # can add more OR predicates here.
        cutoff = now - timedelta(days=30)
        tenants = (
            db.query(Tenant)
            .filter(
                (Tenant.email_verified_at >= cutoff) |
                (Tenant.first_scan_at >= cutoff)
            )
            .all()
        )

        def _already_sent_or_pending(tenant_id: int, code: str, dedup_key: str) -> bool:
            existing = (
                db.query(SentEmail)
                .filter(
                    SentEmail.tenant_id == tenant_id,
                    SentEmail.code == code,
                    SentEmail.dedup_key == dedup_key,
                )
                .first()
            )
            # We skip if anything already exists — dispatch() handles the fine-grained
            # duplicate/pending/failed cases; the tick just avoids pointless calls.
            return existing is not None

        dispatched = 0
        for tenant in tenants:
            # Rule 1: GETTING_STARTED — 1h after email_verified_at
            try:
                if tenant.email_verified_at:
                    elapsed = now - tenant.email_verified_at
                    if elapsed >= timedelta(hours=1):
                        dedup = EmailCode.GETTING_STARTED.value
                        if not _already_sent_or_pending(tenant.id, EmailCode.GETTING_STARTED.value, dedup):
                            _asyncio.run(dispatch(
                                EmailCode.GETTING_STARTED,
                                tenant, db,
                                dedup_key=dedup,
                                extra_data={},
                            ))
                            dispatched += 1
            except Exception:
                logger.exception("lifecycle_tick GETTING_STARTED failed for tenant=%s", tenant.id)

            # Rule 2: FIRST_SCAN_CELEBRATION — 30min after first_scan_at, and only if deep audit hasn't run yet
            try:
                if tenant.first_scan_at and not tenant.first_deep_audit_at:
                    elapsed = now - tenant.first_scan_at
                    if elapsed >= timedelta(minutes=30):
                        dedup = EmailCode.FIRST_SCAN_CELEBRATION.value
                        if not _already_sent_or_pending(tenant.id, EmailCode.FIRST_SCAN_CELEBRATION.value, dedup):
                            _asyncio.run(dispatch(
                                EmailCode.FIRST_SCAN_CELEBRATION,
                                tenant, db,
                                dedup_key=dedup,
                                extra_data={},
                            ))
                            dispatched += 1
            except Exception:
                logger.exception("lifecycle_tick FIRST_SCAN_CELEBRATION failed for tenant=%s", tenant.id)

        if dispatched:
            logger.info("lifecycle_tick: dispatched %d lifecycle email(s) across %d tenants",
                        dispatched, len(tenants))
    except Exception:
        logger.exception("lifecycle_tick: top-level failure")
    finally:
        db.close()


@celery_app.task(name="worker.tasks.retry_failed_lifecycle_emails_task")
def retry_failed_lifecycle_emails_task():
    """Reclaim stale pending rows and retry failed rows with exponential backoff.

    Two passes per run (every 15 min):
      A. Stale-pending reaper: status='pending' AND last_attempt_at < now - 10min
         → re-claim marker and run shared helper.
      B. Failed-row retry with backoff: status='failed' AND created_at within 72h
         AND last_attempt_at < now - backoff(attempt_count)
         → re-claim (flip status='pending') and run shared helper.
    """
    import asyncio as _asyncio
    import logging

    from database.models import SentEmail, Tenant, create_db_engine, create_db_session
    from integrations.lifecycle_emails import _perform_send_and_update_status

    logger = logging.getLogger(__name__)
    db_url = os.environ.get("DATABASE_URL", "sqlite:///hound.db")
    engine = create_db_engine(db_url)
    db = create_db_session(engine)

    try:
        now = datetime.now(timezone.utc)
        stale_cutoff = now - timedelta(minutes=10)
        created_cutoff = now - timedelta(hours=72)

        retried = 0
        reaped = 0

        # Pass A: Stale-pending reaper
        stale_rows = (
            db.query(SentEmail)
            .filter(
                SentEmail.status == "pending",
                SentEmail.last_attempt_at < stale_cutoff,
            )
            .limit(100)
            .all()
        )
        for row in stale_rows:
            original_last_attempt = row.last_attempt_at
            claimed = (
                db.query(SentEmail)
                .filter(
                    SentEmail.id == row.id,
                    SentEmail.status == "pending",
                    SentEmail.last_attempt_at == original_last_attempt,
                )
                .update(
                    {SentEmail.last_attempt_at: now},
                    synchronize_session=False,
                )
            )
            db.commit()
            if claimed != 1:
                continue  # lost race
            db.refresh(row)
            tenant = db.query(Tenant).filter(Tenant.id == row.tenant_id).first()
            if tenant is None:
                row.status = "failed"
                row.send_error = "tenant missing"
                db.commit()
                continue
            try:
                _asyncio.run(_perform_send_and_update_status(row, tenant, db))
                reaped += 1
            except Exception:
                logger.exception("retry_failed_lifecycle: helper crashed on stale row id=%s", row.id)

        # Pass B: Failed-row retry with exponential backoff
        failed_rows = (
            db.query(SentEmail)
            .filter(
                SentEmail.status == "failed",
                SentEmail.created_at > created_cutoff,
            )
            .limit(500)
            .all()
        )
        for row in failed_rows:
            backoff = _backoff_minutes(row.attempt_count or 1)
            if row.last_attempt_at is None:
                # No attempt yet recorded — eligible
                eligible = True
            else:
                eligible = row.last_attempt_at < now - timedelta(minutes=backoff)
            if not eligible:
                continue

            original_last_attempt = row.last_attempt_at
            claimed = (
                db.query(SentEmail)
                .filter(
                    SentEmail.id == row.id,
                    SentEmail.status == "failed",
                    SentEmail.last_attempt_at == original_last_attempt,
                )
                .update(
                    {SentEmail.status: "pending", SentEmail.last_attempt_at: now},
                    synchronize_session=False,
                )
            )
            db.commit()
            if claimed != 1:
                continue  # lost race
            db.refresh(row)
            tenant = db.query(Tenant).filter(Tenant.id == row.tenant_id).first()
            if tenant is None:
                row.status = "failed"
                row.send_error = "tenant missing"
                db.commit()
                continue
            try:
                _asyncio.run(_perform_send_and_update_status(row, tenant, db))
                retried += 1
            except Exception:
                logger.exception("retry_failed_lifecycle: helper crashed on failed row id=%s", row.id)

        if reaped or retried:
            logger.info("retry_failed_lifecycle: reaped=%d, retried=%d", reaped, retried)
    except Exception:
        logger.exception("retry_failed_lifecycle: top-level failure")
    finally:
        db.close()
