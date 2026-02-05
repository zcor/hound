"""
SQLAdmin configuration for Hound dashboard.

Provides a GUI admin interface for managing database models.
Access at /admin when mounted to the FastAPI app.
"""

from pathlib import Path
from sqladmin import Admin, ModelView, action
from starlette.requests import Request
from starlette.responses import RedirectResponse
from markupsafe import Markup

from database.models import (
    AuditSession,
    Graph,
    Hypothesis,
    Project,
    ScanExecution,
    Tenant,
    TokenUsageLog,
)


def status_formatter(value):
    """Format status with colored badges."""
    if value is None:
        return ""
    colors = {
        "queued": "secondary",
        "running": "primary",
        "completed": "success",
        "failed": "danger",
        "pending": "warning",
        "aborted": "dark",
    }
    color = colors.get(value.lower(), "info")
    return Markup(f'<span class="badge bg-{color}">{value}</span>')


def severity_formatter(value):
    """Format severity with colored badges."""
    if value is None:
        return ""
    colors = {
        "critical": "danger",
        "high": "warning",
        "medium": "info",
        "low": "secondary",
    }
    color = colors.get(value.lower(), "secondary")
    return Markup(f'<span class="badge bg-{color}">{value}</span>')


def confidence_formatter(value):
    """Format confidence as a progress bar."""
    if value is None:
        return ""
    percent = int(value * 100)
    if percent >= 80:
        color = "success"
    elif percent >= 50:
        color = "warning"
    else:
        color = "danger"
    return Markup(
        f'<div class="progress" style="width:100px;height:20px;">'
        f'<div class="progress-bar bg-{color}" style="width:{percent}%">{percent}%</div>'
        f'</div>'
    )


class TenantAdmin(ModelView, model=Tenant):
    """Admin view for Tenant model."""
    
    column_list = [Tenant.id, Tenant.name, Tenant.installation_id, Tenant.created_at]
    column_searchable_list = [Tenant.name]
    column_sortable_list = [Tenant.id, Tenant.name, Tenant.created_at]
    column_default_sort = [(Tenant.created_at, True)]
    icon = "fa-solid fa-building"
    name = "Tenant"
    name_plural = "Tenants"


class ProjectAdmin(ModelView, model=Project):
    """Admin view for Project model."""
    
    column_list = [
        Project.id,
        Project.name,
        Project.git_url,
        Project.status,
        Project.tenant,
        Project.created_at,
    ]
    column_searchable_list = [Project.name, Project.git_url]
    column_sortable_list = [Project.id, Project.name, Project.status, Project.created_at]
    column_default_sort = [(Project.created_at, True)]
    column_formatters = {
        Project.status: lambda m, a: status_formatter(m.status),
    }
    icon = "fa-solid fa-code-branch"
    name = "Project"
    name_plural = "Projects"
    
    # Show related audit sessions in detail view
    column_details_list = [
        Project.id,
        Project.name,
        Project.git_url,
        Project.status,
        Project.tenant,
        Project.audit_sessions,
        Project.graphs,
        Project.created_at,
        Project.last_accessed,
    ]
    
    @action(
        name="view_dashboard",
        label="View Dashboard",
        confirmation_message=None,
        add_in_detail=True,
        add_in_list=True,
    )
    async def view_dashboard_action(self, request: Request) -> RedirectResponse:
        """Open interactive project dashboard with graph visualization."""
        pks = request.query_params.get("pks", "").split(",")
        
        if pks and pks[0]:
            # Redirect to project dashboard
            return RedirectResponse(
                f"/admin/dashboard/{pks[0]}",
                status_code=302,
            )
        
        return RedirectResponse(
            request.url_for("admin:list", identity=self.identity),
            status_code=302,
        )
    
    @action(
        name="build_graphs",
        label="Build Graphs",
        confirmation_message="Build knowledge graphs for the selected projects? This is required before running an audit.",
        add_in_detail=True,
        add_in_list=True,
    )
    async def build_graphs_action(self, request: Request) -> RedirectResponse:
        """Build knowledge graphs for selected projects. Uses Celery if available, falls back to sync."""
        pks = request.query_params.get("pks", "").split(",")
        
        if not pks or pks == [""]:
            return RedirectResponse(
                request.url_for("admin:list", identity=self.identity),
                status_code=302,
            )
        
        # Try to use Celery worker first (production/scalable mode)
        use_celery = False
        try:
            from worker.tasks import build_graphs_task
            # Test if Celery is actually connected by checking broker
            build_graphs_task.app.control.ping(timeout=1)
            use_celery = True
        except Exception:
            use_celery = False
        
        # Get database session
        from server.api import get_engine
        from database import create_db_session
        engine = get_engine()
        db = create_db_session(engine)
        
        results = []
        try:
            for pk in pks:
                try:
                    project_id = int(pk)
                    project = db.query(Project).filter(Project.id == project_id).first()
                    
                    if not project:
                        results.append(f"Project {pk} not found")
                        continue
                    
                    if not project.source_path and not project.git_url:
                        results.append(f"{project.name}: No source path or git URL")
                        continue
                    
                    if use_celery and project.git_url:
                        # PRODUCTION MODE: Use Celery worker (non-blocking, scalable)
                        import hashlib
                        import time
                        scan_id = f"graphs_{hashlib.md5(project.git_url.encode()).hexdigest()[:12]}_{int(time.time())}"
                        
                        build_graphs_task.delay(
                            repo_url=project.git_url,
                            scan_id=scan_id,
                            tenant_id=project.tenant_id,
                            project_id=project.id,
                            num_graphs=4,
                        )
                        results.append(f"🚀 {project.name}: Graph build queued (Celery)")
                    else:
                        # DEVELOPMENT MODE: Use sync endpoint (blocking)
                        import httpx
                        
                        async def build_graphs_request():
                            async with httpx.AsyncClient(timeout=600.0) as client:
                                host = request.headers.get("host", "localhost:8000")
                                scheme = request.headers.get("x-forwarded-proto", "http")
                                base_url = f"{scheme}://{host}"
                                
                                response = await client.post(
                                    f"{base_url}/graphs/build-sync",
                                    json={
                                        "project_id": project_id,
                                        "num_graphs": 4,
                                        "init_only": False,
                                    }
                                )
                                return response
                        
                        response = await build_graphs_request()
                        
                        if response.status_code == 200:
                            data = response.json()
                            results.append(f"✅ {project.name}: {data['graphs_built']} graphs ({data['total_nodes']}N/{data['total_edges']}E) [sync]")
                        else:
                            error = response.json().get("detail", "Unknown error")
                            results.append(f"❌ {project.name}: {error}")
                        
                except Exception as e:
                    results.append(f"❌ Project {pk}: {str(e)[:100]}")
        finally:
            db.close()
        
        mode = "Celery workers" if use_celery else "sync mode"
        message = f"[{mode}] " + " | ".join(results) if results else "No projects processed"
        
        return RedirectResponse(
            f"/admin/project/list?message={message[:200]}",
            status_code=302,
        )
    
    @action(
        name="run_audit",
        label="Run Audit",
        confirmation_message="Are you sure you want to start an audit for the selected projects?",
        add_in_detail=True,
        add_in_list=True,
    )
    async def run_audit_action(self, request: Request) -> RedirectResponse:
        """Start audit for selected projects. Uses Celery if available, falls back to sync."""
        pks = request.query_params.get("pks", "").split(",")
        
        if not pks or pks == [""]:
            return RedirectResponse(
                request.url_for("admin:list", identity=self.identity),
                status_code=302,
            )
        
        # Try to use Celery worker first (production/scalable mode)
        use_celery = False
        try:
            from worker.tasks import execute_audit_task
            execute_audit_task.app.control.ping(timeout=1)
            use_celery = True
        except Exception:
            use_celery = False
        
        # Get database session
        from server.api import get_engine
        from database import create_db_session
        engine = get_engine()
        db = create_db_session(engine)
        
        results = []
        try:
            for pk in pks:
                try:
                    project_id = int(pk)
                    project = db.query(Project).filter(Project.id == project_id).first()
                    
                    if not project:
                        results.append(f"Project {pk} not found")
                        continue
                    
                    # Check if project has graphs
                    from database.models import Graph
                    graphs_count = db.query(Graph).filter(Graph.project_id == project_id).count()
                    if graphs_count == 0:
                        results.append(f"⚠️ {project.name}: No graphs - build graphs first!")
                        continue
                    
                    if use_celery and project.git_url:
                        # PRODUCTION MODE: Use Celery worker (non-blocking, scalable)
                        import hashlib
                        import time
                        session_id = f"audit_{hashlib.md5(project.git_url.encode()).hexdigest()[:12]}_{int(time.time())}"
                        
                        execute_audit_task.delay(
                            repo_url=project.git_url,
                            scan_id=session_id,
                            tenant_id=project.tenant_id,
                            project_id=project.id,
                        )
                        results.append(f"🚀 {project.name}: Audit queued (Celery)")
                    else:
                        # DEVELOPMENT MODE: Use sync endpoint (blocking)
                        import httpx
                        
                        async def run_audit_request():
                            async with httpx.AsyncClient(timeout=3600.0) as client:
                                host = request.headers.get("host", "localhost:8000")
                                scheme = request.headers.get("x-forwarded-proto", "http")
                                base_url = f"{scheme}://{host}"
                                
                                response = await client.post(
                                    f"{base_url}/audits/run-sync",
                                    json={
                                        "project_id": project_id,
                                        "max_investigations": 20,
                                        "time_limit_minutes": 30,
                                    }
                                )
                                return response
                        
                        response = await run_audit_request()
                        
                        if response.status_code == 200:
                            data = response.json()
                            results.append(f"✅ {project.name}: {data['hypotheses_found']} findings ({data['confirmed_count']} confirmed) [sync]")
                        else:
                            error = response.json().get("detail", "Unknown error")
                            results.append(f"❌ {project.name}: {error}")
                        
                except Exception as e:
                    results.append(f"❌ Project {pk}: {str(e)[:100]}")
        finally:
            db.close()
        
        mode = "Celery workers" if use_celery else "sync mode"
        message = f"[{mode}] " + " | ".join(results) if results else "No projects processed"
        
        return RedirectResponse(
            f"/admin/project/list?message={message[:200]}",
            status_code=302,
        )
    
    @action(
        name="generate_full_report",
        label="Generate Report",
        confirmation_message="Generate comprehensive audit report for selected projects? (Uses all confirmed findings)",
        add_in_detail=True,
        add_in_list=True,
    )
    async def generate_full_report_action(self, request: Request) -> RedirectResponse:
        """Generate report from all confirmed findings in the project (across all audit sessions)."""
        pks = request.query_params.get("pks", "").split(",")
        generated = []
        
        from server.api import get_engine
        from database import create_db_session
        engine = get_engine()
        db = create_db_session(engine)
        
        try:
            import httpx
            for pk in pks:
                if pk:
                    try:
                        project = db.query(Project).filter(Project.id == int(pk)).first()
                        if not project:
                            continue
                        
                        # Find most recent completed audit session for this project
                        latest_session = db.query(AuditSession).filter(
                            AuditSession.project_id == project.id,
                            AuditSession.status == "completed"
                        ).order_by(AuditSession.start_time.desc()).first()
                        
                        if not latest_session:
                            generated.append(f"⚠️ {project.name}: No completed audit sessions found")
                            continue
                        
                        # Call report generation API
                        async def generate_report_request():
                            async with httpx.AsyncClient(timeout=300.0) as client:
                                host = request.headers.get("host", "localhost:8000")
                                scheme = request.headers.get("x-forwarded-proto", "http")
                                base_url = f"{scheme}://{host}"
                                
                                response = await client.post(
                                    f"{base_url}/sessions/{latest_session.session_id}/report",
                                    json={
                                        "format": "html",
                                        "title": f"Security Audit Report: {project.name}",
                                        "auditors": "Security Team",
                                        "include_all": False  # Only confirmed findings
                                    }
                                )
                                return response
                        
                        response = await generate_report_request()
                        
                        if response.status_code == 200:
                            data = response.json()
                            report_path = Path(data['output_path'])
                            findings_count = data['total_findings']
                            # Create downloadable URL
                            report_url = f"/reports/{project.name}/{report_path.name}"
                            generated.append(f"✅ {project.name}: {findings_count} findings → <a href='{report_url}' target='_blank'>{report_path.name}</a>")
                        else:
                            error = response.json().get("detail", "Unknown error")
                            generated.append(f"❌ {project.name}: {error[:50]}")
                            
                    except Exception as e:
                        print(f"Failed to generate report for project {pk}: {e}")
                        import traceback
                        traceback.print_exc()
                        generated.append(f"❌ Project {pk}: {str(e)[:50]}")
        finally:
            db.close()
        
        if generated:
            message = " | ".join(generated)
            request.session["flash"] = Markup(message[:500])
        else:
            request.session["flash"] = "No reports generated"
        
        return RedirectResponse(
            request.url_for("admin:list", identity=self.identity),
            status_code=302,
        )


class AuditSessionAdmin(ModelView, model=AuditSession):
    """Admin view for AuditSession model."""
    
    column_list = [
        AuditSession.id,
        AuditSession.session_id,
        AuditSession.project,
        AuditSession.status,
        AuditSession.start_time,
        AuditSession.end_time,
    ]
    column_searchable_list = [AuditSession.session_id]
    column_sortable_list = [
        AuditSession.id,
        AuditSession.status,
        AuditSession.start_time,
        AuditSession.end_time,
    ]
    column_default_sort = [(AuditSession.start_time, True)]
    column_formatters = {
        AuditSession.status: lambda m, a: status_formatter(m.status),
    }
    # Show more fields in detail view
    column_details_list = [
        AuditSession.id,
        AuditSession.session_id,
        AuditSession.project,
        AuditSession.status,
        AuditSession.start_time,
        AuditSession.end_time,
        AuditSession.models,
        AuditSession.token_usage,
    ]
    icon = "fa-solid fa-magnifying-glass"
    name = "Audit Session"
    name_plural = "Audit Sessions"
    
    @action(
        name="view_progress",
        label="View Progress",
        confirmation_message=None,
        add_in_detail=True,
        add_in_list=True,
    )
    async def view_progress_action(self, request: Request) -> RedirectResponse:
        """Open WebSocket progress viewer for selected session."""
        pks = request.query_params.get("pks", "").split(",")
        
        if pks and pks[0]:
            # Query the session directly
            from server.api import get_engine
            from database import create_db_session
            engine = get_engine()
            db = create_db_session(engine)
            try:
                session = db.query(AuditSession).filter(AuditSession.id == int(pks[0])).first()
                if session:
                    # Redirect to a progress viewer page
                    return RedirectResponse(
                        f"/admin/progress/{session.session_id}",
                        status_code=302,
                    )
            finally:
                db.close()
        
        return RedirectResponse(
            request.url_for("admin:list", identity=self.identity),
            status_code=302,
        )
    
    @action(
        name="abort_audit",
        label="Abort Audit",
        confirmation_message="Are you sure you want to abort the selected audits?",
        add_in_detail=True,
        add_in_list=True,
    )
    async def abort_audit_action(self, request: Request) -> RedirectResponse:
        """Abort running audit sessions."""
        pks = request.query_params.get("pks", "").split(",")
        aborted = []
        
        from server.api import get_engine
        from database import create_db_session
        engine = get_engine()
        db = create_db_session(engine)
        try:
            for pk in pks:
                if pk:
                    try:
                        session = db.query(AuditSession).filter(AuditSession.id == int(pk)).first()
                        if session and session.status == "running":
                            # Update status to aborted
                            session.status = "aborted"
                            db.commit()
                            aborted.append(session.session_id)
                    except Exception as e:
                        print(f"Failed to abort session {pk}: {e}")
        finally:
            db.close()
        
        if aborted:
            request.session["flash"] = f"Aborted: {', '.join(aborted)}"
        
        return RedirectResponse(
            request.url_for("admin:list", identity=self.identity),
            status_code=302,
        )
    
    @action(
        name="generate_report",
        label="Generate Report",
        confirmation_message="Generate audit report for selected sessions? (Confirmed findings only)",
        add_in_detail=True,
        add_in_list=True,
    )
    async def generate_report_action(self, request: Request) -> RedirectResponse:
        """Generate professional HTML audit report for selected sessions."""
        pks = request.query_params.get("pks", "").split(",")
        generated = []
        
        from server.api import get_engine
        from database import create_db_session
        engine = get_engine()
        db = create_db_session(engine)
        
        try:
            import httpx
            for pk in pks:
                if pk:
                    try:
                        session = db.query(AuditSession).filter(AuditSession.id == int(pk)).first()
                        if not session:
                            continue
                        
                        project = db.query(Project).filter(Project.id == session.project_id).first()
                        if not project:
                            continue
                        
                        # Call report generation API
                        async def generate_report_request():
                            async with httpx.AsyncClient(timeout=300.0) as client:
                                host = request.headers.get("host", "localhost:8000")
                                scheme = request.headers.get("x-forwarded-proto", "http")
                                base_url = f"{scheme}://{host}"
                                
                                response = await client.post(
                                    f"{base_url}/sessions/{session.session_id}/report",
                                    json={
                                        "format": "html",
                                        "title": f"Security Audit Report: {project.name}",
                                        "auditors": "Security Team",
                                        "include_all": False  # Only confirmed findings
                                    }
                                )
                                return response
                        
                        response = await generate_report_request()
                        
                        if response.status_code == 200:
                            data = response.json()
                            report_path = Path(data['output_path'])
                            findings_count = data['total_findings']
                            generated.append(f"{project.name}: {findings_count} findings → {report_path.name}")
                        else:
                            error = response.json().get("detail", "Unknown error")
                            generated.append(f"❌ {project.name}: {error[:50]}")
                            
                    except Exception as e:
                        print(f"Failed to generate report for session {pk}: {e}")
                        generated.append(f"❌ Session {pk}: {str(e)[:50]}")
        finally:
            db.close()
        
        if generated:
            message = " | ".join(generated)
            request.session["flash"] = message[:500]
        else:
            request.session["flash"] = "No reports generated"
        
        return RedirectResponse(
            request.url_for("admin:list", identity=self.identity),
            status_code=302,
        )


class ScanExecutionAdmin(ModelView, model=ScanExecution):
    """Admin view for ScanExecution model (Surface Scans)."""
    
    column_list = [
        ScanExecution.id,
        ScanExecution.repo_name,
        ScanExecution.repo_url,
        ScanExecution.status,
        ScanExecution.risk_score,
        ScanExecution.risk_level,
        ScanExecution.contracts_scanned,
        ScanExecution.project_id,
        ScanExecution.created_at,
    ]
    column_searchable_list = [ScanExecution.repo_name, ScanExecution.execution_id, ScanExecution.repo_url]
    column_sortable_list = [
        ScanExecution.id,
        ScanExecution.status,
        ScanExecution.risk_score,
        ScanExecution.risk_level,
        ScanExecution.created_at,
    ]
    column_default_sort = [(ScanExecution.created_at, True)]
    column_formatters = {
        ScanExecution.status: lambda m, a: status_formatter(m.status),
        ScanExecution.risk_level: lambda m, a: severity_formatter(m.risk_level),
        ScanExecution.risk_score: lambda m, a: Markup(
            f'<span class="badge bg-{"danger" if (m.risk_score or 0) >= 70 else "warning" if (m.risk_score or 0) >= 40 else "success"}">'
            f'{m.risk_score or 0}/100</span>'
        ) if m.risk_score is not None else "",
    }
    # Only use column_details_list to specify exactly which fields to show (exclude large JSON fields)
    column_details_list = [
        ScanExecution.id,
        ScanExecution.execution_id,
        ScanExecution.repo_name,
        ScanExecution.repo_url,
        ScanExecution.status,
        ScanExecution.risk_score,
        ScanExecution.risk_level,
        ScanExecution.summary,
        ScanExecution.contracts_scanned,
        ScanExecution.contracts_total,
        ScanExecution.llm_calls_made,
        ScanExecution.project,
        ScanExecution.tenant,
        ScanExecution.error_message,
        ScanExecution.started_at,
        ScanExecution.completed_at,
        ScanExecution.created_at,
    ]
    icon = "fa-solid fa-radar"
    name = "Surface Scan"
    name_plural = "Surface Scans"
    
    # Allow creating new scans
    can_create = True
    can_edit = False  # Scans are read-only after creation
    can_delete = True
    
    # Form fields for creating a new scan
    form_columns = ["repo_url", "tenant"]
    form_args = {
        "repo_url": {
            "label": "Repository URL",
            "description": "GitHub URL to scan (e.g., https://github.com/org/repo). After creating, use the 'Run Scan' action to execute.",
        },
    }
    
    async def on_model_change(self, data, model, is_created, request):
        """Handle new scan creation - set up initial state."""
        if is_created and data.get("repo_url"):
            import uuid
            from datetime import datetime
            from urllib.parse import urlparse
            
            # Set initial state
            repo_url = data.get("repo_url")
            parsed = urlparse(repo_url)
            path_parts = parsed.path.strip("/").split("/")
            repo_name = f"{path_parts[-2]}-{path_parts[-1]}" if len(path_parts) >= 2 else "unknown-repo"
            
            model.execution_id = f"scan_{uuid.uuid4().hex[:12]}_{int(datetime.now().timestamp())}"
            model.repo_name = repo_name
            model.status = "pending"
            model.repo_url = repo_url
    
    @action(
        name="run_scan",
        label="Run Scan",
        confirmation_message="Run surface scan on the selected repositories?",
        add_in_detail=True,
        add_in_list=True,
    )
    async def run_scan_action(self, request: Request) -> RedirectResponse:
        """Run surface scan on pending scan records."""
        pks = request.query_params.get("pks", "").split(",")
        
        if not pks or pks == [""]:
            return RedirectResponse(
                request.url_for("admin:list", identity=self.identity),
                status_code=302,
            )
        
        from analysis.surface import SurfaceScanner
        from utils.config_loader import load_config
        from datetime import datetime
        from server.api import get_engine
        from database import create_db_session
        
        engine = get_engine()
        db = create_db_session(engine)
        scanned = []
        
        try:
            config = load_config()
        except Exception:
            config = {}
        
        scanner = SurfaceScanner(
            config=config,
            llm_budget=0,  # Fast scan without LLM
            model=None,
            quiet=True,
        )
        
        try:
            for pk in pks:
                try:
                    scan = db.query(ScanExecution).filter(ScanExecution.id == int(pk)).first()
                    if scan and scan.repo_url and scan.status in ("pending", "failed"):
                        # Mark as in progress
                        scan.status = "running"
                        scan.started_at = datetime.now()
                        db.commit()
                        
                        # Run the scan
                        result = scanner.scan(scan.repo_url)
                        
                        # Update with results
                        scan.repo_name = result.repo_name
                        scan.status = "completed" if not result.error else "failed"
                        scan.risk_score = result.risk_score
                        scan.risk_level = result.risk_level
                        scan.findings = [f.model_dump() for f in result.findings]
                        scan.quality_metrics = result.quality_metrics.model_dump()
                        scan.summary = result.summary
                        scan.llm_calls_made = result.llm_calls_used
                        scan.contracts_scanned = result.contracts_scanned
                        scan.contracts_total = result.contracts_total
                        scan.error_message = result.error
                        scan.completed_at = datetime.now()
                        db.commit()
                        scanned.append(scan.repo_name)
                except Exception as e:
                    print(f"Failed to scan {pk}: {e}")
        finally:
            db.close()
        
        if scanned:
            request.session["flash"] = f"Scanned: {', '.join(scanned)}"
        else:
            request.session["flash"] = "No scans executed"
        
        return RedirectResponse(
            request.url_for("admin:list", identity=self.identity),
            status_code=302,
        )
    
    @action(
        name="convert_to_project",
        label="Convert to Project",
        confirmation_message="Create a project from the selected scans? This will make them ready for full audits.",
        add_in_detail=True,
        add_in_list=True,
    )
    async def convert_to_project_action(self, request: Request) -> RedirectResponse:
        """Convert selected scans to full projects."""
        pks = request.query_params.get("pks", "").split(",")
        
        if not pks or pks == [""]:
            return RedirectResponse(
                request.url_for("admin:list", identity=self.identity),
                status_code=302,
            )
        
        from server.api import get_engine
        from database import create_db_session
        engine = get_engine()
        db = create_db_session(engine)
        created_projects = []
        
        try:
            for pk in pks:
                try:
                    scan = db.query(ScanExecution).filter(ScanExecution.id == int(pk)).first()
                    if scan and scan.repo_url:
                        # Check if project already exists for this URL
                        existing = db.query(Project).filter(Project.git_url == scan.repo_url).first()
                        if existing:
                            # Link scan to existing project
                            scan.project_id = existing.id
                            db.commit()
                            created_projects.append(f"{scan.repo_name} (linked to existing)")
                            continue
                        
                        # Create new project
                        project = Project(
                            name=scan.repo_name,
                            git_url=scan.repo_url,
                            tenant_id=scan.tenant_id,
                            status="pending",
                        )
                        db.add(project)
                        db.flush()  # Get the project ID
                        
                        # Link scan to project
                        scan.project_id = project.id
                        db.commit()
                        created_projects.append(scan.repo_name)
                except Exception as e:
                    print(f"Failed to convert scan {pk} to project: {e}")
        finally:
            db.close()
        
        if created_projects:
            request.session["flash"] = f"Created projects: {', '.join(created_projects)}"
        else:
            request.session["flash"] = "No projects created"
        
        return RedirectResponse(
            request.url_for("admin:list", identity=self.identity),
            status_code=302,
        )
    
    @action(
        name="view_findings",
        label="View Findings",
        confirmation_message=None,
        add_in_detail=True,
        add_in_list=True,
    )
    async def view_findings_action(self, request: Request) -> RedirectResponse:
        """View scan findings in detail."""
        pks = request.query_params.get("pks", "").split(",")
        
        if pks and pks[0]:
            # Redirect to a findings view page
            return RedirectResponse(
                f"/admin/scan-findings/{pks[0]}",
                status_code=302,
            )
        
        return RedirectResponse(
            request.url_for("admin:list", identity=self.identity),
            status_code=302,
        )
    
    @action(
        name="generate_report",
        label="Generate Report",
        confirmation_message="Generate HTML marketing report for the selected scans?",
        add_in_detail=True,
        add_in_list=True,
    )
    async def generate_report_action(self, request: Request) -> RedirectResponse:
        """Generate HTML report for selected scans."""
        pks = request.query_params.get("pks", "").split(",")
        
        if not pks or pks == [""]:
            return RedirectResponse(
                request.url_for("admin:list", identity=self.identity),
                status_code=302,
            )
        
        from server.api import get_engine
        from database import create_db_session
        from analysis.surface.report import ScanReportGenerator
        from analysis.surface.models import ScanResult, Finding, QualityMetrics
        from pathlib import Path
        
        engine = get_engine()
        db = create_db_session(engine)
        generated_reports = []
        
        try:
            report_gen = ScanReportGenerator()
            reports_dir = Path.home() / ".hound/surface_reports"
            reports_dir.mkdir(parents=True, exist_ok=True)
            
            for pk in pks:
                try:
                    scan = db.query(ScanExecution).filter(ScanExecution.id == int(pk)).first()
                    if scan:
                        # Reconstruct ScanResult from database
                        findings = []
                        for f in (scan.findings or []):
                            findings.append(Finding(**f))
                        
                        qm = scan.quality_metrics or {}
                        quality_metrics = QualityMetrics(**qm)
                        
                        result = ScanResult(
                            repo_url=scan.repo_url,
                            repo_path=scan.repo_url or "",
                            repo_name=scan.repo_name,
                            scan_timestamp=scan.started_at or scan.created_at,
                            risk_score=scan.risk_score or 0,
                            risk_level=scan.risk_level or "low",
                            findings=findings,
                            quality_metrics=quality_metrics,
                            contracts_scanned=scan.contracts_scanned,
                            contracts_total=scan.contracts_total,
                            llm_calls_used=scan.llm_calls_made,
                            summary=scan.summary or "",
                            error=scan.error_message,
                        )
                        
                        # Generate HTML report
                        html = report_gen.generate_html(result)
                        report_path = reports_dir / f"{scan.repo_name}_{scan.execution_id}.html"
                        report_path.write_text(html)
                        generated_reports.append(str(report_path))
                except Exception as e:
                    print(f"Failed to generate report for scan {pk}: {e}")
        finally:
            db.close()
        
        if generated_reports:
            request.session["flash"] = f"Generated {len(generated_reports)} report(s) in {reports_dir}"
        else:
            request.session["flash"] = "No reports generated"
        
        return RedirectResponse(
            request.url_for("admin:list", identity=self.identity),
            status_code=302,
        )


class GraphAdmin(ModelView, model=Graph):
    """Admin view for Graph model."""
    
    column_list = [
        Graph.id,
        Graph.name,
        Graph.internal_name,
        Graph.project,
        Graph.created_at,
        Graph.updated_at,
    ]
    column_searchable_list = [Graph.name, Graph.internal_name]
    column_sortable_list = [Graph.id, Graph.name, Graph.created_at, Graph.updated_at]
    column_default_sort = [(Graph.updated_at, True)]
    # Show data in detail view but formatted
    column_details_list = [
        Graph.id,
        Graph.name,
        Graph.internal_name,
        Graph.project,
        Graph.created_at,
        Graph.updated_at,
    ]
    icon = "fa-solid fa-diagram-project"
    name = "Graph"
    name_plural = "Graphs"
    
    @action(
        name="view_visualization",
        label="View Graph",
        confirmation_message=None,
        add_in_detail=True,
        add_in_list=True,
    )
    async def view_visualization_action(self, request: Request) -> RedirectResponse:
        """Open interactive graph visualization."""
        pks = request.query_params.get("pks", "").split(",")
        
        if pks and pks[0]:
            # Query the graph directly to get project_id
            from server.api import get_engine
            from database import create_db_session
            engine = get_engine()
            db = create_db_session(engine)
            try:
                graph = db.query(Graph).filter(Graph.id == int(pks[0])).first()
                if graph and graph.project_id:
                    # Redirect to project dashboard with this graph selected
                    return RedirectResponse(
                        f"/admin/dashboard/{graph.project_id}",
                        status_code=302,
                    )
            finally:
                db.close()
        
        return RedirectResponse(
            request.url_for("admin:list", identity=self.identity),
            status_code=302,
        )


class HypothesisAdmin(ModelView, model=Hypothesis):
    """Admin view for Hypothesis model."""
    
    column_list = [
        Hypothesis.id,
        Hypothesis.title,
        Hypothesis.vulnerability_type,
        Hypothesis.status,
        Hypothesis.severity,
        Hypothesis.confidence,
        Hypothesis.project,
        Hypothesis.created_at,
    ]
    column_searchable_list = [Hypothesis.title, Hypothesis.vulnerability_type]
    column_sortable_list = [
        Hypothesis.id,
        Hypothesis.status,
        Hypothesis.severity,
        Hypothesis.confidence,
        Hypothesis.created_at,
    ]
    column_default_sort = [(Hypothesis.created_at, True)]
    column_formatters = {
        Hypothesis.status: lambda m, a: status_formatter(m.status),
        Hypothesis.severity: lambda m, a: severity_formatter(m.severity),
        Hypothesis.confidence: lambda m, a: confidence_formatter(m.confidence),
    }
    column_details_list = [
        Hypothesis.id,
        Hypothesis.title,
        Hypothesis.vulnerability_type,
        Hypothesis.status,
        Hypothesis.severity,
        Hypothesis.confidence,
        Hypothesis.description,
        Hypothesis.project,
        Hypothesis.created_at,
    ]
    icon = "fa-solid fa-lightbulb"
    name = "Finding"
    name_plural = "Findings"
    
    @action(
        name="confirm_finding",
        label="Confirm",
        confirmation_message="Mark selected findings as confirmed?",
        add_in_detail=True,
        add_in_list=True,
    )
    async def confirm_finding_action(self, request: Request) -> RedirectResponse:
        """Confirm selected findings."""
        pks = request.query_params.get("pks", "").split(",")
        confirmed = []
        
        from server.api import get_engine
        from database import create_db_session
        engine = get_engine()
        db = create_db_session(engine)
        try:
            for pk in pks:
                if pk:
                    try:
                        finding = db.query(Hypothesis).filter(Hypothesis.id == int(pk)).first()
                        if finding:
                            finding.status = "confirmed"
                            finding.confidence = 1.0
                            db.commit()
                            confirmed.append(finding.title[:30])
                    except Exception as e:
                        print(f"Failed to confirm finding {pk}: {e}")
        finally:
            db.close()
        
        if confirmed:
            request.session["flash"] = f"Confirmed: {len(confirmed)} findings"
        
        return RedirectResponse(
            request.url_for("admin:list", identity=self.identity),
            status_code=302,
        )
    
    @action(
        name="reject_finding",
        label="Reject",
        confirmation_message="Mark selected findings as rejected/false positive?",
        add_in_detail=True,
        add_in_list=True,
    )
    async def reject_finding_action(self, request: Request) -> RedirectResponse:
        """Reject selected findings as false positives."""
        pks = request.query_params.get("pks", "").split(",")
        rejected = []
        
        from server.api import get_engine
        from database import create_db_session
        engine = get_engine()
        db = create_db_session(engine)
        try:
            for pk in pks:
                if pk:
                    try:
                        finding = db.query(Hypothesis).filter(Hypothesis.id == int(pk)).first()
                        if finding:
                            finding.status = "rejected"
                            finding.confidence = 0.0
                            db.commit()
                            rejected.append(finding.title[:30])
                    except Exception as e:
                        print(f"Failed to reject finding {pk}: {e}")
        finally:
            db.close()
        
        if rejected:
            request.session["flash"] = f"Rejected: {len(rejected)} findings"
        
        return RedirectResponse(
            request.url_for("admin:list", identity=self.identity),
            status_code=302,
        )
    
    @action(
        name="confirm_and_report",
        label="Confirm & Generate Report",
        confirmation_message="Confirm selected findings and generate audit report?",
        add_in_detail=True,
        add_in_list=True,
    )
    async def confirm_and_report_action(self, request: Request) -> RedirectResponse:
        """Confirm findings and immediately generate an audit report."""
        pks = request.query_params.get("pks", "").split(",")
        
        from server.api import get_engine
        from database import create_db_session
        engine = get_engine()
        db = create_db_session(engine)
        
        confirmed = []
        project_id = None
        project_name = None
        
        try:
            # First, confirm all selected findings
            for pk in pks:
                if pk:
                    try:
                        finding = db.query(Hypothesis).filter(Hypothesis.id == int(pk)).first()
                        if finding:
                            finding.status = "confirmed"
                            finding.confidence = 1.0
                            db.commit()
                            confirmed.append(finding.title[:30])
                            if not project_id:
                                project_id = finding.project_id
                    except Exception as e:
                        print(f"Failed to confirm finding {pk}: {e}")
            
            if not confirmed:
                request.session["flash"] = "No findings to confirm"
                return RedirectResponse(
                    request.url_for("admin:list", identity=self.identity),
                    status_code=302,
                )
            
            # Get project and latest session
            project = db.query(Project).filter(Project.id == project_id).first()
            if not project:
                request.session["flash"] = f"Confirmed {len(confirmed)} findings, but project not found"
                return RedirectResponse(
                    request.url_for("admin:list", identity=self.identity),
                    status_code=302,
                )
            
            project_name = project.name
            
            # Find most recent completed audit session
            latest_session = db.query(AuditSession).filter(
                AuditSession.project_id == project_id,
                AuditSession.status == "completed"
            ).order_by(AuditSession.start_time.desc()).first()
            
            if not latest_session:
                request.session["flash"] = f"Confirmed {len(confirmed)} findings, but no completed audit session found for report"
                return RedirectResponse(
                    request.url_for("admin:list", identity=self.identity),
                    status_code=302,
                )
            
            # Generate report
            import httpx
            
            async def generate_report_request():
                async with httpx.AsyncClient(timeout=300.0) as client:
                    host = request.headers.get("host", "localhost:8000")
                    scheme = request.headers.get("x-forwarded-proto", "http")
                    base_url = f"{scheme}://{host}"
                    
                    response = await client.post(
                        f"{base_url}/sessions/{latest_session.session_id}/report",
                        json={
                            "format": "html",
                            "title": f"Security Audit Report: {project.name}",
                            "auditors": "Security Team",
                            "include_all": False
                        }
                    )
                    return response
            
            response = await generate_report_request()
            
            if response.status_code == 200:
                data = response.json()
                report_path = Path(data['output_path'])
                findings_count = data['total_findings']
                report_url = f"/reports/{project.name}/{report_path.name}"
                request.session["flash"] = Markup(
                    f"✅ Confirmed {len(confirmed)} findings → Generated report with {findings_count} total findings → "
                    f"<a href='{report_url}' target='_blank'>{report_path.name}</a>"
                )
            else:
                error = response.json().get("detail", "Unknown error")
                request.session["flash"] = f"Confirmed {len(confirmed)} findings, but report generation failed: {error[:100]}"
                
        except Exception as e:
            print(f"Failed in confirm_and_report action: {e}")
            import traceback
            traceback.print_exc()
            request.session["flash"] = f"Error: {str(e)[:100]}"
        finally:
            db.close()
        
        return RedirectResponse(
            request.url_for("admin:list", identity=self.identity),
            status_code=302,
        )


class TokenUsageAdmin(ModelView, model=TokenUsageLog):
    """Admin view for TokenUsageLog model - track LLM costs."""
    
    column_list = [
        TokenUsageLog.id,
        TokenUsageLog.provider,
        TokenUsageLog.model,
        TokenUsageLog.profile,
        TokenUsageLog.total_tokens,
        TokenUsageLog.cost_usd,
        TokenUsageLog.project,
        TokenUsageLog.created_at,
    ]
    column_searchable_list = [TokenUsageLog.model, TokenUsageLog.provider, TokenUsageLog.session_id]
    column_sortable_list = [
        TokenUsageLog.id,
        TokenUsageLog.provider,
        TokenUsageLog.model,
        TokenUsageLog.total_tokens,
        TokenUsageLog.cost_usd,
        TokenUsageLog.created_at,
    ]
    column_default_sort = [(TokenUsageLog.created_at, True)]
    column_formatters = {
        TokenUsageLog.cost_usd: lambda m, a: Markup(
            f'<span class="badge bg-{"success" if (m.cost_usd or 0) < 0.01 else "warning" if (m.cost_usd or 0) < 0.10 else "danger"}">'
            f'${m.cost_usd:.4f}</span>'
        ) if m.cost_usd is not None else Markup('<span class="text-muted">N/A</span>'),
        TokenUsageLog.total_tokens: lambda m, a: f"{m.total_tokens:,}",
        TokenUsageLog.provider: lambda m, a: Markup(
            f'<span class="badge bg-info">{m.provider}</span>'
        ),
    }
    column_details_list = [
        TokenUsageLog.id,
        TokenUsageLog.provider,
        TokenUsageLog.model,
        TokenUsageLog.profile,
        TokenUsageLog.input_tokens,
        TokenUsageLog.output_tokens,
        TokenUsageLog.total_tokens,
        TokenUsageLog.cost_usd,
        TokenUsageLog.project,
        TokenUsageLog.session_id,
        TokenUsageLog.request_type,
        TokenUsageLog.endpoint,
        TokenUsageLog.created_at,
    ]
    icon = "fa-solid fa-coins"
    name = "Token Usage"
    name_plural = "Token Usage"
    
    # Read-only - token logs shouldn't be manually created/edited
    can_create = False
    can_edit = False
    can_delete = True  # Allow cleanup of old logs


def setup_admin(app, engine):
    """
    Set up SQLAdmin with all model views.
    
    Args:
        app: FastAPI application instance
        engine: SQLAlchemy engine instance
        
    Returns:
        Admin instance
    """
    import os
    
    # Get base URL from environment or use default
    # This is important for port forwarding scenarios (Codespaces, ngrok, etc.)
    base_url = os.environ.get("ADMIN_BASE_URL", "/admin")
    
    admin = Admin(
        app,
        engine,
        title="Hound Admin",
        base_url=base_url,
    )
    
    # Register all admin views
    admin.add_view(TenantAdmin)
    admin.add_view(ProjectAdmin)
    admin.add_view(AuditSessionAdmin)
    admin.add_view(ScanExecutionAdmin)
    admin.add_view(GraphAdmin)
    admin.add_view(HypothesisAdmin)
    admin.add_view(TokenUsageAdmin)
    
    return admin
