"""
SQLAdmin configuration for Hound dashboard.

Provides a GUI admin interface for managing database models.
Access at /admin when mounted to the FastAPI app.
"""

from sqladmin import Admin, ModelView, action
from sqladmin.formatters import BASE_FORMATTERS
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
        """Build knowledge graphs for selected projects."""
        pks = request.query_params.get("pks", "").split(",")
        
        if not pks or pks == [""]:
            return RedirectResponse(
                request.url_for("admin:list", identity=self.identity),
                status_code=302,
            )
        
        # Import worker task
        try:
            from worker.tasks import build_graphs_task
        except ImportError:
            request.session["flash"] = "Worker tasks not available"
            return RedirectResponse(
                request.url_for("admin:list", identity=self.identity),
                status_code=302,
            )
        
        # Get projects and start graph builds
        from server.api import get_engine
        from database import create_db_session
        engine = get_engine()
        db = create_db_session(engine)
        started_projects = []
        try:
            for pk in pks:
                try:
                    project = db.query(Project).filter(Project.id == int(pk)).first()
                    if project and project.git_url:
                        import hashlib
                        import time
                        scan_id = f"graphs_{hashlib.md5(project.git_url.encode()).hexdigest()[:12]}_{int(time.time())}"
                        
                        # Dispatch graph build task
                        build_graphs_task.delay(
                            repo_url=project.git_url,
                            scan_id=scan_id,
                            tenant_id=project.tenant_id,
                            project_id=project.id,
                        )
                        started_projects.append(project.name)
                except Exception as e:
                    print(f"Failed to start graph build for project {pk}: {e}")
        finally:
            db.close()
        
        if started_projects:
            message = f"Graph build started for: {', '.join(started_projects)}"
        else:
            message = "No graph builds started (projects may be missing git_url)"
        
        request.session["flash"] = message
        
        return RedirectResponse(
            request.url_for("admin:list", identity=self.identity),
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
        """Start an audit for selected projects."""
        pks = request.query_params.get("pks", "").split(",")
        
        if not pks or pks == [""]:
            # No projects selected
            return RedirectResponse(
                request.url_for("admin:list", identity=self.identity),
                status_code=302,
            )
        
        # Import worker task
        try:
            from worker.tasks import execute_audit_task
        except ImportError:
            # Worker not available, flash error
            request.session["flash"] = "Worker tasks not available"
            return RedirectResponse(
                request.url_for("admin:list", identity=self.identity),
                status_code=302,
            )
        
        # Get projects and start audits
        from server.api import get_engine
        from database import create_db_session
        engine = get_engine()
        db = create_db_session(engine)
        started_projects = []
        try:
            for pk in pks:
                try:
                    project = db.query(Project).filter(Project.id == int(pk)).first()
                    if project and project.git_url:
                        # Generate session ID
                        import hashlib
                        import time
                        session_id = f"audit_{hashlib.md5(project.git_url.encode()).hexdigest()[:12]}_{int(time.time())}"
                        
                        # Dispatch audit task
                        execute_audit_task.delay(
                            repo_url=project.git_url,
                            scan_id=session_id,
                            tenant_id=project.tenant_id,
                            project_id=project.id,
                        )
                        started_projects.append(project.name)
                except Exception as e:
                    # Log error but continue with other projects
                    print(f"Failed to start audit for project {pk}: {e}")
        finally:
            db.close()
        
        # Flash success message
        if started_projects:
            message = f"Audit started for: {', '.join(started_projects)}"
        else:
            message = "No audits started (projects may be missing git_url)"
        
        # Store flash message in session
        request.session["flash"] = message
        
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


class ScanExecutionAdmin(ModelView, model=ScanExecution):
    """Admin view for ScanExecution model (Surface Scans)."""
    
    column_list = [
        ScanExecution.id,
        ScanExecution.repo_name,
        ScanExecution.status,
        ScanExecution.risk_level,
        ScanExecution.created_at,
    ]
    column_searchable_list = [ScanExecution.repo_name, ScanExecution.execution_id]
    column_sortable_list = [
        ScanExecution.id,
        ScanExecution.status,
        ScanExecution.risk_level,
        ScanExecution.created_at,
    ]
    column_default_sort = [(ScanExecution.created_at, True)]
    # Exclude large JSON/text fields from detail view
    column_details_exclude_list = [
        ScanExecution.findings,
        ScanExecution.quality_metrics,
        ScanExecution.scan_config,
    ]
    icon = "fa-solid fa-radar"
    name = "Scan"
    name_plural = "Scans"


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
    
    return admin
