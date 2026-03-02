"""
SQLAdmin configuration for Hound dashboard.

Provides a GUI admin interface for managing database models.
Access at /admin when mounted to the FastAPI app.
"""

import os
from datetime import datetime
from pathlib import Path

from markupsafe import Markup
from sqladmin import Admin, BaseView, ModelView, action, expose
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse

from database.models import (
    AuditSession,
    Graph,
    Hypothesis,
    PaymentLog,
    Project,
    ScanExecution,
    Team,
    TeamMember,
    Tenant,
    TenantDiscount,
    TokenUsageLog,
    X402Discount,
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
    """Admin view for Tenant model - Organizations/Users."""
    
    page_size = 100
    page_size_options = [25, 50, 100, 200]
    
    column_list = [
        Tenant.id,
        Tenant.name,
        Tenant.status,
        Tenant.plan,
        Tenant.github_account_login,
        Tenant.contact_email,
        Tenant.installation_id,
        Tenant.created_at,
    ]
    column_searchable_list = [Tenant.name, Tenant.github_account_login, Tenant.contact_email]
    column_sortable_list = [Tenant.id, Tenant.name, Tenant.status, Tenant.plan, Tenant.created_at]
    column_default_sort = [(Tenant.created_at, True)]
    column_formatters = {
        Tenant.status: lambda m, a: status_formatter(m.status),
        Tenant.plan: lambda m, a: Markup(
            f'<span class="badge bg-{"success" if m.plan in ("professional", "enterprise") else "info" if m.plan == "starter" else "secondary"}">{m.plan or "free"}</span>'
        ),
        Tenant.name: lambda m, a: Markup(
            f'<strong style="font-size: 1.1em; color: #64b5f6;">{m.name}</strong>'
        ),
    }
    column_details_list = [
        Tenant.id,
        Tenant.name,
        Tenant.status,
        Tenant.plan,
        Tenant.plan_period,
        Tenant.scan_credits,
        Tenant.stripe_customer_id,
        Tenant.stripe_subscription_id,
        Tenant.plan_updated_at,
        Tenant.contact_email,
        Tenant.github_account_login,
        Tenant.github_account_type,
        Tenant.installation_id,
        Tenant.projects,
        Tenant.scan_executions,
        Tenant.created_at,
        Tenant.updated_at,
    ]
    icon = "fa-solid fa-building"
    name = "Tenant / Organization"
    name_plural = "Tenants / Organizations"

    @action(
        name="preview_dashboard",
        label="Preview Dashboard",
        confirmation_message=None,
        add_in_detail=True,
        add_in_list=True,
    )
    async def preview_dashboard_action(self, request: Request) -> RedirectResponse:
        """Open the tenant's dashboard in admin preview mode."""
        pks = request.query_params.get("pks", "").split(",")
        if not pks or pks == [""]:
            return RedirectResponse(
                request.url_for("admin:list", identity=self.identity),
                status_code=302,
            )
        tenant_id = pks[0]
        return RedirectResponse(f"/admin/tenant/{tenant_id}/preview", status_code=302)


class ProjectAdmin(ModelView, model=Project):
    """Admin view for Project model."""
    
    page_size = 100
    page_size_options = [25, 50, 100, 200]
    
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
        Project.tenant: lambda m, a: Markup(
            f'<span class="badge bg-info" style="font-size: 0.9em;">{m.tenant.name if m.tenant else "No Tenant"}</span>'
        ) if m.tenant else Markup('<span class="text-muted">No Tenant</span>'),
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
        from database import create_db_session
        from server.api import get_engine
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
                                # Use localhost for internal API calls to avoid proxy authentication
                                base_url = "http://localhost:8000"
                                
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
        from database import create_db_session
        from server.api import get_engine
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
                                # Use localhost for internal API calls to avoid proxy authentication
                                base_url = "http://localhost:8000"
                                
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
        label="🤖 Generate Report (AI)",
        confirmation_message="Generate AI-powered comprehensive audit report? This analyzes all confirmed findings and generates an executive summary using AI. Takes 30-60 seconds.",
        add_in_detail=True,
        add_in_list=True,
    )
    async def generate_full_report_action(self, request: Request) -> RedirectResponse:
        """Generate report from all confirmed findings with AI-generated executive summary."""
        pks = request.query_params.get("pks", "").split(",")
        generated = []
        
        from database import create_db_session
        from server.api import get_engine
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
                                # Use localhost for internal API calls to avoid proxy authentication
                                base_url = "http://localhost:8000"
                                
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
                            report_url = data.get('report_url', f"/reports/{project.name}/{report_path.name}")
                            generated.append(
                                f"✅ {project.name}: {findings_count} findings → "
                                f"<a href='{report_url}' target='_blank' class='btn btn-sm btn-success'>📄 View Report</a>"
                            )
                        else:
                            error_data = response.json() if response.status_code != 500 else {"detail": "Server error"}
                            error = error_data.get("detail", "Unknown error")
                            generated.append(f"❌ {project.name}: {error[:100]}")
                            
                    except Exception as e:
                        print(f"Failed to generate report for project {pk}: {e}")
                        import traceback
                        traceback.print_exc()
                        generated.append(f"❌ Project {pk}: {str(e)[:50]}")
        finally:
            db.close()
        
        if generated:
            message = " | ".join(generated)
            request.session["flash"] = Markup(message[:1000])
        else:
            request.session["flash"] = "No reports generated"
        
        return RedirectResponse(
            request.url_for("admin:list", identity=self.identity),
            status_code=302,
        )


class AuditSessionAdmin(ModelView, model=AuditSession):
    """Admin view for AuditSession model."""
    
    page_size = 100
    page_size_options = [25, 50, 100, 200]
    
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
        AuditSession.project: lambda m, a: Markup(
            f'<span class="badge bg-primary" style="font-size: 0.9em;">{m.project.name if m.project else "N/A"}</span>'
        ) if m.project else Markup('<span class="text-muted">No Project</span>'),
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
            from database import create_db_session
            from server.api import get_engine
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
        
        from database import create_db_session
        from server.api import get_engine
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
        label="🤖 Generate Report (AI)",
        confirmation_message="Generate AI-powered audit report? This will take 30-60 seconds as the AI analyzes findings and compiles the executive summary. Confirmed findings only.",
        add_in_detail=True,
        add_in_list=True,
    )
    async def generate_report_action(self, request: Request) -> RedirectResponse:
        """Generate professional HTML audit report with AI-generated executive summary."""
        pks = request.query_params.get("pks", "").split(",")
        generated = []
        
        from database import create_db_session
        from server.api import get_engine
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
                                # Use localhost for internal API calls to avoid proxy authentication
                                base_url = "http://localhost:8000"
                                
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
                            report_url = data.get('report_url', f"/reports/{project.name}/{report_path.name}")
                            generated.append(
                                f"✅ {project.name}: {findings_count} findings → "
                                f"<a href='{report_url}' target='_blank' class='text-success'><strong>📄 View Report</strong></a>"
                            )
                        else:
                            error_data = response.json() if response.status_code != 500 else {"detail": "Server error - check logs"}
                            error = error_data.get("detail", "Unknown error")
                            generated.append(f"❌ {project.name}: {error[:100]}")
                            
                    except Exception as e:
                        print(f"Failed to generate report for session {pk}: {e}")
                        generated.append(f"❌ Session {pk}: {str(e)[:50]}")
        finally:
            db.close()
        
        if generated:
            message = " | ".join(generated)
            request.session["flash"] = Markup(message[:1000])
        else:
            request.session["flash"] = "No reports generated"
        
        return RedirectResponse(
            request.url_for("admin:list", identity=self.identity),
            status_code=302,
        )


class ScanExecutionAdmin(ModelView, model=ScanExecution):
    """Admin view for ScanExecution model (Surface Scans)."""
    
    page_size = 100
    page_size_options = [25, 50, 100, 200]
    
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
    column_details_formatters = {
        ScanExecution.findings: lambda m, a: ScanExecutionAdmin.format_findings(m, a),
        ScanExecution.quality_metrics: lambda m, a: ScanExecutionAdmin.format_quality_metrics(m, a),
        ScanExecution.status: lambda m, a: status_formatter(m.status),
        ScanExecution.risk_level: lambda m, a: severity_formatter(m.risk_level),
    }
    # Custom formatter for findings JSON - display as formatted HTML
    @staticmethod
    def format_findings(m, a):
        """Format findings JSON as readable HTML with severity badges."""
        import json
        if not m.findings:
            return Markup('<p class="text-muted">No findings available</p>')
        
        try:
            findings = m.findings if isinstance(m.findings, dict) else json.loads(m.findings)
            html = '<div class="findings-container" style="max-width: 900px;">'
            
            severity_order = [('critical', 'danger'), ('high', 'warning'), ('medium', 'info'), ('low', 'secondary')]
            total_count = 0
            
            for severity, badge_color in severity_order:
                findings_list = findings.get(severity, [])
                if not findings_list:
                    continue
                    
                count = len(findings_list)
                total_count += count
                html += f'<h5 class="mt-3"><span class="badge bg-{badge_color} text-uppercase">{severity}</span> ({count})</h5>'
                
                for finding in findings_list:
                    confidence_pct = int(finding.get('confidence', 0) * 100)
                    html += f'''
                    <div class="card mb-2" style="border-left: 4px solid var(--bs-{badge_color});">
                        <div class="card-body p-3">
                            <h6 class="card-title mb-1">
                                <strong>{finding.get('id', 'N/A')}</strong>: {finding.get('title', 'Untitled')}
                                <span class="badge bg-secondary ms-2">{confidence_pct}% confidence</span>
                            </h6>
                            <p class="mb-1 text-muted small">
                                <i class="fa-solid fa-file-code"></i> {finding.get('contract', 'Unknown')} 
                                <i class="fa-solid fa-hashtag ms-2"></i> Line {finding.get('line', 'N/A')}
                            </p>
                            <p class="mb-2">{finding.get('description', 'No description')}</p>
                            <div class="alert alert-info mb-0 py-2">
                                <strong>💡 Recommendation:</strong> {finding.get('recommendation', 'No recommendation')}
                            </div>
                        </div>
                    </div>
                    '''
            
            if total_count == 0:
                html += '<p class="text-muted">No findings to display</p>'
            
            html += '</div>'
            return Markup(html)
        except Exception as e:
            return Markup(f'<p class="text-danger">Error formatting findings: {str(e)}</p>')
    
    # Custom formatter for quality metrics
    @staticmethod
    def format_quality_metrics(m, a):
        """Format quality metrics as progress bars."""
        import json
        if not m.quality_metrics:
            return Markup('<p class="text-muted">No metrics available</p>')
        
        try:
            metrics = m.quality_metrics if isinstance(m.quality_metrics, dict) else json.loads(m.quality_metrics)
            html = '<div class="metrics-container" style="max-width: 600px;">'
            
            metric_labels = {
                'security_score': '🔒 Security Score',
                'code_coverage': '📊 Code Coverage',
                'test_coverage': '✅ Test Coverage',
                'documentation_score': '📝 Documentation',
                'dependency_health': '📦 Dependency Health',
                'maintainability': '🔧 Maintainability'
            }
            
            for key, label in metric_labels.items():
                value = metrics.get(key, 0)
                percent = int(value * 100)
                
                if percent >= 80:
                    bar_color = 'success'
                elif percent >= 60:
                    bar_color = 'info'
                elif percent >= 40:
                    bar_color = 'warning'
                else:
                    bar_color = 'danger'
                
                html += f'''
                <div class="mb-2">
                    <div class="d-flex justify-content-between mb-1">
                        <span style="font-size: 0.9em;">{label}</span>
                        <span class="badge bg-{bar_color}">{percent}%</span>
                    </div>
                    <div class="progress" style="height: 20px;">
                        <div class="progress-bar bg-{bar_color}" role="progressbar" style="width: {percent}%"></div>
                    </div>
                </div>
                '''
            
            html += '</div>'
            return Markup(html)
        except Exception as e:
            return Markup(f'<p class="text-danger">Error formatting metrics: {str(e)}</p>')
    
    # Only use column_details_list to specify exactly which fields to show (exclude large JSON fields)
    # Note: Findings and metrics are available via "View Findings" action button
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
    # Add helpful note in column labels
    column_labels = {
        ScanExecution.summary: "Summary (📋 Use 'View Findings' button for detailed findings)"
    }
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
        
        from datetime import datetime

        from analysis.surface import SurfaceScanner
        from database import create_db_session
        from server.api import get_engine
        from utils.config_loader import load_config
        
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
        
        from database import create_db_session
        from server.api import get_engine
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
        
        from pathlib import Path

        from analysis.surface.models import Finding, QualityMetrics, ScanResult
        from analysis.surface.report import ScanReportGenerator
        from database import create_db_session
        from server.api import get_engine
        
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
    
    page_size = 100
    page_size_options = [25, 50, 100, 200]
    
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
    column_formatters = {
        Graph.project: lambda m, a: Markup(
            f'<span class="badge bg-primary" style="font-size: 0.9em;">{m.project.name if m.project else "N/A"}</span>'
        ) if m.project else Markup('<span class="text-muted">No Project</span>'),
    }
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
            from database import create_db_session
            from server.api import get_engine
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
    
    page_size = 100
    page_size_options = [25, 50, 100, 200]
    
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
        Hypothesis.project: lambda m, a: Markup(
            f'<span class="badge bg-primary" style="font-size: 0.9em;">{m.project.name if m.project else "N/A"}</span>'
        ) if m.project else Markup('<span class="text-muted">No Project</span>'),
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
        
        from database import create_db_session
        from server.api import get_engine
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
        
        from database import create_db_session
        from server.api import get_engine
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
        label="✅ Confirm & Generate Report (AI)",
        confirmation_message="Confirm selected findings and generate AI-powered audit report? The AI will analyze findings and create an executive summary. Takes 30-60 seconds.",
        add_in_detail=True,
        add_in_list=True,
    )
    async def confirm_and_report_action(self, request: Request) -> RedirectResponse:
        """Confirm findings and immediately generate an AI-powered audit report."""
        pks = request.query_params.get("pks", "").split(",")
        
        from database import create_db_session
        from server.api import get_engine
        engine = get_engine()
        db = create_db_session(engine)
        
        confirmed = []
        project_id = None
        
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
                    # Use localhost for internal API calls to avoid proxy authentication
                    base_url = "http://localhost:8000"
                    
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
                report_url = data.get('report_url', f"/reports/{project.name}/{report_path.name}")
                request.session["flash"] = Markup(
                    f"✅ Confirmed {len(confirmed)} findings → AI generated report with {findings_count} total findings → "
                    f"<a href='{report_url}' target='_blank' class='btn btn-sm btn-success'>📄 View Report</a>"
                )
            else:
                error_data = response.json() if response.status_code != 500 else {"detail": "Server error"}
                error = error_data.get("detail", "Unknown error")
                request.session["flash"] = f"Confirmed {len(confirmed)} findings, but report generation failed: {error[:150]}"
                
        except Exception as e:
            print(f"Failed in confirm_and_report action: {e}")
            import traceback
            traceback.print_exc()
            request.session["flash"] = f"Error: {str(e)[:150]}"
        finally:
            db.close()
        
        return RedirectResponse(
            request.url_for("admin:list", identity=self.identity),
            status_code=302,
        )


class TeamAdmin(ModelView, model=Team):
    """Admin view for Team model - repository-based team access control."""

    column_list = [
        Team.id,
        Team.name,
        Team.github_repo_name,
        Team.github_repo_id,
        Team.last_synced_at,
        Team.created_at,
    ]
    column_searchable_list = [Team.name, Team.github_repo_name]
    column_sortable_list = [
        Team.id,
        Team.name,
        Team.github_repo_name,
        Team.created_at,
        Team.last_synced_at,
    ]
    column_default_sort = [(Team.created_at, True)]
    column_details_list = [
        Team.id,
        Team.name,
        Team.github_repo_id,
        Team.github_repo_name,
        Team.last_synced_at,
        Team.created_at,
        Team.updated_at,
    ]
    icon = "fa-solid fa-people-group"
    name = "Team"
    name_plural = "Teams"
    can_create = True
    can_edit = True
    can_delete = True


class TeamMemberAdmin(ModelView, model=TeamMember):
    """Admin view for TeamMember model - team membership management."""

    column_list = [
        TeamMember.id,
        TeamMember.team,
        TeamMember.user,
        TeamMember.role,
        TeamMember.joined_at,
    ]
    column_searchable_list = [TeamMember.role]
    column_sortable_list = [
        TeamMember.id,
        TeamMember.role,
        TeamMember.joined_at,
    ]
    column_default_sort = [(TeamMember.joined_at, True)]
    column_formatters = {
        TeamMember.role: lambda m, a: Markup(
            f'<span class="badge bg-{"danger" if m.role == "admin" else "primary" if m.role == "member" else "secondary"}">'
            f'{m.role}</span>'
        ),
    }
    column_details_list = [
        TeamMember.id,
        TeamMember.team,
        TeamMember.user,
        TeamMember.role,
        TeamMember.joined_at,
    ]
    icon = "fa-solid fa-user-group"
    name = "Team Member"
    name_plural = "Team Members"
    can_create = True
    can_edit = True
    can_delete = True


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


class PaymentLogAdmin(ModelView, model=PaymentLog):
    """Admin view for PaymentLog model — x402 payment tracking."""

    page_size = 50
    column_list = [
        PaymentLog.id,
        PaymentLog.endpoint,
        PaymentLog.status,
        PaymentLog.amount_usd,
        PaymentLog.discount_code,
        PaymentLog.resolved_price_cents,
        PaymentLog.payer_address,
        PaymentLog.created_at,
    ]
    column_searchable_list = [PaymentLog.endpoint, PaymentLog.discount_code, PaymentLog.payer_address]
    column_sortable_list = [PaymentLog.id, PaymentLog.status, PaymentLog.amount_usd, PaymentLog.created_at]
    column_default_sort = [(PaymentLog.created_at, True)]
    column_formatters = {
        PaymentLog.status: lambda m, a: status_formatter(m.status),
        PaymentLog.amount_usd: lambda m, a: Markup(
            f'<span class="badge bg-success">${m.amount_usd:.2f}</span>'
        ) if m.amount_usd else "",
        PaymentLog.discount_code: lambda m, a: Markup(
            f'<span class="badge bg-warning">{m.discount_code}</span>'
        ) if m.discount_code else "",
    }
    icon = "fa-solid fa-credit-card"
    name = "Payment Log"
    name_plural = "Payment Logs"
    can_create = False
    can_edit = False
    can_delete = True


class X402DiscountAdmin(ModelView, model=X402Discount):
    """Admin view for X402Discount model — coupon management."""

    page_size = 50
    column_list = [
        X402Discount.id,
        X402Discount.code,
        X402Discount.fixed_price_cents,
        X402Discount.percentage_off,
        X402Discount.endpoint,
        X402Discount.active,
        X402Discount.current_uses,
        X402Discount.max_uses,
        X402Discount.max_uses_per_tenant,
        X402Discount.expires_at,
        X402Discount.created_at,
    ]
    column_searchable_list = [X402Discount.code, X402Discount.endpoint]
    column_sortable_list = [X402Discount.id, X402Discount.code, X402Discount.active, X402Discount.created_at]
    column_default_sort = [(X402Discount.created_at, True)]
    column_formatters = {
        X402Discount.active: lambda m, a: Markup(
            f'<span class="badge bg-{"success" if m.active else "danger"}">{"Active" if m.active else "Inactive"}</span>'
        ),
        X402Discount.fixed_price_cents: lambda m, a: Markup(
            f'<span class="badge bg-info">${m.fixed_price_cents / 100:.2f}</span>'
        ) if m.fixed_price_cents is not None else "",
        X402Discount.percentage_off: lambda m, a: Markup(
            f'<span class="badge bg-info">{m.percentage_off}% off</span>'
        ) if m.percentage_off is not None else "",
        X402Discount.current_uses: lambda m, a: Markup(
            f'{m.current_uses}/{m.max_uses if m.max_uses is not None else "∞"}'
        ),
    }
    icon = "fa-solid fa-tags"
    name = "X402 Discount"
    name_plural = "X402 Discounts"
    can_create = True
    can_edit = True
    can_delete = True


class TenantDiscountAdmin(ModelView, model=TenantDiscount):
    """Admin view for TenantDiscount model — coupon redemptions."""

    page_size = 50
    column_list = [
        TenantDiscount.id,
        TenantDiscount.tenant,
        TenantDiscount.discount,
        TenantDiscount.uses,
        TenantDiscount.redeemed_at,
    ]
    column_sortable_list = [TenantDiscount.id, TenantDiscount.uses, TenantDiscount.redeemed_at]
    column_default_sort = [(TenantDiscount.redeemed_at, True)]
    icon = "fa-solid fa-ticket"
    name = "Tenant Discount"
    name_plural = "Tenant Discounts"
    can_create = True
    can_edit = True
    can_delete = True


class ReportsView(BaseView):
    """Custom view to browse and access generated audit reports."""
    
    name = "Reports"
    icon = "fa-solid fa-file-pdf"
    
    @expose("/reports-list", methods=["GET"])
    async def reports_list(self, request: Request):
        """Display list of all generated reports."""
        reports_dir = Path.home() / ".hound" / "reports"
        
        reports = []
        if reports_dir.exists():
            for project_dir in sorted(reports_dir.iterdir()):
                if project_dir.is_dir():
                    for report_file in sorted(project_dir.glob("*.html"), reverse=True):
                        # Extract date from filename: audit_report_YYYYMMDD_HHMMSS.html
                        try:
                            filename = report_file.name
                            date_part = filename.replace("audit_report_", "").replace(".html", "")
                            date_str, time_str = date_part.split("_")
                            report_date = datetime.strptime(date_str, "%Y%m%d").strftime("%Y-%m-%d")
                            report_time = datetime.strptime(time_str, "%H%M%S").strftime("%H:%M:%S")
                        except Exception:
                            report_date = datetime.fromtimestamp(report_file.stat().st_mtime).strftime("%Y-%m-%d")
                            report_time = datetime.fromtimestamp(report_file.stat().st_mtime).strftime("%H:%M:%S")
                        
                        # Build URL path
                        report_url = f"/reports/{project_dir.name}/{report_file.name}"
                        
                        # Get file size
                        size_bytes = report_file.stat().st_size
                        size_kb = size_bytes / 1024
                        
                        reports.append({
                            "project": project_dir.name,
                            "filename": report_file.name,
                            "date": report_date,
                            "time": report_time,
                            "size": f"{size_kb:.1f} KB",
                            "url": report_url,
                            "path": str(report_file),
                        })
        
        # Generate HTML table
        html = """
<!DOCTYPE html>
<html>
<head>
    <title>Audit Reports - Firepan Security</title>
    <link rel="stylesheet" href="/admin/statics/css/tabler.min.css">
    <link rel="stylesheet" href="/admin/statics/css/tabler-icons.min.css">
    <style>
        body { background: #1a1d22; color: #c8d0db; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        .page-header { margin-bottom: 30px; }
        .card { background: #242d3a; border: 1px solid #2d3748; border-radius: 8px; }
        .table { color: #c8d0db; }
        .table thead { background: #1e2531; }
        .badge { font-size: 0.85em; }
        a.btn-primary { background: #3b82f6; border-color: #3b82f6; }
        a.btn-primary:hover { background: #2563eb; }
    </style>
</head>
<body>
    <div class="container">
        <div class="page-header">
            <div class="row align-items-center">
                <div class="col">
                    <h1 class="page-title">
                        <i class="ti ti-file-text me-2"></i>
                        Audit Reports
                    </h1>
                    <p class="text-muted">Browse and download generated security audit reports</p>
                </div>
                <div class="col-auto">
                    <a href="/admin" class="btn btn-secondary">
                        <i class="ti ti-arrow-left me-2"></i>Back to Admin
                    </a>
                </div>
            </div>
        </div>
        
        <div class="card">
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-hover table-vcenter">
                        <thead>
                            <tr>
                                <th>Project</th>
                                <th>Generated</th>
                                <th>Time</th>
                                <th>Size</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
"""
        
        if not reports:
            html += """
                            <tr>
                                <td colspan="5" class="text-center text-muted py-5">
                                    <i class="ti ti-inbox" style="font-size: 3em; opacity: 0.3;"></i>
                                    <p class="mt-3">No reports generated yet</p>
                                </td>
                            </tr>
"""
        else:
            for report in reports:
                html += f"""
                            <tr>
                                <td>
                                    <span class="badge bg-blue">{report['project']}</span>
                                </td>
                                <td>{report['date']}</td>
                                <td><span class="text-muted">{report['time']}</span></td>
                                <td><span class="badge bg-secondary">{report['size']}</span></td>
                                <td>
                                    <a href="{report['url']}" target="_blank" class="btn btn-sm btn-primary">
                                        <i class="ti ti-eye me-1"></i>View Report
                                    </a>
                                </td>
                            </tr>
"""
        
        html += """
                        </tbody>
                    </table>
                </div>
            </div>
            <div class="card-footer text-muted">
                """ + f"""Total reports: <strong>{len(reports)}</strong>""" + """
            </div>
        </div>
    </div>
</body>
</html>
"""
        
        return HTMLResponse(html)


class ScanFindingsView(BaseView):
    """Custom view to display scan findings in detail."""
    
    name = "Scan Findings"
    icon = "fa-solid fa-bug"
    
    @expose("/scan-findings/<scan_id>", methods=["GET"])
    async def findings_detail(self, request: Request):
        """Display findings for a specific scan."""

        from database import create_db_session
        from server.api import get_engine
        
        scan_id = request.path_params.get("scan_id")
        
        engine = get_engine()
        db = create_db_session(engine)
        
        try:
            scan = db.query(ScanExecution).filter(ScanExecution.id == int(scan_id)).first()
            
            if not scan:
                return HTMLResponse("""
                    <html><body style="background: #1a1d22; color: #c8d0db; padding: 40px; text-align: center;">
                        <h1>Scan Not Found</h1>
                        <p>The requested scan does not exist.</p>
                        <a href="/admin/scan-execution/list" style="color: #3b82f6;">Back to Scans</a>
                    </body></html>
                """, status_code=404)
            
            # Format findings
            findings_html = ScanExecutionAdmin.format_findings(scan, None)
            metrics_html = ScanExecutionAdmin.format_quality_metrics(scan, None)
            
            # Build HTML page
            html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Scan Findings - {scan.repo_name}</title>
    <link rel="stylesheet" href="/admin/statics/css/tabler.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body {{ background: #1a1d22; color: #c8d0db; padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        .page-header {{ margin-bottom: 30px; }}
        .card {{ background: #242d3a; border: 1px solid #2d3748; border-radius: 8px; margin-bottom: 20px; }}
        .card-header {{ background: #1e2531; padding: 15px 20px; border-bottom: 1px solid #2d3748; font-weight: 600; }}
        .card-body {{ padding: 20px; }}
        .badge {{ font-size: 0.85em; padding: 6px 12px; }}
        .info-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-bottom: 20px; }}
        .info-item {{ background: #1e2531; padding: 15px; border-radius: 6px; }}
        .info-label {{ color: #717a87; font-size: 0.85em; margin-bottom: 5px; }}
        .info-value {{ font-size: 1.1em; font-weight: 600; }}
        a.btn-primary {{ background: #3b82f6; border-color: #3b82f6; color: white; padding: 8px 16px; text-decoration: none; border-radius: 4px; display: inline-block; }}
        a.btn-primary:hover {{ background: #2563eb; }}
        a.btn-secondary {{ background: #4b5563; border-color: #4b5563; color: white; padding: 8px 16px; text-decoration: none; border-radius: 4px; display: inline-block; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="page-header">
            <div class="row align-items-center">
                <div class="col">
                    <h1 class="page-title">
                        <i class="fa-solid fa-radar me-2"></i>
                        Surface Scan Findings
                    </h1>
                    <p class="text-muted">{scan.repo_name}</p>
                </div>
                <div class="col-auto">
                    <a href="/admin/scan-execution/details/{scan.id}" class="btn-secondary me-2">
                        <i class="fa-solid fa-arrow-left me-2"></i>Back to Scan
                    </a>
                    <a href="/admin/scan-execution/list" class="btn-primary">
                        <i class="fa-solid fa-list me-2"></i>All Scans
                    </a>
                </div>
            </div>
        </div>
        
        <!-- Scan Overview -->
        <div class="card">
            <div class="card-header">Scan Overview</div>
            <div class="card-body">
                <div class="info-grid">
                    <div class="info-item">
                        <div class="info-label">Execution ID</div>
                        <div class="info-value"><code>{scan.execution_id}</code></div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Status</div>
                        <div class="info-value">{status_formatter(scan.status)}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Risk Score</div>
                        <div class="info-value">
                            <span class="badge bg-{"danger" if (scan.risk_score or 0) >= 70 else "warning" if (scan.risk_score or 0) >= 40 else "success"}">
                                {scan.risk_score or 0}/100
                            </span>
                        </div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Contracts Scanned</div>
                        <div class="info-value">{scan.contracts_scanned} / {scan.contracts_total}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Repository</div>
                        <div class="info-value">
                            {"<a href='" + scan.repo_url + "' target='_blank' style='color: #3b82f6;'>" + scan.repo_url + "</a>" if scan.repo_url else "N/A"}
                        </div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Completed At</div>
                        <div class="info-value">{scan.completed_at.strftime("%Y-%m-%d %H:%M:%S") if scan.completed_at else "N/A"}</div>
                    </div>
                </div>
                
                {f"<div class='alert alert-info'><strong>Summary:</strong> {scan.summary}</div>" if scan.summary else ""}
            </div>
        </div>
        
        <!-- Security Findings -->
        <div class="card">
            <div class="card-header">
                <i class="fa-solid fa-bug me-2"></i>Security Findings
            </div>
            <div class="card-body">
                {findings_html}
            </div>
        </div>
        
        <!-- Quality Metrics -->
        <div class="card">
            <div class="card-header">
                <i class="fa-solid fa-chart-line me-2"></i>Quality Metrics
            </div>
            <div class="card-body">
                {metrics_html}
            </div>
        </div>
    </div>
</body>
</html>
"""
            
            return HTMLResponse(html)
        
        finally:
            db.close()


def setup_admin(app, engine):
    """
    Set up SQLAdmin with all model views.
    
    Args:
        app: FastAPI application instance
        engine: SQLAlchemy engine instance
        
    Returns:
        Admin instance
    """
    
    # Get base URL from environment or use default
    # This is important for port forwarding scenarios (Codespaces, ngrok, etc.)
    base_url = os.environ.get("ADMIN_BASE_URL", "/admin")
    
    admin = Admin(
        app,
        engine,
        title="Firepan Admin",
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
    admin.add_view(TeamAdmin)
    admin.add_view(TeamMemberAdmin)
    admin.add_view(PaymentLogAdmin)
    admin.add_view(X402DiscountAdmin)
    admin.add_view(TenantDiscountAdmin)
    admin.add_view(ReportsView)
    # Note: ScanFindingsView not added to navigation - accessible only via "View Findings" action
    
    return admin
