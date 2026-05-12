"""
Agent-native audit API.

Provides a clean pay-per-audit flow for external agents:
  POST /agent/audits                — start a paid deep audit (x402)
  GET  /agent/audits/{id}/status    — poll status
  GET  /agent/audits/{id}/findings  — fetch findings
  GET  /agent/audits/{id}/report    — fetch formatted report
  GET  /agent/audits/{id}/graphs    — list knowledge graphs
  GET  /agent/audits/{id}/graphs/{graph_id} — fetch full graph data
  POST /agent/surface-scan          — quick surface scan ($0.50)

No SaaS project setup required.  Ownership is enforced via tenant_id
stored directly on the AuditSession row.

NOTE: This router is imported and mounted by server/api.py.  get_db and
get_current_tenant_id are injected via ``configure_dependencies()`` to
avoid circular imports.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database.models import AuditSession, Graph, Hypothesis, ScanExecution
from server.auth_utils import reject_preview_writes

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/agent", tags=["agent"])

# Placeholders — filled by configure_dependencies() from api.py
_get_db_dep = None
_get_tenant_dep = None


def configure_dependencies(get_db, get_current_tenant_id):
    """Inject api-level dependencies to break circular import."""
    global _get_db_dep, _get_tenant_dep
    _get_db_dep = get_db
    _get_tenant_dep = get_current_tenant_id


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class AgentAuditRequest(BaseModel):
    """Request body for POST /agent/audits."""
    repo_url: str = Field(..., description="Git repository URL (HTTPS)")
    installation_id: int | None = Field(None, description="GitHub App installation ID (for private repos)")
    investigation_prompt: str | None = Field(None, description="Custom investigation focus prompt")
    max_iterations: int = Field(default=30, ge=1, le=200, description="Max agent iterations per investigation")
    time_limit_minutes: int = Field(default=120, ge=5, le=480, description="Overall time budget in minutes")
    mode: Literal["sweep", "intuition", "auditor"] = Field(default="sweep", description="Audit mode: 'sweep', 'intuition', or 'auditor' (single-auditor + fp-check, opt-in — firepan-vff)")
    plan_n: int = Field(default=5, ge=1, le=20, description="Investigations to plan per batch")


class AgentAuditResponse(BaseModel):
    """Response from POST /agent/audits."""
    session_id: str
    status: str
    status_url: str
    results_url: str
    message: str


class AgentAuditStatusResponse(BaseModel):
    """Response from GET /agent/audits/{id}/status."""
    session_id: str
    status: str
    progress: dict[str, Any] | None = None
    findings_count: int = 0
    error_message: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None


class AgentFindingItem(BaseModel):
    """A single finding returned to the agent."""
    id: int
    hypothesis_id: str | None = None
    title: str
    description: str | None = None
    vulnerability_type: str | None = None
    status: str
    confidence: float | None = None
    severity: str | None = None
    evidence: Any | None = None
    created_at: datetime | None = None


class AgentFindingsResponse(BaseModel):
    """Response from GET /agent/audits/{id}/findings."""
    session_id: str
    findings: list[AgentFindingItem]
    total: int


class AgentReportResponse(BaseModel):
    """Response from GET /agent/audits/{id}/report."""
    session_id: str
    status: str
    report_markdown: str | None = None
    report_url: str | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _db():
    """Return the get_db dependency (must be configured first)."""
    if _get_db_dep is None:
        raise RuntimeError("agent_routes dependencies not configured")
    return _get_db_dep


def _tenant():
    """Return the get_current_tenant_id dependency."""
    if _get_tenant_dep is None:
        raise RuntimeError("agent_routes dependencies not configured")
    return _get_tenant_dep


async def _resolve_db(request: Request):
    """FastAPI sub-dependency that delegates to the injected get_db."""
    gen = _db()()
    db = next(gen)
    try:
        yield db
    finally:
        try:
            next(gen)
        except StopIteration:
            pass


async def _resolve_tenant(request: Request):
    """FastAPI sub-dependency that delegates to the injected get_current_tenant_id."""
    return await _tenant()(request)


def _verify_session_ownership(
    session: AuditSession | None, tenant_id: int
) -> AuditSession:
    """Return session if it belongs to tenant, else 404."""
    if not session:
        raise HTTPException(status_code=404, detail="Audit session not found")
    if session.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Audit session not found")
    return session


# ---------------------------------------------------------------------------
# POST /agent/audits — start a paid audit
# ---------------------------------------------------------------------------

@router.post("/audits", response_model=AgentAuditResponse)
async def agent_start_audit(
    body: AgentAuditRequest,
    request: Request,
    db: Session = Depends(_resolve_db),
    tenant_id: int = Depends(_resolve_tenant),
    _: None = Depends(reject_preview_writes),
):
    """
    Start an agent-native deep audit.

    x402 payment is required (route key: ``POST /agent/audits``).
    No SaaS project or dashboard setup needed — submit a ``repo_url``
    and receive a ``session_id`` for polling.

    Idempotency-Key header is required.  If the same key is reused
    the original session_id is returned (no double-charge).
    """
    from server.x402_deps import PaymentGate, create_paid_job, mark_job_failed, require_payment

    # --- x402 payment gate ---
    gate_fn = require_payment("POST /agent/audits")
    gate: PaymentGate = await gate_fn(request=request, tenant_id=tenant_id, db=db)

    if gate.status == "already_processed":
        return AgentAuditResponse(
            session_id=gate.job_id or "",
            status="already_processed",
            status_url=f"/agent/audits/{gate.job_id}/status",
            results_url=f"/agent/audits/{gate.job_id}/findings",
            message="Already processed (idempotent replay)",
        )

    # --- import worker (late, avoids circular) ---
    try:
        from worker.tasks import execute_audit_task
    except ImportError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Worker module not available: {exc}. Is Celery configured?",
        )

    # --- create session ---
    session_id = f"agent_{uuid.uuid4().hex[:12]}_{int(datetime.now().timestamp())}"

    audit_session = AuditSession(
        session_id=session_id,
        tenant_id=tenant_id,
        project_id=None,
        status="queued",
        start_time=datetime.now(timezone.utc),
        models={"max_iterations": body.max_iterations},
        session_metadata={"source": "agent_api", "repo_url": body.repo_url},
    )
    db.add(audit_session)
    db.commit()

    # Also create a ScanExecution so the result appears in admin views
    scan_exec = ScanExecution(
        execution_id=session_id,
        project_id=None,
        tenant_id=tenant_id,
        repo_url=body.repo_url,
        repo_name=body.repo_url.rstrip("/").rsplit("/", 1)[-1],
        status="queued",
        started_at=datetime.now(timezone.utc),
        scan_config={"scan_type": "deep", "mode": body.mode, "source": "agent_api"},
    )
    db.add(scan_exec)
    db.commit()

    logger.info("Agent audit %s created for %s (tenant=%d)", session_id, body.repo_url, tenant_id)

    # --- link payment to job ---
    if gate.enabled and gate.payment_log_id:
        try:
            create_paid_job(db, gate.payment_log_id, session_id)
        except Exception:
            logger.exception("Failed to link payment to audit job %s", session_id)
            mark_job_failed(db, gate.payment_log_id)

    # --- dispatch worker task ---
    task = execute_audit_task.delay(
        repo_url=body.repo_url,
        scan_id=session_id,
        tenant_id=tenant_id,
        project_id=None,
        max_iterations=body.max_iterations,
        investigation_prompt=body.investigation_prompt,
        installation_id=body.installation_id,
        time_limit_minutes=body.time_limit_minutes,
        mode=body.mode,
        plan_n=body.plan_n,
    )
    logger.info("Worker task %s dispatched for agent audit %s", task.id, session_id)

    return AgentAuditResponse(
        session_id=session_id,
        status="queued",
        status_url=f"/agent/audits/{session_id}/status",
        results_url=f"/agent/audits/{session_id}/findings",
        message=f"Audit queued. Celery task: {task.id}",
    )


# ---------------------------------------------------------------------------
# GET /agent/audits/{session_id}/status
# ---------------------------------------------------------------------------

@router.get("/audits/{session_id}/status", response_model=AgentAuditStatusResponse)
async def agent_audit_status(
    session_id: str,
    db: Session = Depends(_resolve_db),
    tenant_id: int = Depends(_resolve_tenant),
):
    """Poll the status of an agent audit."""
    session = db.query(AuditSession).filter(
        AuditSession.session_id == session_id,
    ).first()
    session = _verify_session_ownership(session, tenant_id)

    findings_count = 0
    scan_exec = db.query(ScanExecution).filter_by(execution_id=session_id).first()
    if scan_exec and scan_exec.findings:
        findings_count = len(scan_exec.findings) if isinstance(scan_exec.findings, list) else 0

    # Also count hypotheses if a project was attached
    if session.project_id:
        findings_count = max(
            findings_count,
            db.query(Hypothesis).filter(Hypothesis.project_id == session.project_id).count(),
        )

    error_message = None
    if scan_exec and scan_exec.error_message:
        error_message = scan_exec.error_message

    return AgentAuditStatusResponse(
        session_id=session.session_id,
        status=session.status,
        progress=session.token_usage,
        findings_count=findings_count,
        error_message=error_message,
        started_at=session.start_time,
        completed_at=session.end_time,
    )


# ---------------------------------------------------------------------------
# GET /agent/audits/{session_id}/findings
# ---------------------------------------------------------------------------

@router.get("/audits/{session_id}/findings", response_model=AgentFindingsResponse)
async def agent_audit_findings(
    session_id: str,
    db: Session = Depends(_resolve_db),
    tenant_id: int = Depends(_resolve_tenant),
):
    """Fetch findings for an agent audit."""
    session = db.query(AuditSession).filter(
        AuditSession.session_id == session_id,
    ).first()
    session = _verify_session_ownership(session, tenant_id)

    items: list[AgentFindingItem] = []

    # Pull from Hypothesis table if project is attached
    if session.project_id:
        hypotheses = (
            db.query(Hypothesis)
            .filter(Hypothesis.project_id == session.project_id)
            .order_by(Hypothesis.confidence.desc())
            .all()
        )
        for h in hypotheses:
            items.append(AgentFindingItem(
                id=h.id,
                hypothesis_id=h.hypothesis_id,
                title=h.title,
                description=h.description,
                vulnerability_type=h.vulnerability_type,
                status=h.status,
                confidence=h.confidence,
                severity=h.severity,
                evidence=h.evidence,
                created_at=h.created_at,
            ))

    # Also check ScanExecution.findings (for agent audits that store inline)
    if not items:
        scan_exec = db.query(ScanExecution).filter_by(execution_id=session_id).first()
        if scan_exec and isinstance(scan_exec.findings, list):
            for idx, f in enumerate(scan_exec.findings):
                items.append(AgentFindingItem(
                    id=idx,
                    title=f.get("title", "Untitled"),
                    description=f.get("description"),
                    vulnerability_type=f.get("vulnerability_type"),
                    status=f.get("status", "proposed"),
                    confidence=f.get("confidence"),
                    severity=f.get("severity"),
                    evidence=f.get("evidence"),
                ))

    return AgentFindingsResponse(
        session_id=session_id,
        findings=items,
        total=len(items),
    )


# ---------------------------------------------------------------------------
# GET /agent/audits/{session_id}/report
# ---------------------------------------------------------------------------

@router.get("/audits/{session_id}/report", response_model=AgentReportResponse)
async def agent_audit_report(
    session_id: str,
    db: Session = Depends(_resolve_db),
    tenant_id: int = Depends(_resolve_tenant),
):
    """
    Fetch the formatted report for an agent audit.

    Returns the Markdown report content if available.
    """
    session = db.query(AuditSession).filter(
        AuditSession.session_id == session_id,
    ).first()
    session = _verify_session_ownership(session, tenant_id)

    if session.status not in ("completed", "in_review"):
        return AgentReportResponse(
            session_id=session_id,
            status=session.status,
            report_markdown=None,
            report_url=None,
        )

    # Try to read the report from ScanExecution.deep_audit_overview
    report_md: str | None = None
    scan_exec = db.query(ScanExecution).filter_by(execution_id=session_id).first()
    if scan_exec and scan_exec.deep_audit_overview:
        overview = scan_exec.deep_audit_overview
        if isinstance(overview, dict):
            report_md = overview.get("markdown") or overview.get("report")
        elif isinstance(overview, str):
            report_md = overview

    # Fallback: build minimal report from metadata
    if not report_md and session.session_metadata:
        meta = session.session_metadata
        if isinstance(meta, dict) and meta.get("report_markdown"):
            report_md = meta["report_markdown"]

    return AgentReportResponse(
        session_id=session_id,
        status=session.status,
        report_markdown=report_md,
        report_url=f"/reports/{session_id}" if report_md else None,
    )


# ---------------------------------------------------------------------------
# Response schemas – knowledge graphs
# ---------------------------------------------------------------------------

class AgentGraphSummary(BaseModel):
    """Summary of a knowledge graph (no full data)."""
    id: int
    name: str
    internal_name: str | None = None
    node_count: int = 0
    edge_count: int = 0
    node_types: list[str] = []
    edge_types: list[str] = []
    created_at: datetime | None = None
    updated_at: datetime | None = None


class AgentGraphListResponse(BaseModel):
    """Response from GET /agent/audits/{id}/graphs."""
    session_id: str
    graphs: list[AgentGraphSummary]
    total: int


class AgentGraphDetailResponse(BaseModel):
    """Response from GET /agent/audits/{id}/graphs/{graph_id}."""
    id: int
    session_id: str
    name: str
    internal_name: str | None = None
    data: dict[str, Any]
    created_at: datetime | None = None
    updated_at: datetime | None = None


# ---------------------------------------------------------------------------
# GET /agent/audits/{session_id}/graphs — list knowledge graphs
# ---------------------------------------------------------------------------

@router.get("/audits/{session_id}/graphs", response_model=AgentGraphListResponse)
async def agent_audit_graphs(
    session_id: str,
    db: Session = Depends(_resolve_db),
    tenant_id: int = Depends(_resolve_tenant),
):
    """
    List knowledge graphs built during an agent audit.

    Returns graph metadata (name, node/edge counts, types) without
    the full graph data.  Use the detail endpoint to fetch full data.
    """
    session = db.query(AuditSession).filter(
        AuditSession.session_id == session_id,
    ).first()
    session = _verify_session_ownership(session, tenant_id)

    # Graphs may be linked by session_id (agent audits) or project_id
    graphs: list[Graph] = []
    graphs = db.query(Graph).filter(Graph.session_id == session_id).all()
    if not graphs and session.project_id:
        graphs = db.query(Graph).filter(Graph.project_id == session.project_id).all()

    items = []
    for g in graphs:
        data = g.data or {}
        nodes = data.get("nodes", [])
        edges = data.get("edges", [])
        stats = data.get("stats", {})
        items.append(AgentGraphSummary(
            id=g.id,
            name=g.name,
            internal_name=g.internal_name,
            node_count=stats.get("num_nodes", len(nodes)),
            edge_count=stats.get("num_edges", len(edges)),
            node_types=stats.get("node_types", list({n.get("type", "") for n in nodes if isinstance(n, dict)})),
            edge_types=stats.get("edge_types", list({e.get("type", "") for e in edges if isinstance(e, dict)})),
            created_at=g.created_at,
            updated_at=g.updated_at,
        ))

    return AgentGraphListResponse(
        session_id=session_id,
        graphs=items,
        total=len(items),
    )


# ---------------------------------------------------------------------------
# GET /agent/audits/{session_id}/graphs/{graph_id} — full graph data
# ---------------------------------------------------------------------------

@router.get("/audits/{session_id}/graphs/{graph_id}", response_model=AgentGraphDetailResponse)
async def agent_audit_graph_detail(
    session_id: str,
    graph_id: int,
    db: Session = Depends(_resolve_db),
    tenant_id: int = Depends(_resolve_tenant),
):
    """
    Fetch full knowledge graph data (nodes, edges, metadata).

    The ``data`` field contains the complete graph structure with
    nodes, edges, stats, and metadata as produced by the GraphBuilder.
    """
    session = db.query(AuditSession).filter(
        AuditSession.session_id == session_id,
    ).first()
    session = _verify_session_ownership(session, tenant_id)

    graph = db.query(Graph).filter(Graph.id == graph_id).first()
    if not graph:
        raise HTTPException(status_code=404, detail="Graph not found")

    # Verify graph belongs to this audit
    owns = (graph.session_id == session_id)
    if not owns and session.project_id and graph.project_id == session.project_id:
        owns = True
    if not owns:
        raise HTTPException(status_code=404, detail="Graph not found")

    return AgentGraphDetailResponse(
        id=graph.id,
        session_id=session_id,
        name=graph.name,
        internal_name=graph.internal_name,
        data=graph.data or {},
        created_at=graph.created_at,
        updated_at=graph.updated_at,
    )


# ---------------------------------------------------------------------------
# Response schemas – surface scan
# ---------------------------------------------------------------------------

class AgentSurfaceScanRequest(BaseModel):
    """Request body for POST /agent/surface-scan."""
    repo_url: str = Field(..., description="GitHub repository URL to scan")
    llm_budget: int = Field(default=5, ge=0, le=20, description="Maximum LLM calls (0=pattern-only)")
    model: str | None = Field(default=None, description="Override LLM model")


class AgentSurfaceFinding(BaseModel):
    """A single surface-scan finding."""
    pattern_id: str
    title: str
    severity: str
    category: str
    confidence: float
    location: str
    code_snippet: str
    description: str
    llm_verified: bool = False
    llm_notes: str | None = None


class AgentSurfaceScanResponse(BaseModel):
    """Response from POST /agent/surface-scan."""
    execution_id: str
    repo_url: str | None = None
    repo_name: str
    risk_score: int
    risk_level: str
    findings: list[AgentSurfaceFinding]
    contracts_scanned: int
    llm_calls_used: int
    scan_duration_seconds: float
    summary: str
    error: str | None = None


# ---------------------------------------------------------------------------
# POST /agent/surface-scan — quick paid surface scan ($0.50)
# ---------------------------------------------------------------------------

@router.post("/surface-scan", response_model=AgentSurfaceScanResponse)
async def agent_surface_scan(
    body: AgentSurfaceScanRequest,
    request: Request,
    db: Session = Depends(_resolve_db),
    tenant_id: int = Depends(_resolve_tenant),
    _: None = Depends(reject_preview_writes),
):
    """
    Run a quick surface-level vulnerability scan ($0.50 via x402).

    Returns pattern-matched and optionally LLM-verified findings
    immediately (synchronous).  Much faster and cheaper than a
    full deep audit — ideal as a first pass.
    """
    from server.x402_deps import PaymentGate, create_paid_job, mark_job_failed, require_payment

    gate_fn = require_payment("POST /agent/surface-scan")
    gate: PaymentGate = await gate_fn(request=request, tenant_id=tenant_id, db=db)

    if gate.status == "already_processed":
        return AgentSurfaceScanResponse(
            execution_id=gate.job_id or "",
            repo_name="",
            risk_score=0,
            risk_level="unknown",
            findings=[],
            contracts_scanned=0,
            llm_calls_used=0,
            scan_duration_seconds=0,
            summary="Already processed (idempotent replay)",
        )

    from analysis.surface import SurfaceScanner
    from utils.config_loader import load_config

    config = load_config()
    scanner = SurfaceScanner(
        config=config,
        llm_budget=body.llm_budget,
        model=body.model,
        quiet=True,
    )

    result = scanner.scan(body.repo_url)
    execution_id = f"agent_surface_{uuid.uuid4().hex[:12]}_{int(datetime.now().timestamp())}"

    # Persist to ScanExecution
    try:
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
                "llm_budget": body.llm_budget,
                "model": body.model,
                "paid": True,
                "scan_type": "surface",
                "source": "agent_api",
            },
            llm_calls_made=result.llm_calls_used,
            contracts_scanned=result.contracts_scanned,
            contracts_total=result.contracts_total,
            error_message=result.error,
            scan_log=result.scan_log,
            started_at=result.scan_timestamp,
            completed_at=datetime.now(timezone.utc),
        )
        db.add(scan_exec)
        db.commit()

        if gate.enabled and gate.payment_log_id:
            try:
                create_paid_job(db, gate.payment_log_id, execution_id)
            except Exception:
                logger.exception("Failed to link payment to surface scan %s", execution_id)
                mark_job_failed(db, gate.payment_log_id)
    except Exception:
        logger.exception("Failed to save agent surface scan to database")
        if gate.enabled and gate.payment_log_id:
            mark_job_failed(db, gate.payment_log_id)

    return AgentSurfaceScanResponse(
        execution_id=execution_id,
        repo_url=result.repo_url,
        repo_name=result.repo_name,
        risk_score=result.risk_score,
        risk_level=result.risk_level,
        findings=[
            AgentSurfaceFinding(
                pattern_id=f.pattern_id,
                title=f.title,
                severity=f.severity,
                category=f.category,
                confidence=f.confidence,
                location=f.location,
                code_snippet=f.code_snippet,
                description=f.description,
                llm_verified=f.llm_verified,
                llm_notes=f.llm_notes,
            )
            for f in result.findings
        ],
        contracts_scanned=result.contracts_scanned,
        llm_calls_used=result.llm_calls_used,
        scan_duration_seconds=result.scan_duration_seconds,
        summary=result.summary,
        error=result.error,
    )
