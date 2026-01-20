"""
FastAPI server for Hound Dashboard API.

Provides REST and WebSocket endpoints to serve data to the React frontend.
This is the main entry point for the Hound SaaS architecture.

Architecture:
    Web Server (this file):
        - Handles HTTP requests and validates input
        - Creates database records for audits
        - Dispatches work to Celery worker queue
        - Handles GitHub webhook events
        
    Worker Queue (worker/tasks.py):
        - Executes long-running audits in background
        - Publishes progress to Redis Pub/Sub
        
    Redis:
        - Message broker for Celery tasks
        - Pub/Sub for real-time progress streaming

Endpoints:
    POST /audits/start - Start a new audit (async, returns immediately)
    POST /webhooks/github - Handle GitHub App events
    GET /ws/sessions/{id} - WebSocket for live progress
    GET /projects - List projects
    POST /projects - Create project
    GET /sessions/{id}/findings - Get audit findings
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import redis.asyncio as aioredis
from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from commands.project import ProjectManager
from database.models import (
    AuditSession,
    Base,
    Graph,
    Hypothesis,
    Project,
    ScanExecution,
    Tenant,
    create_db_engine,
    create_db_session,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database configuration
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///hound.db")

# Create engine lazily to avoid connection errors during import
_engine = None


def get_engine():
    """Get or create database engine."""
    global _engine
    if _engine is None:
        _engine = create_db_engine(DATABASE_URL)
        # Initialize database tables
        Base.metadata.create_all(_engine)
    return _engine


# Create FastAPI app
app = FastAPI(
    title="Hound Dashboard API",
    description="API for Hound security analysis dashboard",
    version="1.0.0",
    root_path=os.environ.get("ROOT_PATH", ""),  # For reverse proxy / port forwarding
)

# Configure CORS
# In production, configure with specific allowed origins via environment variable
allowed_origins = os.environ.get("HOUND_ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Middleware to fix URL generation for proxied requests (Codespaces, ngrok, etc.)
@app.middleware("http")
async def fix_forwarded_headers(request: Request, call_next):
    """
    Ensure X-Forwarded-Proto and X-Forwarded-Host are respected for URL generation.
    This fixes admin panel links when accessed via HTTPS proxy (Codespaces, ngrok, etc.).
    """
    # If we have forwarded proto, update the scope
    forwarded_proto = request.headers.get("x-forwarded-proto")
    if forwarded_proto:
        request.scope["scheme"] = forwarded_proto
    
    # If we have forwarded host, we need to update the headers
    # Starlette uses the Host header for URL generation
    forwarded_host = request.headers.get("x-forwarded-host")
    if forwarded_host:
        # Rebuild headers with the forwarded host as Host
        new_headers = []
        for name, value in request.scope["headers"]:
            if name.lower() == b"host":
                new_headers.append((b"host", forwarded_host.encode()))
            else:
                new_headers.append((name, value))
        request.scope["headers"] = new_headers
    
    response = await call_next(request)
    return response# Mount SQLAdmin dashboard at /admin
from server.admin import setup_admin

# Initialize admin panel (deferred until engine is ready)
_admin = None


def get_admin():
    """Get or create admin panel."""
    global _admin
    if _admin is None:
        engine = get_engine()
        _admin = setup_admin(app, engine)
    return _admin


# Initialize admin on startup
@app.on_event("startup")
async def startup_event():
    """Initialize admin panel on startup."""
    get_admin()


# Redirect for URL compatibility - auditsession -> audit-session
from starlette.responses import RedirectResponse as StarletteRedirect

@app.get("/admin/auditsession/{path:path}")
async def redirect_auditsession(path: str):
    """Redirect old auditsession URLs to audit-session."""
    return StarletteRedirect(f"/admin/audit-session/{path}", status_code=301)


# Dependency for database session
def get_db():
    """Get database session."""
    engine = get_engine()
    db = create_db_session(engine)
    try:
        yield db
    finally:
        db.close()


# Progress viewer page for admin panel
from fastapi.responses import HTMLResponse

# ============================================================================
# INTERACTIVE ADMIN DASHBOARD PAGES
# ============================================================================

@app.get("/admin/dashboard/{project_id}", response_class=HTMLResponse)
async def admin_project_dashboard(project_id: int, request: Request, db: Session = Depends(get_db)):
    """
    Interactive project dashboard with graph visualization, findings, and activity.
    Brings chatbot-style visualization features to the admin panel.
    """
    # Get project
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        return HTMLResponse(content="<h1>Project not found</h1>", status_code=404)
    
    # Get graphs
    graphs = db.query(Graph).filter(Graph.project_id == project_id).all()
    
    # Get findings
    findings = db.query(Hypothesis).filter(Hypothesis.project_id == project_id).order_by(Hypothesis.confidence.desc()).all()
    
    # Get sessions
    sessions = db.query(AuditSession).filter(AuditSession.project_id == project_id).order_by(AuditSession.start_time.desc()).limit(10).all()
    
    # Get active session if any
    active_session = None
    for s in sessions:
        if s.status in ('running', 'queued'):
            active_session = s
            break
    
    # Prepare graph data for D3 visualization
    graphs_json = {}
    for g in graphs:
        graphs_json[g.name] = g.data if g.data else {"nodes": [], "edges": []}
    
    # Prepare findings data
    findings_json = [
        {
            "id": f.hypothesis_id,
            "title": f.title,
            "description": f.description,
            "vulnerability_type": f.vulnerability_type,
            "status": f.status,
            "confidence": f.confidence,
            "severity": f.severity,
            "node_refs": f.node_refs or [],
            "evidence": f.evidence or {},
        }
        for f in findings
    ]
    
    # Prepare sessions data
    sessions_json = [
        {
            "id": s.session_id,
            "status": s.status,
            "started": s.start_time.isoformat() if s.start_time else None,
            "ended": s.end_time.isoformat() if s.end_time else None,
            "token_usage": s.token_usage,
            "models": s.models,
        }
        for s in sessions
    ]
    
    # Aggregate token usage across all sessions
    total_tokens = {"input": 0, "output": 0, "total": 0, "calls": 0}
    model_usage = {}
    for s in sessions:
        if s.token_usage:
            tu = s.token_usage.get("total_usage", {})
            total_tokens["input"] += tu.get("input_tokens", 0)
            total_tokens["output"] += tu.get("output_tokens", 0)
            total_tokens["total"] += tu.get("total_tokens", 0)
            total_tokens["calls"] += tu.get("call_count", 0)
            
            by_model = s.token_usage.get("by_model", {})
            for model_key, usage in by_model.items():
                if model_key not in model_usage:
                    model_usage[model_key] = {"input": 0, "output": 0, "total": 0, "calls": 0}
                model_usage[model_key]["input"] += usage.get("input_tokens", 0)
                model_usage[model_key]["output"] += usage.get("output_tokens", 0)
                model_usage[model_key]["total"] += usage.get("total_tokens", 0)
                model_usage[model_key]["calls"] += usage.get("call_count", 0)
    
    # Cost estimates per 1M tokens (approximate pricing)
    model_pricing = {
        "anthropic:claude-sonnet-4-20250514": {"input": 3.00, "output": 15.00},
        "anthropic:claude-3-5-sonnet": {"input": 3.00, "output": 15.00},
        "anthropic:claude-3-5-sonnet-20241022": {"input": 3.00, "output": 15.00},
        "anthropic:claude-3-opus": {"input": 15.00, "output": 75.00},
        "anthropic:claude-3-haiku": {"input": 0.25, "output": 1.25},
        "openai:gpt-4o": {"input": 2.50, "output": 10.00},
        "openai:gpt-4o-mini": {"input": 0.15, "output": 0.60},
        "openai:gpt-4-turbo": {"input": 10.00, "output": 30.00},
        "openai:o1": {"input": 15.00, "output": 60.00},
        "openai:o1-mini": {"input": 3.00, "output": 12.00},
        "deepseek:deepseek-chat": {"input": 0.14, "output": 0.28},
        "deepseek:deepseek-reasoner": {"input": 0.55, "output": 2.19},
        "gemini:gemini-2.0-flash": {"input": 0.10, "output": 0.40},
        "gemini:gemini-1.5-pro": {"input": 1.25, "output": 5.00},
        "xai:grok-2": {"input": 2.00, "output": 10.00},
    }
    
    # Calculate estimated costs
    estimated_cost = 0.0
    for model_key, usage in model_usage.items():
        pricing = model_pricing.get(model_key, {"input": 3.00, "output": 15.00})  # Default to Sonnet pricing
        input_cost = (usage["input"] / 1_000_000) * pricing["input"]
        output_cost = (usage["output"] / 1_000_000) * pricing["output"]
        estimated_cost += input_cost + output_cost
    
    usage_json = {
        "total": total_tokens,
        "by_model": model_usage,
        "estimated_cost": round(estimated_cost, 4),
        "pricing": model_pricing,
    }
    
    # Pre-generate model usage HTML to avoid nested f-string issues
    if model_usage:
        model_usage_html = ""
        for model, usage in model_usage.items():
            model_name = model.split(':')[-1] if ':' in model else model
            model_provider = model.split(':')[0] if ':' in model else 'unknown'
            model_usage_html += f'''
                <div class="model-item">
                    <div class="model-name">{model_name}</div>
                    <div class="model-provider">{model_provider}</div>
                    <div class="model-stats">
                        <span>{usage["total"]:,} tokens</span>
                        <span>{usage["calls"]} calls</span>
                    </div>
                </div>'''
    else:
        model_usage_html = '<div class="empty-state"><div class="icon">📈</div><div>No usage data yet.<br>Run an audit to track token usage.</div></div>'
    
    # Get base URL for WebSocket
    host = request.headers.get("x-forwarded-host", request.headers.get("host", "localhost:8000"))
    proto = request.headers.get("x-forwarded-proto", "http")
    ws_proto = "wss" if proto == "https" else "ws"
    
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Dashboard: {project.name}</title>
        <script src="https://d3js.org/d3.v7.min.js"></script>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');
            
            * {{ box-sizing: border-box; margin: 0; padding: 0; }}
            
            body {{
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
                background: linear-gradient(135deg, #0f1419 0%, #1a1f2e 100%);
                color: #e6edf3;
                min-height: 100vh;
            }}
            
            .header {{
                background: linear-gradient(135deg, #1c2128 0%, #2d333b 100%);
                padding: 16px 24px;
                border-bottom: 1px solid #30a14e33;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }}
            
            .header h1 {{
                font-size: 20px;
                font-weight: 600;
                color: #30a14e;
            }}
            
            .header .back-link {{
                color: #58a6ff;
                text-decoration: none;
                font-size: 14px;
            }}
            
            .header .back-link:hover {{ text-decoration: underline; }}
            
            .controls {{
                background: #161b22;
                padding: 12px 24px;
                border-bottom: 1px solid #30363d;
                display: flex;
                gap: 20px;
                align-items: center;
                flex-wrap: wrap;
            }}
            
            .control-group {{
                display: flex;
                flex-direction: column;
                gap: 4px;
            }}
            
            .control-group label {{
                font-size: 11px;
                color: #7d8590;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}
            
            select, button, input {{
                background: #21262d;
                color: #e6edf3;
                border: 1px solid #30363d;
                padding: 8px 12px;
                border-radius: 6px;
                font-family: inherit;
                font-size: 13px;
                cursor: pointer;
                transition: all 0.2s;
            }}
            
            select:hover, button:hover {{ background: #30363d; border-color: #30a14e; }}
            button.primary {{ background: #238636; border-color: #238636; }}
            button.primary:hover {{ background: #2ea043; }}
            button.danger {{ background: #da3633; border-color: #da3633; }}
            
            .main-container {{
                display: grid;
                grid-template-columns: 1fr 400px;
                height: calc(100vh - 120px);
            }}
            
            .graph-container {{
                background: #0d1117;
                position: relative;
                overflow: hidden;
            }}
            
            .graph-container svg {{
                width: 100%;
                height: 100%;
            }}
            
            .sidebar {{
                background: #161b22;
                border-left: 1px solid #30363d;
                overflow-y: auto;
                display: flex;
                flex-direction: column;
            }}
            
            .tabs {{
                display: flex;
                border-bottom: 1px solid #30363d;
                background: #1c2128;
            }}
            
            .tab {{
                flex: 1;
                padding: 12px;
                text-align: center;
                cursor: pointer;
                font-size: 13px;
                font-weight: 500;
                color: #7d8590;
                border-bottom: 2px solid transparent;
                transition: all 0.2s;
            }}
            
            .tab:hover {{ color: #e6edf3; background: #21262d; }}
            .tab.active {{ color: #30a14e; border-bottom-color: #30a14e; }}
            
            .tab-content {{
                flex: 1;
                overflow-y: auto;
                padding: 16px;
            }}
            
            .tab-pane {{ display: none; }}
            .tab-pane.active {{ display: block; }}
            
            .finding-item {{
                background: #21262d;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 12px;
                margin-bottom: 12px;
                cursor: pointer;
                transition: all 0.2s;
            }}
            
            .finding-item:hover {{
                border-color: #30a14e;
                transform: translateY(-1px);
            }}
            
            .finding-item.rejected {{
                opacity: 0.6;
            }}
            
            .finding-item.rejected .finding-title {{
                text-decoration: line-through;
            }}
            
            .finding-header {{
                display: flex;
                justify-content: space-between;
                align-items: flex-start;
                gap: 8px;
            }}
            
            .finding-title {{
                font-weight: 600;
                font-size: 14px;
                color: #e6edf3;
                flex: 1;
            }}
            
            .badge {{
                font-size: 11px;
                padding: 2px 8px;
                border-radius: 999px;
                font-weight: 500;
            }}
            
            .badge.critical {{ background: #da3633; color: #fff; }}
            .badge.high {{ background: #d29922; color: #fff; }}
            .badge.medium {{ background: #58a6ff; color: #fff; }}
            .badge.low {{ background: #3d444d; color: #aaa; }}
            .badge.confirmed {{ background: #238636; color: #fff; }}
            .badge.rejected {{ background: #6e7681; color: #fff; }}
            .badge.proposed {{ background: #1f6feb; color: #fff; }}
            
            .finding-meta {{
                font-size: 12px;
                color: #7d8590;
                margin-top: 6px;
            }}
            
            .confidence-bar {{
                height: 4px;
                background: #30363d;
                border-radius: 2px;
                margin-top: 8px;
                overflow: hidden;
            }}
            
            .confidence-bar .fill {{
                height: 100%;
                background: linear-gradient(90deg, #30a14e, #56d364);
                transition: width 0.3s;
            }}
            
            .actions {{
                display: flex;
                gap: 6px;
                margin-top: 10px;
            }}
            
            .actions button {{
                flex: 1;
                padding: 6px 10px;
                font-size: 12px;
            }}
            
            .actions .confirm {{ background: #238636; border-color: #238636; }}
            .actions .reject {{ background: #6e7681; border-color: #6e7681; }}
            
            .node-info {{
                background: #21262d;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 12px;
                margin-bottom: 12px;
            }}
            
            .node-info h4 {{
                font-size: 14px;
                color: #30a14e;
                margin-bottom: 8px;
            }}
            
            .node-info .detail {{
                font-size: 12px;
                color: #8b949e;
                margin-bottom: 4px;
            }}
            
            .node-info .detail strong {{
                color: #e6edf3;
            }}
            
            .node-info code {{
                background: #0d1117;
                padding: 8px;
                border-radius: 4px;
                display: block;
                margin-top: 8px;
                font-family: 'JetBrains Mono', monospace;
                font-size: 11px;
                white-space: pre-wrap;
                max-height: 200px;
                overflow-y: auto;
                color: #e6edf3;
            }}
            
            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 12px;
                margin-bottom: 16px;
            }}
            
            .stat-card {{
                background: #21262d;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 12px;
                text-align: center;
            }}
            
            .stat-value {{
                font-size: 24px;
                font-weight: 600;
                color: #30a14e;
            }}
            
            .stat-label {{
                font-size: 11px;
                color: #7d8590;
                text-transform: uppercase;
                margin-top: 4px;
            }}
            
            #legend {{
                position: absolute;
                top: 16px;
                right: 16px;
                background: rgba(22, 27, 34, 0.95);
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 12px;
                max-width: 200px;
                backdrop-filter: blur(10px);
            }}
            
            #legend h4 {{
                font-size: 11px;
                text-transform: uppercase;
                color: #7d8590;
                margin-bottom: 8px;
                border-bottom: 1px solid #30363d;
                padding-bottom: 6px;
            }}
            
            .legend-item {{
                display: flex;
                align-items: center;
                gap: 8px;
                font-size: 11px;
                color: #8b949e;
                margin: 4px 0;
            }}
            
            .legend-color {{
                width: 12px;
                height: 12px;
                border-radius: 50%;
            }}
            
            #tooltip {{
                position: absolute;
                background: rgba(22, 27, 34, 0.95);
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                font-size: 12px;
                pointer-events: none;
                opacity: 0;
                max-width: 300px;
                z-index: 100;
            }}
            
            .node circle {{
                stroke-width: 2px;
                cursor: pointer;
                transition: all 0.2s;
            }}
            
            .node:hover circle {{
                stroke-width: 3px;
                filter: drop-shadow(0 0 8px currentColor);
            }}
            
            .node text {{
                font-size: 10px;
                fill: #8b949e;
                pointer-events: none;
            }}
            
            .link {{
                stroke-opacity: 0.4;
                fill: none;
            }}
            
            .link:hover {{
                stroke-opacity: 0.8;
            }}
            
            .activity-item {{
                display: flex;
                gap: 10px;
                padding: 8px 0;
                border-bottom: 1px solid #21262d;
                font-size: 12px;
            }}
            
            .activity-time {{
                color: #7d8590;
                min-width: 70px;
            }}
            
            .activity-tag {{
                padding: 2px 8px;
                border-radius: 999px;
                font-size: 10px;
                font-weight: 500;
            }}
            
            .activity-tag.fetch {{ background: #238636; color: #fff; }}
            .activity-tag.memo {{ background: #d29922; color: #fff; }}
            .activity-tag.graph {{ background: #1f6feb; color: #fff; }}
            .activity-tag.hyp {{ background: #da3633; color: #fff; }}
            .activity-tag.think {{ background: #8957e5; color: #fff; }}
            
            .activity-msg {{
                color: #e6edf3;
                flex: 1;
                word-break: break-word;
            }}
            
            .empty-state {{
                text-align: center;
                padding: 40px;
                color: #7d8590;
            }}
            
            .empty-state .icon {{
                font-size: 48px;
            }}
            
            /* Activity Stream Styles */
            .now-investigating {{
                background: linear-gradient(90deg, #1f6feb22 0%, #8957e522 100%);
                border: 1px solid #1f6feb44;
                padding: 12px 16px;
                margin: 0;
                font-size: 13px;
                color: #58a6ff;
                animation: pulse 2s ease-in-out infinite;
            }}
            
            @keyframes pulse {{
                0%, 100% {{ opacity: 1; }}
                50% {{ opacity: 0.7; }}
            }}
            
            .now-investigating.idle {{
                animation: none;
                opacity: 0.6;
                color: #7d8590;
            }}
            
            .activity-controls {{
                display: flex;
                gap: 8px;
                padding: 8px 12px;
                background: #21262d;
                border-bottom: 1px solid #30363d;
            }}
            
            .activity-controls button {{
                padding: 4px 12px;
                font-size: 11px;
            }}
            
            .activity-stream {{
                flex: 1;
                overflow-y: auto;
                padding: 8px 12px;
                max-height: 400px;
            }}
            
            .activity-event {{
                display: flex;
                gap: 8px;
                padding: 6px 8px;
                margin-bottom: 4px;
                background: #21262d;
                border-radius: 6px;
                font-size: 12px;
                align-items: flex-start;
            }}
            
            .activity-event.decision {{ border-left: 3px solid #238636; }}
            .activity-event.result {{ border-left: 3px solid #58a6ff; }}
            .activity-event.thought {{ border-left: 3px solid #8957e5; }}
            .activity-event.error {{ border-left: 3px solid #da3633; }}
            .activity-event.status {{ border-left: 3px solid #d29922; }}
            
            .event-time {{
                color: #7d8590;
                font-size: 10px;
                min-width: 55px;
                font-family: 'JetBrains Mono', monospace;
            }}
            
            .event-iteration {{
                background: #30363d;
                color: #8b949e;
                padding: 1px 6px;
                border-radius: 10px;
                font-size: 10px;
                min-width: 30px;
                text-align: center;
            }}
            
            .event-tag {{
                padding: 2px 8px;
                border-radius: 4px;
                font-size: 10px;
                font-weight: 600;
                text-transform: uppercase;
                min-width: 70px;
                text-align: center;
            }}
            
            .event-tag.fetch {{ background: #23863633; color: #3fb950; }}
            .event-tag.memo {{ background: #d2992233; color: #d29922; }}
            .event-tag.graph {{ background: #1f6feb33; color: #58a6ff; }}
            .event-tag.hyp {{ background: #da363333; color: #f85149; }}
            .event-tag.think {{ background: #8957e533; color: #a371f7; }}
            .event-tag.status {{ background: #d2992233; color: #d29922; }}
            .event-tag.error {{ background: #da363333; color: #f85149; }}
            
            .event-content {{
                flex: 1;
                color: #c9d1d9;
                line-height: 1.4;
            }}
            
            .event-content .action {{ color: #58a6ff; font-weight: 500; }}
            .event-content .thought {{ color: #8b949e; font-style: italic; }}
            
            .ws-status {{
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 10px;
                display: flex;
                align-items: center;
                gap: 4px;
            }}
            
            .ws-status.connected {{ background: #23863633; color: #3fb950; }}
            .ws-status.disconnected {{ background: #da363333; color: #f85149; }}
            .ws-status .dot {{
                width: 6px;
                height: 6px;
                border-radius: 50%;
                background: currentColor;
            }}
            
            /* Usage Tab Styles */
            .usage-header {{
                padding: 12px 16px;
                border-bottom: 1px solid #30363d;
            }}
            
            .usage-header h3 {{
                margin: 0;
                font-size: 14px;
                color: #e6edf3;
            }}
            
            .usage-summary {{
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 12px;
                padding: 16px;
                background: #0d1117;
                border-bottom: 1px solid #30363d;
            }}
            
            .usage-stat {{
                text-align: center;
                padding: 12px;
                background: #161b22;
                border-radius: 8px;
                border: 1px solid #30363d;
            }}
            
            .usage-stat.highlight {{
                background: linear-gradient(135deg, #238636 0%, #1f6feb 100%);
                border: none;
            }}
            
            .usage-value {{
                font-size: 20px;
                font-weight: 600;
                color: #e6edf3;
                font-family: 'JetBrains Mono', monospace;
            }}
            
            .usage-label {{
                font-size: 11px;
                color: #7d8590;
                margin-top: 4px;
                text-transform: uppercase;
            }}
            
            .usage-stat.highlight .usage-label {{
                color: rgba(255,255,255,0.8);
            }}
            
            .usage-breakdown, .model-usage, .pricing-info {{
                padding: 16px;
                border-bottom: 1px solid #21262d;
            }}
            
            .usage-breakdown h4, .model-usage h4, .pricing-info h4 {{
                font-size: 12px;
                color: #7d8590;
                margin: 0 0 12px 0;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}
            
            .token-row {{
                display: flex;
                justify-content: space-between;
                padding: 8px 0;
                border-bottom: 1px solid #21262d;
            }}
            
            .token-row:last-child {{
                border-bottom: none;
            }}
            
            .token-label {{
                color: #7d8590;
            }}
            
            .token-value {{
                color: #e6edf3;
                font-family: 'JetBrains Mono', monospace;
            }}
            
            .model-item {{
                background: #21262d;
                border-radius: 6px;
                padding: 12px;
                margin-bottom: 8px;
            }}
            
            .model-name {{
                font-weight: 600;
                color: #e6edf3;
                font-size: 13px;
            }}
            
            .model-provider {{
                font-size: 11px;
                color: #7d8590;
                text-transform: uppercase;
                margin-top: 2px;
            }}
            
            .model-stats {{
                display: flex;
                gap: 16px;
                margin-top: 8px;
                font-size: 12px;
                color: #8b949e;
                font-family: 'JetBrains Mono', monospace;
            }}
            
            .pricing-table {{
                background: #21262d;
                border-radius: 6px;
                overflow: hidden;
            }}
            
            .pricing-row {{
                display: grid;
                grid-template-columns: 2fr 1fr 1fr;
                padding: 8px 12px;
                border-bottom: 1px solid #30363d;
                font-size: 12px;
            }}
            
            .pricing-row:last-child {{
                border-bottom: none;
            }}
            
            .pricing-row.header {{
                background: #161b22;
                font-weight: 600;
                color: #7d8590;
                text-transform: uppercase;
                font-size: 10px;
            }}
            
            .pricing-row span:not(:first-child) {{
                text-align: right;
                font-family: 'JetBrains Mono', monospace;
                color: #3fb950;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <div>
                <a href="/admin/project/list" class="back-link">&larr; Back to Projects</a>
                <h1>🔍 {project.name}</h1>
            </div>
            <div style="display: flex; gap: 10px;">
                <button onclick="buildGraphs()">Build Graphs</button>
                <button class="primary" onclick="runAudit()">Run Audit</button>
            </div>
        </div>
        
        <div class="controls">
            <div class="control-group">
                <label>Graph</label>
                <select id="graph-selector" onchange="loadGraph(this.value)">
                    {''.join(f'<option value="{g.name}">{g.name}</option>' for g in graphs) if graphs else '<option value="">No graphs</option>'}
                </select>
            </div>
            <div class="control-group">
                <label>Node Filter</label>
                <select id="type-filter" onchange="filterNodes(this.value)">
                    <option value="all">All Types</option>
                </select>
            </div>
            <div class="control-group">
                <label>Layout</label>
                <select id="layout-selector" onchange="changeLayout(this.value)">
                    <option value="force">Force Directed</option>
                    <option value="hierarchical">Hierarchical</option>
                    <option value="circular">Circular</option>
                </select>
            </div>
            <button onclick="resetView()">Reset View</button>
            <button onclick="exportGraph()">Export PNG</button>
        </div>
        
        <div class="main-container">
            <div class="graph-container" id="graph-container">
                <div id="legend"></div>
                <div id="tooltip"></div>
            </div>
            
            <div class="sidebar">
                <div class="tabs">
                    <div class="tab active" data-tab="findings">Findings ({len(findings)})</div>
                    <div class="tab" data-tab="nodes">Node Info</div>
                    <div class="tab" data-tab="activity">Activity</div>
                    <div class="tab" data-tab="usage">Usage</div>
                </div>
                
                <div class="tab-content">
                    <div class="tab-pane active" id="findings-pane">
                        <div class="stats-grid">
                            <div class="stat-card">
                                <div class="stat-value">{len([f for f in findings if f.status == 'confirmed'])}</div>
                                <div class="stat-label">Confirmed</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value">{len([f for f in findings if f.severity in ['critical', 'high']])}</div>
                                <div class="stat-label">High+ Severity</div>
                            </div>
                        </div>
                        
                        <div id="findings-list">
                            {''.join(f'''
                            <div class="finding-item {f.status}" data-id="{f.hypothesis_id}" onclick="selectFinding('{f.hypothesis_id}')">
                                <div class="finding-header">
                                    <div class="finding-title">{f.title[:60]}{'...' if len(f.title) > 60 else ''}</div>
                                    <span class="badge {f.severity}">{f.severity}</span>
                                </div>
                                <div class="finding-meta">{f.vulnerability_type} • <span class="badge {f.status}">{f.status}</span></div>
                                <div class="confidence-bar"><div class="fill" style="width:{int(f.confidence * 100)}%"></div></div>
                                <div class="actions">
                                    <button class="confirm" onclick="event.stopPropagation(); confirmFinding('{f.hypothesis_id}')">Confirm</button>
                                    <button class="reject" onclick="event.stopPropagation(); rejectFinding('{f.hypothesis_id}')">Reject</button>
                                </div>
                            </div>
                            ''' for f in findings) if findings else '<div class="empty-state"><div class="icon">🔍</div><div>No findings yet. Run an audit to discover vulnerabilities.</div></div>'}
                        </div>
                    </div>
                    
                    <div class="tab-pane" id="nodes-pane">
                        <div id="node-details">
                            <div class="empty-state">
                                <div class="icon">📍</div>
                                <div>Click a node in the graph to see details</div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="tab-pane" id="activity-pane">
                        <div class="now-investigating idle" id="now-investigating">
                            🔍 Waiting for audit to start...
                        </div>
                        <div class="activity-controls">
                            <span class="ws-status disconnected" id="ws-status">
                                <span class="dot"></span>
                                <span>Disconnected</span>
                            </span>
                            <button onclick="connectToSession()">Connect</button>
                            <button onclick="clearActivity()">Clear</button>
                            <select id="session-selector" onchange="onSessionChange()">
                                <option value="">Select session...</option>
                                {''.join(f'<option value="{s.session_id}" {"selected" if active_session and s.session_id == active_session.session_id else ""}>{s.session_id[:12]}... ({s.status})</option>' for s in sessions) if sessions else ''}
                            </select>
                        </div>
                        <div class="activity-stream" id="activity-stream">
                            <div class="empty-state" id="activity-empty">
                                <div class="icon">📊</div>
                                <div>Activity will appear here during audits.<br>Select a session and click Connect.</div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="tab-pane" id="usage-pane">
                        <div class="usage-header">
                            <h3>💰 Token Usage & Cost</h3>
                        </div>
                        <div class="usage-summary">
                            <div class="usage-stat">
                                <div class="usage-value" id="total-tokens">{total_tokens["total"]:,}</div>
                                <div class="usage-label">Total Tokens</div>
                            </div>
                            <div class="usage-stat">
                                <div class="usage-value" id="total-calls">{total_tokens["calls"]:,}</div>
                                <div class="usage-label">API Calls</div>
                            </div>
                            <div class="usage-stat highlight">
                                <div class="usage-value" id="estimated-cost">${estimated_cost:.4f}</div>
                                <div class="usage-label">Estimated Cost</div>
                            </div>
                        </div>
                        
                        <div class="usage-breakdown">
                            <h4>Token Breakdown</h4>
                            <div class="token-row">
                                <span class="token-label">Input Tokens:</span>
                                <span class="token-value">{total_tokens["input"]:,}</span>
                            </div>
                            <div class="token-row">
                                <span class="token-label">Output Tokens:</span>
                                <span class="token-value">{total_tokens["output"]:,}</span>
                            </div>
                        </div>
                        
                        <div class="model-usage">
                            <h4>By Model</h4>
                            <div id="model-usage-list">
                                {model_usage_html}
                            </div>
                        </div>
                        
                        <div class="pricing-info">
                            <h4>💡 Pricing Reference (per 1M tokens)</h4>
                            <div class="pricing-table">
                                <div class="pricing-row header">
                                    <span>Model</span>
                                    <span>Input</span>
                                    <span>Output</span>
                                </div>
                                <div class="pricing-row">
                                    <span>Claude Sonnet 4</span>
                                    <span>$3.00</span>
                                    <span>$15.00</span>
                                </div>
                                <div class="pricing-row">
                                    <span>GPT-4o</span>
                                    <span>$2.50</span>
                                    <span>$10.00</span>
                                </div>
                                <div class="pricing-row">
                                    <span>DeepSeek Chat</span>
                                    <span>$0.14</span>
                                    <span>$0.28</span>
                                </div>
                                <div class="pricing-row">
                                    <span>Gemini 2.0 Flash</span>
                                    <span>$0.10</span>
                                    <span>$0.40</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            // Data from server
            const projectId = {project_id};
            const projectName = "{project.name}";
            const allGraphs = {json.dumps(graphs_json)};
            const allSessions = {json.dumps(sessions_json)};
            const activeSessionId = "{active_session.session_id if active_session else ''}";
            const wsBase = "{ws_proto}://{host}";
            const allFindings = {json.dumps(findings_json)};
            const usageData = {json.dumps(usage_json)};
            
            // D3 visualization state
            let svg, simulation, g;
            let currentGraph = null;
            let currentNodes = [];
            let currentLinks = [];
            let selectedNode = null;
            
            // Color schemes
            const typeColors = {{
                'contract': '#30a14e',
                'interface': '#58a6ff',
                'library': '#a371f7',
                'function': '#56d364',
                'storage': '#f9826c',
                'event': '#79c0ff',
                'modifier': '#bc8cff',
                'external_actor': '#d29922',
                'role': '#ffa657',
                'code': '#30a14e',
                'concept': '#58a6ff',
                'invariant': '#f9826c',
                'observation': '#a371f7',
                'hypothesis': '#d29922',
                'issue': '#f85149',
                'pattern': '#56d364',
                'dataflow': '#79c0ff',
                'custom': '#8b949e'
            }};
            
            const edgeColors = {{
                'calls': '#30a14e',
                'contains': '#58a6ff',
                'depends_on': '#f9826c',
                'references': '#a371f7',
                'uses': '#79c0ff',
                'implements': '#56d364',
                'extends': '#bc8cff',
                'imports': '#d29922',
                'dataflow': '#ffa657',
                'reads': '#39d353',
                'writes': '#ff7b72',
                'custom': '#8b949e'
            }};
            
            function getNodeColor(type) {{
                return typeColors[type?.toLowerCase()] || typeColors.custom;
            }}
            
            function getEdgeColor(type) {{
                return edgeColors[type?.toLowerCase()] || edgeColors.custom;
            }}
            
            // Initialize
            function init() {{
                setupSvg();
                setupTabs();
                
                const graphNames = Object.keys(allGraphs);
                if (graphNames.length > 0) {{
                    loadGraph(graphNames[0]);
                }} else {{
                    showEmptyGraph();
                }}
            }}
            
            function setupSvg() {{
                const container = document.getElementById('graph-container');
                const width = container.clientWidth;
                const height = container.clientHeight;
                
                svg = d3.select('#graph-container')
                    .append('svg')
                    .attr('width', width)
                    .attr('height', height);
                
                // Add zoom behavior
                const zoom = d3.zoom()
                    .scaleExtent([0.1, 4])
                    .on('zoom', (event) => {{
                        g.attr('transform', event.transform);
                    }});
                
                svg.call(zoom);
                
                // Container for graph elements
                g = svg.append('g');
                
                // Arrow marker for edges
                svg.append('defs').append('marker')
                    .attr('id', 'arrowhead')
                    .attr('viewBox', '-0 -5 10 10')
                    .attr('refX', 20)
                    .attr('refY', 0)
                    .attr('orient', 'auto')
                    .attr('markerWidth', 6)
                    .attr('markerHeight', 6)
                    .append('path')
                    .attr('d', 'M 0,-5 L 10,0 L 0,5')
                    .attr('fill', '#8b949e');
            }}
            
            function setupTabs() {{
                document.querySelectorAll('.tab').forEach(tab => {{
                    tab.addEventListener('click', () => {{
                        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                        document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
                        tab.classList.add('active');
                        document.getElementById(tab.dataset.tab + '-pane').classList.add('active');
                    }});
                }});
            }}
            
            function loadGraph(graphName) {{
                currentGraph = allGraphs[graphName];
                if (!currentGraph) {{
                    showEmptyGraph();
                    return;
                }}
                
                const nodes = currentGraph.nodes || [];
                const edges = currentGraph.edges || [];
                
                // Create node/link data
                currentNodes = nodes.map((n, i) => ({{
                    ...n,
                    id: n.id || n.node_id || `node_${{i}}`,
                    label: n.label || n.name || n.id || `Node ${{i}}`,
                    type: n.type || n.node_type || 'custom',
                    x: Math.random() * 800,
                    y: Math.random() * 600
                }}));
                
                const nodeMap = new Map(currentNodes.map(n => [n.id, n]));
                
                // Map edges - handle both source/target and source_id/target_id field names
                currentLinks = edges.map((e, i) => {{
                    const sourceId = e.source_id || e.source;
                    const targetId = e.target_id || e.target;
                    const sourceNode = nodeMap.get(sourceId);
                    const targetNode = nodeMap.get(targetId);
                    
                    return {{
                        ...e,
                        id: e.id || `edge_${{i}}`,
                        source: sourceNode,
                        target: targetNode,
                        type: e.type || e.label || 'references'
                    }};
                }}).filter(e => e.source && e.target);
                
                console.log('Loaded graph:', currentGraph.name || 'unnamed');
                console.log('Nodes:', currentNodes.length, 'Links:', currentLinks.length);
                
                updateTypeFilter();
                updateLegend();
                renderGraph();
            }}
            
            function showEmptyGraph() {{
                g.selectAll('*').remove();
                g.append('text')
                    .attr('x', svg.attr('width') / 2)
                    .attr('y', svg.attr('height') / 2)
                    .attr('text-anchor', 'middle')
                    .attr('fill', '#7d8590')
                    .text('No graph data. Build graphs first.');
            }}
            
            function renderGraph() {{
                g.selectAll('*').remove();
                
                if (currentNodes.length === 0) {{
                    showEmptyGraph();
                    return;
                }}
                
                const width = parseInt(svg.attr('width'));
                const height = parseInt(svg.attr('height'));
                
                // Create simulation
                simulation = d3.forceSimulation(currentNodes)
                    .force('link', d3.forceLink(currentLinks).id(d => d.id).distance(80))
                    .force('charge', d3.forceManyBody().strength(-200))
                    .force('center', d3.forceCenter(width / 2, height / 2))
                    .force('collision', d3.forceCollide().radius(30));
                
                // Draw edges
                const link = g.append('g')
                    .selectAll('line')
                    .data(currentLinks)
                    .enter()
                    .append('line')
                    .attr('class', 'link')
                    .attr('stroke', d => getEdgeColor(d.type))
                    .attr('stroke-width', 1.5)
                    .attr('marker-end', 'url(#arrowhead)');
                
                // Draw nodes
                const node = g.append('g')
                    .selectAll('.node')
                    .data(currentNodes)
                    .enter()
                    .append('g')
                    .attr('class', 'node')
                    .call(d3.drag()
                        .on('start', dragstarted)
                        .on('drag', dragged)
                        .on('end', dragended));
                
                node.append('circle')
                    .attr('r', d => Math.min(8 + (d.importance || 0) * 2, 20))
                    .attr('fill', d => getNodeColor(d.type))
                    .attr('stroke', d => d3.color(getNodeColor(d.type)).darker(0.5))
                    .on('click', (event, d) => selectNode(d))
                    .on('mouseover', (event, d) => showTooltip(event, d))
                    .on('mouseout', hideTooltip);
                
                node.append('text')
                    .attr('dx', 12)
                    .attr('dy', 4)
                    .text(d => d.label?.substring(0, 20) || '');
                
                // Simulation tick
                simulation.on('tick', () => {{
                    link
                        .attr('x1', d => d.source.x)
                        .attr('y1', d => d.source.y)
                        .attr('x2', d => d.target.x)
                        .attr('y2', d => d.target.y);
                    
                    node.attr('transform', d => `translate(${{d.x}},${{d.y}})`);
                }});
            }}
            
            function dragstarted(event, d) {{
                if (!event.active) simulation.alphaTarget(0.3).restart();
                d.fx = d.x;
                d.fy = d.y;
            }}
            
            function dragged(event, d) {{
                d.fx = event.x;
                d.fy = event.y;
            }}
            
            function dragended(event, d) {{
                if (!event.active) simulation.alphaTarget(0);
                d.fx = null;
                d.fy = null;
            }}
            
            function selectNode(node) {{
                selectedNode = node;
                
                // Switch to nodes tab
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
                document.querySelector('[data-tab="nodes"]').classList.add('active');
                document.getElementById('nodes-pane').classList.add('active');
                
                // Display node details
                const details = document.getElementById('node-details');
                const content = node.content || node.description || node.summary || '';
                
                details.innerHTML = `
                    <div class="node-info">
                        <h4>${{node.label || node.id}}</h4>
                        <div class="detail"><strong>Type:</strong> ${{node.type || 'unknown'}}</div>
                        <div class="detail"><strong>ID:</strong> ${{node.id}}</div>
                        ${{node.file ? `<div class="detail"><strong>File:</strong> ${{node.file}}</div>` : ''}}
                        ${{node.line ? `<div class="detail"><strong>Line:</strong> ${{node.line}}</div>` : ''}}
                        ${{content ? `<code>${{escapeHtml(content.substring(0, 1000))}}</code>` : ''}}
                    </div>
                `;
                
                // Highlight related findings
                highlightRelatedFindings(node.id);
            }}
            
            function highlightRelatedFindings(nodeId) {{
                document.querySelectorAll('.finding-item').forEach(el => {{
                    el.style.borderColor = '#30363d';
                }});
                
                allFindings.forEach(f => {{
                    if (f.node_refs && f.node_refs.includes(nodeId)) {{
                        const el = document.querySelector(`[data-id="${{f.id}}"]`);
                        if (el) el.style.borderColor = '#30a14e';
                    }}
                }});
            }}
            
            function showTooltip(event, node) {{
                const tooltip = document.getElementById('tooltip');
                tooltip.innerHTML = `
                    <strong>${{node.label || node.id}}</strong><br>
                    <span style="color:#7d8590">Type:</span> ${{node.type || 'unknown'}}<br>
                    ${{node.file ? `<span style="color:#7d8590">File:</span> ${{node.file}}` : ''}}
                `;
                tooltip.style.left = (event.pageX + 10) + 'px';
                tooltip.style.top = (event.pageY - 10) + 'px';
                tooltip.style.opacity = 1;
            }}
            
            function hideTooltip() {{
                document.getElementById('tooltip').style.opacity = 0;
            }}
            
            function updateTypeFilter() {{
                const types = new Set(currentNodes.map(n => n.type).filter(Boolean));
                const select = document.getElementById('type-filter');
                select.innerHTML = '<option value="all">All Types</option>' +
                    Array.from(types).sort().map(t => `<option value="${{t}}">${{t}}</option>`).join('');
            }}
            
            function updateLegend() {{
                const types = new Set(currentNodes.map(n => n.type).filter(Boolean));
                const legend = document.getElementById('legend');
                
                legend.innerHTML = `
                    <h4>Node Types</h4>
                    ${{Array.from(types).slice(0, 8).map(t => `
                        <div class="legend-item">
                            <div class="legend-color" style="background:${{getNodeColor(t)}}"></div>
                            ${{t}}
                        </div>
                    `).join('')}}
                `;
            }}
            
            function filterNodes(type) {{
                if (type === 'all') {{
                    g.selectAll('.node').style('opacity', 1);
                }} else {{
                    g.selectAll('.node').style('opacity', d => d.type === type ? 1 : 0.2);
                }}
            }}
            
            function changeLayout(layout) {{
                if (!simulation || !currentNodes.length) return;
                
                const width = parseInt(svg.attr('width'));
                const height = parseInt(svg.attr('height'));
                
                if (layout === 'circular') {{
                    const angle = (2 * Math.PI) / currentNodes.length;
                    const radius = Math.min(width, height) / 3;
                    
                    currentNodes.forEach((n, i) => {{
                        n.fx = width/2 + radius * Math.cos(i * angle);
                        n.fy = height/2 + radius * Math.sin(i * angle);
                    }});
                    simulation.alpha(0.3).restart();
                    setTimeout(() => {{
                        currentNodes.forEach(n => {{ n.fx = null; n.fy = null; }});
                    }}, 1000);
                }} else if (layout === 'hierarchical') {{
                    // Simple hierarchical - group by type
                    const types = [...new Set(currentNodes.map(n => n.type))];
                    const typeIndex = new Map(types.map((t, i) => [t, i]));
                    
                    currentNodes.forEach(n => {{
                        n.fx = 100 + (typeIndex.get(n.type) || 0) * 150;
                        n.fy = 100 + Math.random() * (height - 200);
                    }});
                    simulation.alpha(0.3).restart();
                    setTimeout(() => {{
                        currentNodes.forEach(n => {{ n.fx = null; n.fy = null; }});
                    }}, 1000);
                }} else {{
                    // Force directed - release all fixed positions
                    currentNodes.forEach(n => {{ n.fx = null; n.fy = null; }});
                    simulation.alpha(1).restart();
                }}
            }}
            
            function resetView() {{
                svg.transition().duration(500).call(
                    d3.zoom().transform,
                    d3.zoomIdentity
                );
            }}
            
            function exportGraph() {{
                const svgEl = document.querySelector('#graph-container svg');
                const serializer = new XMLSerializer();
                const svgStr = serializer.serializeToString(svgEl);
                const canvas = document.createElement('canvas');
                canvas.width = svgEl.clientWidth * 2;
                canvas.height = svgEl.clientHeight * 2;
                const ctx = canvas.getContext('2d');
                const img = new Image();
                img.onload = function() {{
                    ctx.fillStyle = '#0d1117';
                    ctx.fillRect(0, 0, canvas.width, canvas.height);
                    ctx.drawImage(img, 0, 0);
                    const link = document.createElement('a');
                    link.download = projectName + '_graph.png';
                    link.href = canvas.toDataURL('image/png');
                    link.click();
                }};
                img.src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svgStr)));
            }}
            
            function selectFinding(id) {{
                const finding = allFindings.find(f => f.id === id);
                if (!finding) return;
                
                // Highlight nodes referenced by this finding
                if (finding.node_refs && finding.node_refs.length > 0) {{
                    g.selectAll('.node circle').style('stroke-width', d => 
                        finding.node_refs.includes(d.id) ? 4 : 2
                    ).style('filter', d =>
                        finding.node_refs.includes(d.id) ? 'drop-shadow(0 0 10px #30a14e)' : 'none'
                    );
                }}
            }}
            
            async function confirmFinding(id) {{
                await fetch(`/api/findings/${{id}}/status`, {{
                    method: 'PUT',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ status: 'confirmed' }})
                }});
                location.reload();
            }}
            
            async function rejectFinding(id) {{
                await fetch(`/api/findings/${{id}}/status`, {{
                    method: 'PUT',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ status: 'rejected' }})
                }});
                location.reload();
            }}
            
            async function buildGraphs() {{
                const resp = await fetch('/graphs/build', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{
                        repo_url: "{project.git_url or ''}",
                        project_id: projectId,
                        num_graphs: 3,
                        init_only: false
                    }})
                }});
                const data = await resp.json();
                if (data.scan_id) {{
                    // Stay on dashboard and connect to activity stream
                    document.getElementById('session-selector').innerHTML += 
                        `<option value="${{data.scan_id}}" selected>${{data.scan_id.slice(0,12)}}... (building)</option>`;
                    connectToSession(data.scan_id);
                    showTab('activity');
                }}
            }}
            
            async function runAudit() {{
                const resp = await fetch('/audits/start', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{
                        repo_url: "{project.git_url or ''}",
                        project_id: projectId,
                        max_iterations: 50
                    }})
                }});
                const data = await resp.json();
                if (data.session_id) {{
                    // Stay on dashboard and connect to activity stream
                    document.getElementById('session-selector').innerHTML += 
                        `<option value="${{data.session_id}}" selected>${{data.session_id.slice(0,12)}}... (running)</option>`;
                    connectToSession(data.session_id);
                    showTab('activity');
                }}
            }}
            
            function escapeHtml(text) {{
                const div = document.createElement('div');
                div.textContent = text;
                return div.innerHTML;
            }}
            
            // ===================================
            // WebSocket Activity Streaming
            // ===================================
            
            let ws = null;
            let currentSessionId = null;
            let lastIteration = 0;
            const seenEvents = new Set();
            
            function showTab(tabName) {{
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
                document.querySelector(`[data-tab="${{tabName}}"]`).classList.add('active');
                document.getElementById(tabName + '-pane').classList.add('active');
            }}
            
            function friendlyTag(action) {{
                const a = (action || '').toLowerCase();
                if (a === 'load_nodes' || a === 'load_node' || a === 'fetch_code') return {{ label: 'Fetch', cls: 'fetch' }};
                if (a === 'update_node') return {{ label: 'Memo', cls: 'memo' }};
                if (a === 'add_edge' || a === 'add_node') return {{ label: 'Graph', cls: 'graph' }};
                if (a === 'query_graph' || a === 'focus' || a === 'summarize') return {{ label: 'Graph', cls: 'graph' }};
                if (a === 'propose_hypothesis') return {{ label: 'Finding', cls: 'hyp' }};
                if (a === 'update_hypothesis') return {{ label: 'Update', cls: 'hyp' }};
                if (a === 'deep_think' || a === 'strategist') return {{ label: 'Think', cls: 'think' }};
                if (a === 'status' || a === 'thought') return {{ label: 'Status', cls: 'status' }};
                if (a === 'error') return {{ label: 'Error', cls: 'error' }};
                return {{ label: action || 'Act', cls: 'status' }};
            }}
            
            function dedupeKey(j) {{
                return `${{j.type||''}}|${{j.action||''}}|${{j.iteration||''}}|${{(j.message||'').slice(0,80)}}`;
            }}
            
            function handleActivityMessage(data) {{
                try {{
                    const j = JSON.parse(data);
                    
                    // Skip keepalive and connection messages
                    if (j.type === 'keepalive' || j.type === 'connected' || j.type === 'pong') return;
                    
                    // Dedupe
                    const key = dedupeKey(j);
                    if (seenEvents.has(key)) return;
                    seenEvents.add(key);
                    if (seenEvents.size > 500) {{
                        const first = seenEvents.values().next().value;
                        seenEvents.delete(first);
                    }}
                    
                    // Extract info
                    const ts = j.timestamp || j.ts ? new Date(j.timestamp || j.ts * 1000) : new Date();
                    const tstr = ts.toTimeString().split(' ')[0].slice(0, 5);
                    const iteration = j.iteration || lastIteration;
                    if (j.iteration) lastIteration = j.iteration;
                    
                    const action = j.action || j.type || '';
                    const tag = friendlyTag(action);
                    
                    // Build message
                    let text = '';
                    if (j.type === 'decision') {{
                        text = `<span class="action">${{tag.label}}: ${{j.action || 'thinking'}}</span>`;
                        if (j.reasoning) text += `<br><span class="thought">${{escapeHtml(j.reasoning.slice(0, 200))}}</span>`;
                    }} else if (j.type === 'thought') {{
                        text = `<span class="thought">${{escapeHtml(j.message || j.reasoning || '')}}</span>`;
                        updateNowInvestigating(j.message || j.reasoning || '');
                    }} else if (j.type === 'action_start') {{
                        text = `<span class="action">Starting: ${{j.action || 'action'}}</span>`;
                    }} else if (j.type === 'action_result' || j.type === 'result') {{
                        text = `<span class="action">Result:</span> ${{escapeHtml((j.message || j.result || '').slice(0, 300))}}`;
                    }} else if (j.type === 'status') {{
                        text = `<span class="action">Status: ${{j.status || j.message || ''}}</span>`;
                        if (j.status === 'completed' || j.status === 'failed') {{
                            updateNowInvestigating(j.status === 'completed' ? '✅ Audit completed' : '❌ Audit failed', true);
                        }}
                    }} else if (j.type === 'error') {{
                        text = `<span class="action">Error:</span> ${{escapeHtml(j.message || j.error || '')}}`;
                    }} else {{
                        text = escapeHtml(j.message || j.reasoning || JSON.stringify(j).slice(0, 200));
                    }}
                    
                    appendActivityEvent(tstr, iteration, tag, text, j.type);
                    
                }} catch (e) {{
                    // Plain text message
                    appendActivityEvent('', '', {{ label: 'Info', cls: 'status' }}, escapeHtml(data), 'info');
                }}
            }}
            
            function appendActivityEvent(time, iteration, tag, text, eventType) {{
                const stream = document.getElementById('activity-stream');
                const empty = document.getElementById('activity-empty');
                if (empty) empty.style.display = 'none';
                
                const div = document.createElement('div');
                div.className = `activity-event ${{eventType || ''}}`;
                div.innerHTML = `
                    <span class="event-time">${{time}}</span>
                    <span class="event-iteration">#${{iteration || '-'}}</span>
                    <span class="event-tag ${{tag.cls}}">${{tag.label}}</span>
                    <span class="event-content">${{text}}</span>
                `;
                
                stream.appendChild(div);
                stream.scrollTop = stream.scrollHeight;
            }}
            
            function updateNowInvestigating(text, idle = false) {{
                const el = document.getElementById('now-investigating');
                if (el) {{
                    el.textContent = idle ? text : `🔍 ${{text.slice(0, 100)}}`;
                    el.className = idle ? 'now-investigating idle' : 'now-investigating';
                }}
            }}
            
            function setWsStatus(connected) {{
                const el = document.getElementById('ws-status');
                if (el) {{
                    el.className = `ws-status ${{connected ? 'connected' : 'disconnected'}}`;
                    el.innerHTML = `<span class="dot"></span><span>${{connected ? 'Connected' : 'Disconnected'}}</span>`;
                }}
            }}
            
            function connectToSession(sessionId) {{
                if (!sessionId) {{
                    sessionId = document.getElementById('session-selector').value;
                }}
                if (!sessionId) {{
                    alert('Please select a session to connect to');
                    return;
                }}
                
                // Close existing connection
                if (ws) {{
                    ws.close();
                    ws = null;
                }}
                
                currentSessionId = sessionId;
                seenEvents.clear();
                lastIteration = 0;
                
                // Connect WebSocket
                const wsUrl = `${{wsBase}}/ws/sessions/${{sessionId}}`;
                console.log('Connecting to:', wsUrl);
                
                ws = new WebSocket(wsUrl);
                
                ws.onopen = () => {{
                    console.log('WebSocket connected');
                    setWsStatus(true);
                    updateNowInvestigating('Connected to audit stream...', false);
                }};
                
                ws.onmessage = (event) => {{
                    handleActivityMessage(event.data);
                }};
                
                ws.onerror = (error) => {{
                    console.error('WebSocket error:', error);
                    appendActivityEvent('', '', {{ label: 'Error', cls: 'error' }}, 'Connection error', 'error');
                }};
                
                ws.onclose = () => {{
                    console.log('WebSocket closed');
                    setWsStatus(false);
                    appendActivityEvent('', '', {{ label: 'Info', cls: 'status' }}, 'Connection closed', 'status');
                }};
                
                // Ping to keep alive
                setInterval(() => {{
                    if (ws && ws.readyState === WebSocket.OPEN) {{
                        ws.send('ping');
                    }}
                }}, 25000);
            }}
            
            function onSessionChange() {{
                const sessionId = document.getElementById('session-selector').value;
                if (sessionId) {{
                    connectToSession(sessionId);
                }}
            }}
            
            function clearActivity() {{
                const stream = document.getElementById('activity-stream');
                stream.innerHTML = `
                    <div class="empty-state" id="activity-empty">
                        <div class="icon">📊</div>
                        <div>Activity cleared. Connect to a session to see live updates.</div>
                    </div>
                `;
                seenEvents.clear();
                lastIteration = 0;
            }}
            
            // Auto-connect if there's an active session
            function autoConnect() {{
                if (activeSessionId) {{
                    setTimeout(() => {{
                        connectToSession(activeSessionId);
                        showTab('activity');
                    }}, 500);
                }}
            }}
            
            // Initialize on load
            document.addEventListener('DOMContentLoaded', () => {{
                init();
                autoConnect();
            }});
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html)


@app.get("/admin/progress/{session_id}", response_class=HTMLResponse)
async def admin_progress_viewer(session_id: str, request: Request, db: Session = Depends(get_db)):
    """
    Render a live progress viewer for audit/graph build sessions.
    Connects to WebSocket and shows real-time updates.
    """
    # Get session info
    session = db.query(AuditSession).filter(AuditSession.session_id == session_id).first()
    session_info = {
        "id": session_id,
        "status": session.status if session else "unknown",
        "project": session.project.name if session and session.project else "N/A",
        "started": session.start_time.isoformat() if session and session.start_time else "N/A",
    }
    
    # Get the base URL for WebSocket
    host = request.headers.get("x-forwarded-host", request.headers.get("host", "localhost:8000"))
    proto = request.headers.get("x-forwarded-proto", "http")
    ws_proto = "wss" if proto == "https" else "ws"
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Progress: {session_id}</title>
        <link rel="stylesheet" href="/admin/statics/css/tabler.min.css">
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 20px; background: #1a1a2e; color: #eee; }}
            .container {{ max-width: 1200px; margin: 0 auto; }}
            .header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }}
            .back-btn {{ color: #5c7cfa; text-decoration: none; }}
            .status {{ padding: 4px 12px; border-radius: 4px; font-weight: 500; }}
            .status.running {{ background: #3b82f6; }}
            .status.completed {{ background: #22c55e; }}
            .status.failed {{ background: #ef4444; }}
            .status.queued {{ background: #6b7280; }}
            .card {{ background: #16213e; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
            .card h3 {{ margin-top: 0; color: #5c7cfa; }}
            .log-container {{ background: #0f0f23; border-radius: 4px; padding: 15px; max-height: 500px; overflow-y: auto; font-family: monospace; font-size: 13px; }}
            .log-entry {{ padding: 4px 0; border-bottom: 1px solid #1a1a2e; }}
            .log-entry.decision {{ color: #fbbf24; }}
            .log-entry.thought {{ color: #a78bfa; }}
            .log-entry.action {{ color: #34d399; }}
            .log-entry.error {{ color: #f87171; }}
            .log-entry.status {{ color: #60a5fa; font-weight: bold; }}
            .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 20px; }}
            .stat {{ background: #16213e; padding: 15px; border-radius: 8px; text-align: center; }}
            .stat-value {{ font-size: 24px; font-weight: bold; color: #5c7cfa; }}
            .stat-label {{ font-size: 12px; color: #9ca3af; margin-top: 5px; }}
            .connection {{ position: fixed; top: 10px; right: 10px; padding: 5px 10px; border-radius: 4px; font-size: 12px; }}
            .connection.connected {{ background: #22c55e; }}
            .connection.disconnected {{ background: #ef4444; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div>
                    <a href="/admin/audit-session/list" class="back-btn">&larr; Back to Sessions</a>
                    <h1>Session Progress</h1>
                </div>
                <div>
                    <span class="status {session_info['status']}" id="status">{session_info['status'].upper()}</span>
                </div>
            </div>
            
            <div class="stats">
                <div class="stat">
                    <div class="stat-value" id="iteration">0</div>
                    <div class="stat-label">Iteration</div>
                </div>
                <div class="stat">
                    <div class="stat-value" id="nodes">0</div>
                    <div class="stat-label">Nodes Loaded</div>
                </div>
                <div class="stat">
                    <div class="stat-value" id="hypotheses">0</div>
                    <div class="stat-label">Hypotheses</div>
                </div>
                <div class="stat">
                    <div class="stat-value" id="graphs">0</div>
                    <div class="stat-label">Graphs</div>
                </div>
            </div>
            
            <div class="card">
                <h3>Session Info</h3>
                <p><strong>Session ID:</strong> {session_id}</p>
                <p><strong>Project:</strong> {session_info['project']}</p>
                <p><strong>Started:</strong> {session_info['started']}</p>
            </div>
            
            <div class="card">
                <h3>Live Log</h3>
                <div class="log-container" id="log"></div>
            </div>
        </div>
        
        <div class="connection disconnected" id="connection">Disconnected</div>
        
        <script>
            const sessionId = "{session_id}";
            const wsUrl = "{ws_proto}://{host}/ws/sessions/" + sessionId;
            let ws;
            let reconnectAttempts = 0;
            
            function connect() {{
                ws = new WebSocket(wsUrl);
                
                ws.onopen = function() {{
                    document.getElementById('connection').className = 'connection connected';
                    document.getElementById('connection').textContent = 'Connected';
                    reconnectAttempts = 0;
                    addLog('Connected to session', 'status');
                }};
                
                ws.onmessage = function(event) {{
                    const data = JSON.parse(event.data);
                    handleMessage(data);
                }};
                
                ws.onclose = function() {{
                    document.getElementById('connection').className = 'connection disconnected';
                    document.getElementById('connection').textContent = 'Disconnected';
                    
                    // Reconnect with backoff
                    if (reconnectAttempts < 5) {{
                        reconnectAttempts++;
                        setTimeout(connect, 1000 * reconnectAttempts);
                    }}
                }};
                
                ws.onerror = function(error) {{
                    addLog('WebSocket error: ' + error.message, 'error');
                }};
            }}
            
            function handleMessage(data) {{
                const type = data.type || 'unknown';
                
                if (type === 'status') {{
                    document.getElementById('status').textContent = (data.status || 'unknown').toUpperCase();
                    document.getElementById('status').className = 'status ' + (data.status || '');
                    addLog('Status: ' + data.message, 'status');
                }}
                else if (type === 'progress') {{
                    if (data.data) {{
                        document.getElementById('iteration').textContent = data.data.iteration || 0;
                        document.getElementById('nodes').textContent = data.data.nodes_visited || 0;
                        document.getElementById('hypotheses').textContent = data.data.hypotheses_count || 0;
                        document.getElementById('graphs').textContent = data.data.graphs_loaded || 0;
                    }}
                }}
                else if (type === 'decision') {{
                    addLog('Decision: ' + data.action + ' - ' + (data.reasoning || '').substring(0, 100), 'decision');
                }}
                else if (type === 'thought') {{
                    addLog(data.thought || data.message || JSON.stringify(data), 'thought');
                }}
                else if (type === 'action_start') {{
                    addLog('Executing: ' + data.action, 'action');
                }}
                else if (type === 'action_result') {{
                    addLog('Result: ' + (data.result?.summary || data.result?.status || 'done'), 'action');
                }}
                else if (type === 'error') {{
                    addLog('Error: ' + data.message, 'error');
                }}
                else {{
                    addLog(JSON.stringify(data), 'thought');
                }}
            }}
            
            function addLog(message, type) {{
                const log = document.getElementById('log');
                const entry = document.createElement('div');
                entry.className = 'log-entry ' + type;
                entry.textContent = new Date().toLocaleTimeString() + ' | ' + message;
                log.appendChild(entry);
                log.scrollTop = log.scrollHeight;
            }}
            
            // Start connection
            connect();
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html)


# Pydantic models for request/response
class ProjectCreate(BaseModel):
    """Request model for creating a project."""

    name: str = Field(..., description="Project name")
    git_url: Optional[str] = Field(None, description="Git repository URL")
    source_path: Optional[str] = Field(None, description="Local source path")
    description: Optional[str] = Field(None, description="Project description")


class ProjectResponse(BaseModel):
    """Response model for project data."""

    id: int
    name: str
    source_path: Optional[str]
    git_url: Optional[str]
    description: Optional[str]
    status: str
    created_at: datetime
    last_accessed: datetime
    graphs_count: int = 0
    sessions_count: int = 0
    hypotheses_count: int = 0
    confirmed_count: int = 0

    class Config:
        from_attributes = True


class SessionResponse(BaseModel):
    """Response model for session data."""

    id: int
    session_id: str
    status: str
    start_time: datetime
    end_time: Optional[datetime]
    models: Optional[Dict[str, Any]]
    token_usage: Optional[Dict[str, Any]]
    coverage: Optional[Dict[str, Any]]
    investigations_count: int = 0

    class Config:
        from_attributes = True


class GraphResponse(BaseModel):
    """Response model for graph data."""

    id: int
    name: str
    internal_name: Optional[str]
    data: Dict[str, Any]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class FindingResponse(BaseModel):
    """Response model for hypothesis/finding data."""

    id: int
    hypothesis_id: str
    title: str
    description: str
    vulnerability_type: str
    status: str
    confidence: float
    severity: str
    node_refs: Optional[List[str]]
    evidence: Optional[Dict[str, Any]]
    reported_by_model: Optional[str]
    junior_model: Optional[str]
    senior_model: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ============================================================================
# Audit Control Request/Response Models
# ============================================================================

class AuditStartRequest(BaseModel):
    """Request model for starting a new audit."""
    
    repo_url: str = Field(..., description="Git repository URL or local path")
    tenant_id: int = Field(default=1, description="Tenant ID for multi-tenancy")
    project_id: Optional[int] = Field(None, description="Link to existing project")
    max_iterations: int = Field(default=50, description="Maximum agent iterations")
    investigation_prompt: Optional[str] = Field(None, description="Custom investigation prompt")
    installation_id: Optional[int] = Field(None, description="GitHub App installation ID")
    pr_number: Optional[int] = Field(None, description="PR number to post findings to")
    repo_full_name: Optional[str] = Field(None, description="Repository full name (owner/repo)")


class AuditStartResponse(BaseModel):
    """Response model after starting an audit."""
    
    session_id: str = Field(..., description="Unique session ID for tracking")
    status: str = Field(default="queued", description="Current status")
    message: str = Field(..., description="Human-readable status message")
    websocket_url: str = Field(..., description="WebSocket URL for live progress")


class AuditStatusResponse(BaseModel):
    """Response model for audit status check."""
    
    session_id: str
    status: str
    progress: Optional[Dict[str, Any]] = None
    findings_count: int = 0
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


# ============================================================================
# Audit Control Endpoints - THE CRITICAL WIRING
# ============================================================================

@app.post("/audits/start", response_model=AuditStartResponse)
async def start_audit(request: AuditStartRequest, db: Session = Depends(get_db)):
    """
    Start a new security audit (async, returns immediately).
    
    This endpoint:
    1. Creates an AuditSession record with status "queued"
    2. Dispatches work to the Celery worker queue
    3. Returns immediately with a session_id for tracking
    
    The actual audit runs in a background Celery worker. Connect to the
    WebSocket endpoint to receive real-time progress updates.
    
    Example:
        POST /audits/start
        {
            "repo_url": "https://github.com/owner/repo",
            "installation_id": 12345,  // For private repos
            "pr_number": 42,           // To post findings as PR comments
            "repo_full_name": "owner/repo"
        }
    """
    # Import worker tasks (done here to avoid circular imports)
    try:
        from worker.tasks import execute_audit_task
    except ImportError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Worker module not available: {e}. Is Celery configured?"
        )
    
    # Generate unique session ID
    session_id = f"audit_{uuid.uuid4().hex[:12]}_{int(datetime.now().timestamp())}"
    
    # Get or create tenant
    tenant = db.query(Tenant).filter(Tenant.id == request.tenant_id).first()
    if not tenant:
        tenant = db.query(Tenant).first()
        if not tenant:
            tenant = Tenant(name="default")
            db.add(tenant)
            db.commit()
    
    # Create AuditSession record with status "queued"
    # Note: tenant_id is tracked via the project relationship, not directly on session
    audit_session = AuditSession(
        session_id=session_id,
        project_id=request.project_id,  # Can be None for ad-hoc scans
        status="queued",
        start_time=datetime.now(timezone.utc),
        models={"max_iterations": request.max_iterations},
    )
    db.add(audit_session)
    db.commit()
    
    logger.info(f"Created audit session {session_id} for {request.repo_url}")
    
    # Dispatch to Celery worker queue (async - returns immediately!)
    task = execute_audit_task.delay(
        repo_url=request.repo_url,
        scan_id=session_id,
        tenant_id=tenant.id,
        project_id=request.project_id,
        max_iterations=request.max_iterations,
        investigation_prompt=request.investigation_prompt,
        installation_id=request.installation_id,
        pr_number=request.pr_number,
        repo_full_name=request.repo_full_name,
    )
    
    logger.info(f"Dispatched audit task {task.id} for session {session_id}")
    
    return AuditStartResponse(
        session_id=session_id,
        status="queued",
        message=f"Audit queued successfully. Task ID: {task.id}",
        websocket_url=f"/ws/sessions/{session_id}",
    )


@app.get("/audits/{session_id}/status", response_model=AuditStatusResponse)
async def get_audit_status(session_id: str, db: Session = Depends(get_db)):
    """
    Get the current status of an audit.
    
    Returns the current status, progress information, and findings count.
    """
    session = db.query(AuditSession).filter(AuditSession.session_id == session_id).first()
    
    if not session:
        raise HTTPException(status_code=404, detail="Audit session not found")
    
    # Count findings
    findings_count = 0
    if session.project_id:
        findings_count = (
            db.query(Hypothesis)
            .filter(Hypothesis.project_id == session.project_id)
            .count()
        )
    
    return AuditStatusResponse(
        session_id=session.session_id,
        status=session.status,
        progress=session.token_usage,  # Contains progress info
        findings_count=findings_count,
        started_at=session.start_time,
        completed_at=session.end_time,
    )


# ============================================================================
# Graph Building Endpoint - BUILD GRAPHS BEFORE AUDIT
# ============================================================================

class GraphBuildRequest(BaseModel):
    """Request model for building graphs."""
    repo_url: str = Field(..., description="Git repository URL or local path")
    tenant_id: Optional[int] = Field(None, description="Tenant ID")
    project_id: Optional[int] = Field(None, description="Project ID to link graphs to")
    max_iterations: int = Field(3, description="Max graph refinement iterations")
    num_graphs: int = Field(2, description="Number of graphs to build")
    init_only: bool = Field(False, description="Only build SystemArchitecture graph")
    installation_id: Optional[int] = Field(None, description="GitHub App installation ID")


class GraphBuildResponse(BaseModel):
    """Response model for graph build."""
    scan_id: str
    status: str
    message: str
    websocket_url: str


@app.post("/graphs/build", response_model=GraphBuildResponse)
async def build_graphs(request: GraphBuildRequest, db: Session = Depends(get_db)):
    """
    Build knowledge graphs for a repository (async, returns immediately).
    
    This is a prerequisite step before running a full audit. It:
    1. Clones/accesses the repository
    2. Creates a manifest of all source files
    3. Bundles code for analysis
    4. Uses LLM to build knowledge graphs
    
    Connect to the WebSocket endpoint to receive real-time progress updates.
    
    Example:
        POST /graphs/build
        {
            "repo_url": "https://github.com/owner/repo",
            "project_id": 1,
            "init_only": true  // For quick initial graph
        }
    """
    try:
        from worker.tasks import build_graphs_task
    except ImportError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Worker module not available: {e}. Is Celery configured?"
        )
    
    # Generate unique scan ID
    scan_id = f"graphs_{uuid.uuid4().hex[:12]}_{int(datetime.now().timestamp())}"
    
    # Get or create tenant
    tenant = db.query(Tenant).filter(Tenant.id == request.tenant_id).first()
    if not tenant:
        tenant = db.query(Tenant).first()
        if not tenant:
            tenant = Tenant(name="default")
            db.add(tenant)
            db.commit()
    
    logger.info(f"Starting graph build {scan_id} for {request.repo_url}")
    
    # Dispatch to Celery worker queue
    task = build_graphs_task.delay(
        repo_url=request.repo_url,
        scan_id=scan_id,
        tenant_id=tenant.id,
        project_id=request.project_id,
        max_iterations=request.max_iterations,
        num_graphs=request.num_graphs,
        init_only=request.init_only,
        installation_id=request.installation_id,
    )
    
    logger.info(f"Dispatched graph build task {task.id} for scan {scan_id}")
    
    return GraphBuildResponse(
        scan_id=scan_id,
        status="queued",
        message=f"Graph build queued successfully. Task ID: {task.id}",
        websocket_url=f"/ws/sessions/{scan_id}",
    )


@app.get("/projects/{project_id}/graphs")
async def get_project_graphs(project_id: int, db: Session = Depends(get_db)):
    """
    Get all graphs for a project.
    
    Returns a list of graphs with their metadata (excludes full graph data).
    """
    graphs = db.query(Graph).filter(Graph.project_id == project_id).all()
    
    return [
        {
            "id": g.id,
            "name": g.name,
            "internal_name": g.internal_name,
            "created_at": g.created_at.isoformat(),
            "updated_at": g.updated_at.isoformat(),
            "node_count": len(g.data.get("nodes", [])) if g.data else 0,
            "edge_count": len(g.data.get("edges", [])) if g.data else 0,
        }
        for g in graphs
    ]


@app.get("/graphs/{graph_id}")
async def get_graph(graph_id: int, db: Session = Depends(get_db)):
    """
    Get a specific graph with full data.
    """
    graph = db.query(Graph).filter(Graph.id == graph_id).first()
    
    if not graph:
        raise HTTPException(status_code=404, detail="Graph not found")
    
    return {
        "id": graph.id,
        "project_id": graph.project_id,
        "name": graph.name,
        "internal_name": graph.internal_name,
        "data": graph.data,
        "created_at": graph.created_at.isoformat(),
        "updated_at": graph.updated_at.isoformat(),
    }


# ============================================================================
# GitHub Webhook Endpoint - HANDLES INCOMING GITHUB EVENTS
# ============================================================================

# GitHub webhook secret (must match the secret configured in GitHub App)
GITHUB_WEBHOOK_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", "")


def verify_github_signature(payload: bytes, signature: str) -> bool:
    """Verify GitHub webhook signature using HMAC-SHA256."""
    if not GITHUB_WEBHOOK_SECRET:
        logger.warning("GITHUB_WEBHOOK_SECRET not set - skipping signature verification")
        return True  # Skip verification if no secret configured (dev mode)
    
    if not signature or not signature.startswith("sha256="):
        return False
    
    expected_sig = hmac.new(
        GITHUB_WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256,
    ).hexdigest()
    
    return hmac.compare_digest(f"sha256={expected_sig}", signature)


@app.post("/webhooks/github")
async def handle_github_webhook(request: Request, db: Session = Depends(get_db)):
    """
    Handle GitHub App webhook events.
    
    This endpoint receives events from GitHub when:
    - App is installed on a repository
    - A pull request is opened or updated
    - A push is made to a monitored branch
    
    For pull_request events, it automatically triggers a security audit
    and posts findings as PR comments.
    
    Security:
        Verifies the X-Hub-Signature-256 header using GITHUB_WEBHOOK_SECRET.
    """
    # Get raw body for signature verification
    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")
    
    if not verify_github_signature(body, signature):
        logger.warning("Invalid GitHub webhook signature")
        raise HTTPException(status_code=401, detail="Invalid signature")
    
    # Parse payload
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")
    
    event_type = request.headers.get("X-GitHub-Event", "")
    logger.info(f"Received GitHub webhook: {event_type}")
    
    # Handle installation events
    if event_type == "installation":
        action = payload.get("action")
        installation = payload.get("installation", {})
        logger.info(f"Installation event: {action} for {installation.get('id')}")
        
        return {"status": "ok", "event": "installation", "action": action}
    
    # Handle pull request events - THIS TRIGGERS AUDITS
    if event_type == "pull_request":
        action = payload.get("action")
        
        # Only audit on PR open or synchronize (new commits pushed)
        if action not in ("opened", "synchronize", "reopened"):
            return {"status": "ok", "event": "pull_request", "action": action, "skipped": True}
        
        pr = payload.get("pull_request", {})
        repo = payload.get("repository", {})
        installation = payload.get("installation", {})
        
        pr_number = pr.get("number")
        repo_full_name = repo.get("full_name")
        clone_url = repo.get("clone_url")
        installation_id = installation.get("id")
        
        if not all([pr_number, repo_full_name, clone_url, installation_id]):
            logger.warning("Missing required fields in PR webhook payload")
            return {"status": "error", "message": "Missing required fields"}
        
        logger.info(f"Triggering audit for PR #{pr_number} on {repo_full_name}")
        
        # Import and dispatch task
        try:
            from worker.tasks import execute_audit_task
        except ImportError as e:
            logger.error(f"Worker module not available: {e}")
            return {"status": "error", "message": "Worker not available"}
        
        # Generate session ID
        session_id = f"pr_{repo_full_name.replace('/', '_')}_{pr_number}_{uuid.uuid4().hex[:8]}"
        
        # Get or create tenant
        tenant = db.query(Tenant).first()
        if not tenant:
            tenant = Tenant(name="default")
            db.add(tenant)
            db.commit()
            db.refresh(tenant)
        
        # Create audit session (project_id is null for webhook-triggered scans)
        audit_session = AuditSession(
            session_id=session_id,
            project_id=None,  # Will be linked to project if one exists/is created
            status="queued",
            start_time=datetime.now(timezone.utc),
            models={"trigger": "github_webhook", "pr_number": pr_number},
        )
        db.add(audit_session)
        db.commit()
        
        # Dispatch to worker
        task = execute_audit_task.delay(
            repo_url=clone_url,
            scan_id=session_id,
            tenant_id=tenant.id,
            installation_id=installation_id,
            pr_number=pr_number,
            repo_full_name=repo_full_name,
        )
        
        logger.info(f"Dispatched PR audit task {task.id} for session {session_id}")
        
        return {
            "status": "ok",
            "event": "pull_request",
            "action": action,
            "session_id": session_id,
            "task_id": task.id,
        }
    
    # Handle push events (optional: audit on push to main branch)
    if event_type == "push":
        ref = payload.get("ref", "")
        repo = payload.get("repository", {})
        
        # Only trigger on main/master branch pushes
        default_branch = repo.get("default_branch", "main")
        if ref not in (f"refs/heads/{default_branch}", f"refs/heads/main", f"refs/heads/master"):
            return {"status": "ok", "event": "push", "skipped": True, "reason": "Not default branch"}
        
        # TODO: Optionally trigger audit on main branch pushes
        logger.info(f"Push to {ref} on {repo.get('full_name')} - audit not triggered (configure as needed)")
        
        return {"status": "ok", "event": "push", "branch": ref}
    
    # Unknown event type
    return {"status": "ok", "event": event_type, "handled": False}


# ============================================================================
# Original API Endpoints
# ============================================================================

@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": "Hound Dashboard API",
        "version": "1.0.0",
        "endpoints": {
            "projects": "/projects",
            "create_project": "POST /projects",
            "sessions": "/projects/{id}/sessions",
            "graph": "/sessions/{id}/graph",
            "findings": "/sessions/{id}/findings",
            "websocket": "/ws/sessions/{id}",
            "start_audit": "POST /audits/start",
            "audit_status": "GET /audits/{session_id}/status",
            "github_webhook": "POST /webhooks/github",
        },
    }


@app.get("/projects", response_model=List[ProjectResponse])
async def list_projects(db: Session = Depends(get_db)):
    """
    List all projects from the database.

    Returns project metadata with statistics including:
    - Number of graphs
    - Number of sessions
    - Number of hypotheses
    - Number of confirmed hypotheses
    """
    projects = db.query(Project).all()

    response = []
    for project in projects:
        # Count related items
        graphs_count = db.query(Graph).filter(Graph.project_id == project.id).count()
        sessions_count = db.query(AuditSession).filter(AuditSession.project_id == project.id).count()
        hypotheses_count = db.query(Hypothesis).filter(Hypothesis.project_id == project.id).count()
        confirmed_count = (
            db.query(Hypothesis)
            .filter(Hypothesis.project_id == project.id, Hypothesis.status == "confirmed")
            .count()
        )

        response.append(
            ProjectResponse(
                id=project.id,
                name=project.name,
                source_path=project.source_path,
                git_url=project.git_url,
                description=project.description,
                status=project.status,
                created_at=project.created_at,
                last_accessed=project.last_accessed,
                graphs_count=graphs_count,
                sessions_count=sessions_count,
                hypotheses_count=hypotheses_count,
                confirmed_count=confirmed_count,
            )
        )

    return response


@app.post("/projects", response_model=ProjectResponse)
async def create_project(project_data: ProjectCreate, db: Session = Depends(get_db)):
    """
    Create a new project for manual git URLs or source paths.

    Accepts either git_url or source_path. Creates the project using
    the ProjectManager and stores it in the database.
    
    Note: If git_url is provided without source_path, the repository
    should be cloned first. This is currently a placeholder for future
    git clone functionality.
    """
    # Validate that at least one source is provided
    if not project_data.git_url and not project_data.source_path:
        raise HTTPException(
            status_code=400, detail="Either git_url or source_path must be provided"
        )

    # Use ProjectManager to create the project
    manager = ProjectManager()

    try:
        # For now, require source_path for actual project creation
        # TODO: Add git clone functionality for git_url
        source = project_data.source_path
        if not source:
            # Placeholder: git_url should trigger clone to temp directory
            raise HTTPException(
                status_code=400, 
                detail="source_path is required. Git URL cloning not yet implemented."
            )

        # Create project using ProjectManager
        project_config = manager.create_project(
            name=project_data.name,
            source_path=source,
            description=project_data.description,
        )

        # Also create database entry
        # First, get or create default tenant
        tenant = db.query(Tenant).first()
        if not tenant:
            tenant = Tenant(name="default")
            db.add(tenant)
            db.commit()
            db.refresh(tenant)

        # Create database project entry with error handling for datetime parsing
        try:
            created_at = datetime.fromisoformat(project_config["created_at"])
            last_accessed = datetime.fromisoformat(project_config["last_accessed"])
        except (ValueError, KeyError) as e:
            logger.warning(f"Failed to parse datetime from project config: {e}")
            # Fallback to current time
            created_at = datetime.now(timezone.utc)
            last_accessed = datetime.now(timezone.utc)
        
        db_project = Project(
            tenant_id=tenant.id,
            name=project_data.name,
            source_path=project_data.source_path,
            git_url=project_data.git_url,
            description=project_data.description or project_config.get("description"),
            status="active",
            created_at=created_at,
            last_accessed=last_accessed,
        )
        db.add(db_project)
        db.commit()
        db.refresh(db_project)

        return ProjectResponse(
            id=db_project.id,
            name=db_project.name,
            source_path=db_project.source_path,
            git_url=db_project.git_url,
            description=db_project.description,
            status=db_project.status,
            created_at=db_project.created_at,
            last_accessed=db_project.last_accessed,
            graphs_count=0,
            sessions_count=0,
            hypotheses_count=0,
            confirmed_count=0,
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create project: {str(e)}")


@app.get("/projects/{project_id}/sessions", response_model=List[SessionResponse])
async def list_project_sessions(project_id: int, db: Session = Depends(get_db)):
    """
    List all audit sessions for a project.

    Returns session metadata including:
    - Session ID and status
    - Start and end times
    - Models used
    - Token usage statistics
    - Coverage information
    - Number of investigations
    """
    # Verify project exists
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Query sessions for the project
    sessions = (
        db.query(AuditSession)
        .filter(AuditSession.project_id == project_id)
        .order_by(AuditSession.start_time.desc())
        .all()
    )

    response = []
    for session in sessions:
        investigations_count = len(session.investigations or [])

        response.append(
            SessionResponse(
                id=session.id,
                session_id=session.session_id,
                status=session.status,
                start_time=session.start_time,
                end_time=session.end_time,
                models=session.models,
                token_usage=session.token_usage,
                coverage=session.coverage,
                investigations_count=investigations_count,
            )
        )

    return response


@app.get("/sessions/{session_id}/graph")
async def get_session_graph(session_id: str, db: Session = Depends(get_db)):
    """
    Return the system_graph JSON for visualization.

    This endpoint retrieves the graph data associated with a session.
    If the session has a project, it returns the SystemArchitecture graph
    for that project.
    """
    # First, try to get the session from the database
    session = db.query(AuditSession).filter(AuditSession.session_id == session_id).first()

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    # Get the project's graphs
    project = db.query(Project).filter(Project.id == session.project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found for session")

    # Try to get SystemArchitecture graph from database
    system_graph = (
        db.query(Graph)
        .filter(
            Graph.project_id == project.id,
            Graph.internal_name == "SystemArchitecture",
        )
        .first()
    )

    if system_graph:
        return system_graph.data

    # Fallback: Try to load from filesystem
    manager = ProjectManager()
    project_path = manager.get_project_path(project.name)

    if not project_path:
        raise HTTPException(status_code=404, detail="Project path not found")

    graphs_dir = project_path / "graphs"
    system_graph_file = graphs_dir / "graph_SystemArchitecture.json"

    if system_graph_file.exists():
        try:
            with open(system_graph_file, "r") as f:
                graph_data = json.load(f)
            return graph_data
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to load graph: {str(e)}")

    raise HTTPException(status_code=404, detail="System graph not found")


@app.get("/sessions/{session_id}/findings", response_model=List[FindingResponse])
async def get_session_findings(session_id: str, db: Session = Depends(get_db)):
    """
    Return the list of confirmed hypotheses (findings).

    This endpoint retrieves all confirmed hypotheses/findings for a project
    associated with the given session.
    """
    # Get the session
    session = db.query(AuditSession).filter(AuditSession.session_id == session_id).first()

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    # Get confirmed hypotheses for the project
    hypotheses = (
        db.query(Hypothesis)
        .filter(
            Hypothesis.project_id == session.project_id,
            Hypothesis.status == "confirmed",
        )
        .order_by(Hypothesis.confidence.desc())
        .all()
    )

    response = []
    for hypothesis in hypotheses:
        response.append(
            FindingResponse(
                id=hypothesis.id,
                hypothesis_id=hypothesis.hypothesis_id,
                title=hypothesis.title,
                description=hypothesis.description,
                vulnerability_type=hypothesis.vulnerability_type,
                status=hypothesis.status,
                confidence=hypothesis.confidence,
                severity=hypothesis.severity,
                node_refs=hypothesis.node_refs,
                evidence=hypothesis.evidence,
                reported_by_model=hypothesis.reported_by_model,
                junior_model=hypothesis.junior_model,
                senior_model=hypothesis.senior_model,
                created_at=hypothesis.created_at,
                updated_at=hypothesis.updated_at,
            )
        )

    return response


class FindingStatusUpdate(BaseModel):
    """Request model for updating finding status."""

    status: str = Field(..., description="New status (proposed, investigating, confirmed, rejected, resolved)")


@app.post("/findings/{finding_id}/status")
async def update_finding_status(
    finding_id: int, status_update: FindingStatusUpdate, db: Session = Depends(get_db)
):
    """
    Update the status of a finding (hypothesis) by database ID.

    This endpoint allows users to confirm or reject findings from the UI.
    Valid statuses are: proposed, investigating, confirmed, rejected, resolved.
    """
    # Validate status
    valid_statuses = ["proposed", "investigating", "confirmed", "rejected", "resolved"]
    if status_update.status not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}",
        )

    # Get the finding
    finding = db.query(Hypothesis).filter(Hypothesis.id == finding_id).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Update status
    finding.status = status_update.status
    finding.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(finding)

    return {
        "id": finding.id,
        "hypothesis_id": finding.hypothesis_id,
        "status": finding.status,
        "updated_at": finding.updated_at.isoformat(),
    }


@app.put("/api/findings/{finding_id}/status")
async def update_finding_status_by_hyp_id(
    finding_id: str, status_update: FindingStatusUpdate, db: Session = Depends(get_db)
):
    """
    Update the status of a finding (hypothesis) by hypothesis_id string.

    This endpoint is used by the admin dashboard.
    Valid statuses are: proposed, investigating, confirmed, rejected, resolved.
    """
    # Validate status
    valid_statuses = ["proposed", "investigating", "confirmed", "rejected", "resolved"]
    if status_update.status not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}",
        )

    # Try to find by hypothesis_id string first, then by integer ID
    finding = db.query(Hypothesis).filter(Hypothesis.hypothesis_id == finding_id).first()
    
    if not finding:
        # Try as integer ID
        try:
            int_id = int(finding_id)
            finding = db.query(Hypothesis).filter(Hypothesis.id == int_id).first()
        except ValueError:
            pass

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Update status and confidence based on status
    finding.status = status_update.status
    if status_update.status == "confirmed":
        finding.confidence = 1.0
    elif status_update.status == "rejected":
        finding.confidence = 0.0
    finding.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(finding)

    return {
        "id": finding.id,
        "hypothesis_id": finding.hypothesis_id,
        "status": finding.status,
        "confidence": finding.confidence,
        "updated_at": finding.updated_at.isoformat(),
    }


# WebSocket endpoint for live audit logs
class ConnectionManager:
    """Manage WebSocket connections for live audit log streaming."""

    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, session_id: str):
        """Accept a new WebSocket connection for a session."""
        await websocket.accept()
        if session_id not in self.active_connections:
            self.active_connections[session_id] = []
        self.active_connections[session_id].append(websocket)

    def disconnect(self, websocket: WebSocket, session_id: str):
        """Remove a WebSocket connection."""
        if session_id in self.active_connections:
            self.active_connections[session_id].remove(websocket)
            if not self.active_connections[session_id]:
                del self.active_connections[session_id]

    async def send_message(self, message: str, session_id: str):
        """Send a message to all connections for a session."""
        if session_id in self.active_connections:
            for connection in self.active_connections[session_id]:
                await connection.send_text(message)

    async def broadcast(self, message: dict, session_id: str):
        """Broadcast a JSON message to all connections for a session."""
        if session_id in self.active_connections:
            message_text = json.dumps(message)
            for connection in self.active_connections[session_id]:
                try:
                    await connection.send_text(message_text)
                except Exception:
                    pass  # Connection closed, will be cleaned up


manager_ws = ConnectionManager()

# Redis configuration
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


async def redis_subscriber(websocket: WebSocket, session_id: str):
    """
    Subscribe to Redis Pub/Sub channel and forward messages to WebSocket.
    
    This runs as a background task that listens to the Redis channel
    for this session and forwards all messages to the WebSocket client.
    """
    try:
        redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
        pubsub = redis_client.pubsub()
        
        # Subscribe to the session channel (matches worker/redis_publisher.py)
        # Publisher uses both updates and status channels
        channel_updates = f"audit:updates:{session_id}"
        channel_status = f"audit:status:{session_id}"
        
        await pubsub.subscribe(channel_updates, channel_status)
        
        logger.info(f"Subscribed to Redis channels: {channel_updates}, {channel_status}")
        
        async for message in pubsub.listen():
            if message["type"] == "message":
                try:
                    data = json.loads(message["data"])
                    await websocket.send_json(data)
                except json.JSONDecodeError:
                    # Forward raw message if not JSON
                    await websocket.send_text(message["data"])
                except Exception as e:
                    logger.error(f"Error sending to WebSocket: {e}")
                    break
                    
    except Exception as e:
        logger.error(f"Redis subscriber error for {session_id}: {e}")
    finally:
        try:
            await pubsub.unsubscribe(channel_updates, channel_status)
            await redis_client.close()
        except Exception:
            pass


@app.websocket("/ws/sessions/{session_id}")
async def websocket_endpoint(websocket: WebSocket, session_id: str):
    """
    WebSocket endpoint for streaming live audit progress.
    
    This endpoint:
    1. Accepts a WebSocket connection
    2. Subscribes to the Redis Pub/Sub channel for this session
    3. Forwards all messages from the worker to the client in real-time
    
    The worker (worker/tasks.py) publishes progress updates to Redis
    using the RedisPublisher class. This endpoint acts as a bridge
    between Redis and the browser.
    
    Message types (from RedisPublisher):
        - status: Overall audit status (queued, running, completed, failed)
        - thought: Agent's current thinking/analysis
        - decision: Agent's action decision
        - action_start: Action execution started
        - action_result: Action execution completed
        - error: Error occurred
        
    Example client usage:
        const ws = new WebSocket('ws://localhost:8000/ws/sessions/abc123');
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            console.log(data.type, data.message);
        };
    """
    await manager_ws.connect(websocket, session_id)
    redis_task = None

    try:
        # Send initial connection confirmation
        await websocket.send_json({
            "type": "connected",
            "session_id": session_id,
            "message": "WebSocket connection established. Subscribing to audit updates...",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        # Start Redis subscriber as a background task
        redis_task = asyncio.create_task(redis_subscriber(websocket, session_id))
        
        # Keep connection alive - listen for client pings/messages
        while True:
            try:
                # Wait for client messages (ping/pong or commands)
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                
                # Handle ping
                if data == "ping":
                    await websocket.send_json({
                        "type": "pong",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                    
            except asyncio.TimeoutError:
                # Send keepalive ping
                try:
                    await websocket.send_json({
                        "type": "keepalive",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                except Exception:
                    break

    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for session {session_id}")
    except Exception as e:
        logger.error(f"WebSocket error for session {session_id}: {e}")
    finally:
        # Clean up
        if redis_task:
            redis_task.cancel()
            try:
                await redis_task
            except asyncio.CancelledError:
                pass
        manager_ws.disconnect(websocket, session_id)


# Health check endpoint
@app.get("/health")
async def health_check():
    """
    Health check endpoint.
    
    Returns the current server status and timestamp. Used by load balancers
    and monitoring systems to verify the server is running and responsive.
    
    Returns:
        dict: Status and UTC timestamp
    """
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
