"""
GitHub App integration for Hound.

Handles GitHub App authentication and webhook events to enable:
- Automatic repository monitoring via GitHub App installations
- Webhook-triggered security audits on push events
- Repository access via installation tokens
"""

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from github import Auth, Github, GithubIntegration
from sqlalchemy.orm import Session

from database.models import Project, Tenant, create_db_engine, create_db_session

# GitHub App configuration
# These should be set as environment variables
GITHUB_APP_ID = os.environ.get("GITHUB_APP_ID")
GITHUB_APP_PRIVATE_KEY_PATH = os.environ.get("GITHUB_APP_PRIVATE_KEY_PATH")
GITHUB_WEBHOOK_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET")
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost/hound")


def get_github_app_integration() -> GithubIntegration:
    """
    Create a GitHub App integration instance.
    
    Returns:
        GithubIntegration instance for making authenticated requests
        
    Raises:
        ValueError: If GitHub App credentials are not configured
    """
    if not GITHUB_APP_ID:
        raise ValueError("GITHUB_APP_ID environment variable is not set")
    
    if not GITHUB_APP_PRIVATE_KEY_PATH:
        raise ValueError("GITHUB_APP_PRIVATE_KEY_PATH environment variable is not set")
    
    private_key_path = Path(GITHUB_APP_PRIVATE_KEY_PATH)
    if not private_key_path.exists():
        raise ValueError(f"Private key file not found: {private_key_path}")
    
    with open(private_key_path) as key_file:
        private_key = key_file.read()
    
    auth = Auth.AppAuth(int(GITHUB_APP_ID), private_key)
    return GithubIntegration(auth=auth)


def get_repo_token(installation_id: int) -> str:
    """
    Get an installation access token for accessing repositories.
    
    This function authenticates as a GitHub App and generates an installation
    token that can be used to access repositories where the app is installed.
    
    Args:
        installation_id: The GitHub App installation ID
        
    Returns:
        Installation access token as a string
        
    Raises:
        ValueError: If GitHub App credentials are not configured
        Exception: If token generation fails
    """
    integration = get_github_app_integration()
    
    # Get the installation access token
    auth = integration.get_access_token(installation_id)
    return auth.token


def get_github_client(installation_id: int) -> Github:
    """
    Get an authenticated GitHub client for an installation.
    
    Args:
        installation_id: The GitHub App installation ID
        
    Returns:
        Authenticated Github client instance
    """
    token = get_repo_token(installation_id)
    return Github(token)


def verify_webhook_signature(payload_body: bytes, signature_header: str) -> bool:
    """
    Verify that the webhook request came from GitHub.
    
    Args:
        payload_body: Raw request body
        signature_header: The X-Hub-Signature-256 header value
        
    Returns:
        True if signature is valid, False otherwise
    """
    if not GITHUB_WEBHOOK_SECRET:
        # If no secret is configured, skip verification (not recommended for production)
        return True
    
    if not signature_header:
        return False
    
    # GitHub sends signature as "sha256=<signature>"
    hash_algorithm, github_signature = signature_header.split('=')
    
    # Create HMAC signature
    expected_signature = hmac.new(
        GITHUB_WEBHOOK_SECRET.encode('utf-8'),
        msg=payload_body,
        digestmod=hashlib.sha256
    ).hexdigest()
    
    # Compare signatures
    return hmac.compare_digest(expected_signature, github_signature)


def get_db_session() -> Session:
    """Get a database session."""
    engine = create_db_engine(DATABASE_URL)
    return create_db_session(engine)


def handle_installation_created(payload: dict[str, Any], db_session: Session) -> None:
    """
    Handle the installation.created webhook event.
    
    Creates Project entries for each repository in the installation.
    
    Args:
        payload: The webhook payload
        db_session: Database session
    """
    installation = payload.get("installation", {})
    installation_id = installation.get("id")
    account = installation.get("account", {})
    account_login = account.get("login", "unknown")
    
    if not installation_id:
        raise ValueError("No installation_id in payload")
    
    # Get or create tenant for this installation
    tenant = db_session.query(Tenant).filter_by(
        installation_id=installation_id
    ).first()
    
    if not tenant:
        tenant = Tenant(
            name=f"github_{account_login}",
            installation_id=installation_id
        )
        db_session.add(tenant)
        db_session.flush()  # Get the tenant ID
    
    # Get list of repositories from the payload
    repositories = payload.get("repositories", [])
    
    for repo_data in repositories:
        repo_name = repo_data.get("full_name")
        repo_id = repo_data.get("id")
        
        if not repo_name:
            continue
        
        # Check if project already exists
        existing_project = db_session.query(Project).filter_by(
            github_repo_id=repo_id
        ).first()
        
        if not existing_project:
            # Create new project
            project = Project(
                tenant_id=tenant.id,
                name=repo_name.replace("/", "_"),
                git_url=f"https://github.com/{repo_name}",
                github_repo_id=repo_id,
                installation_id=installation_id,
                description=f"GitHub repository: {repo_name}",
                status="active"
            )
            db_session.add(project)
    
    db_session.commit()


def handle_push_event(payload: dict[str, Any], db_session: Session) -> None:
    """
    Handle the push webhook event.
    
    Triggers a security audit for the pushed commit if the repository
    is active in our database.
    
    Args:
        payload: The webhook payload
        db_session: Database session
    """
    repository = payload.get("repository", {})
    repo_id = repository.get("id")
    
    # Get the commit SHA
    head_commit = payload.get("head_commit", {})
    commit_sha = head_commit.get("id") or payload.get("after")
    
    if not repo_id or not commit_sha:
        return
    
    # Check if this repo is active in our database
    project = db_session.query(Project).filter_by(
        github_repo_id=repo_id,
        status="active"
    ).first()
    
    if not project:
        # Repository not tracked or not active
        return
    
    # Trigger audit task for this commit
    # Import here to avoid circular dependencies
    from integrations.audit_trigger import run_audit_task
    
    run_audit_task(
        project_id=project.id,
        project_name=project.name,
        commit_sha=commit_sha,
        repo_url=repository.get("clone_url"),
        installation_id=project.installation_id
    )


# FastAPI application for webhooks
app = FastAPI(title="Hound GitHub Webhooks")


@app.post("/webhooks/github")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(None),
    x_github_event: str | None = Header(None)
):
    """
    Handle GitHub webhook events.
    
    Supports:
    - installation.created: Creates Project entries for new installations
    - push: Triggers security audits on code changes
    """
    # Read the raw body for signature verification
    body = await request.body()
    
    # Verify webhook signature
    if not verify_webhook_signature(body, x_hub_signature_256):
        raise HTTPException(status_code=401, detail="Invalid signature")
    
    # Parse the JSON payload
    try:
        payload = json.loads(body.decode('utf-8'))
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")
    
    # Get database session
    db_session = get_db_session()
    
    try:
        # Handle different event types
        if x_github_event == "installation" and payload.get("action") == "created":
            handle_installation_created(payload, db_session)
            return {"status": "ok", "message": "Installation processed"}
        
        elif x_github_event == "push":
            handle_push_event(payload, db_session)
            return {"status": "ok", "message": "Push event processed"}
        
        else:
            # Unsupported event type
            return {"status": "ignored", "event": x_github_event}
    
    except Exception as e:
        db_session.rollback()
        raise HTTPException(status_code=500, detail=f"Error processing webhook: {str(e)}")
    
    finally:
        db_session.close()


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
