#!/usr/bin/env python3
"""
GitHub Webhook Server for Hound.

This script starts the FastAPI webhook server to receive GitHub events.

Usage:
    python webhook_server.py
    
Environment Variables:
    GITHUB_APP_ID: GitHub App ID
    GITHUB_APP_PRIVATE_KEY_PATH: Path to the private key .pem file
    GITHUB_WEBHOOK_SECRET: Webhook secret for signature verification
    DATABASE_URL: PostgreSQL connection URL
    HOST: Server host (default: 0.0.0.0)
    PORT: Server port (default: 8000)
"""

import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

import uvicorn

from integrations.github_app import app


def main():
    """Run the webhook server."""
    # Check required environment variables
    required_vars = [
        "GITHUB_APP_ID",
        "GITHUB_APP_PRIVATE_KEY_PATH",
    ]
    
    missing_vars = [var for var in required_vars if not os.environ.get(var)]
    
    if missing_vars:
        print("Error: Missing required environment variables:")
        for var in missing_vars:
            print(f"  - {var}")
        print("\nPlease set these environment variables before running the server.")
        sys.exit(1)
    
    # Warn about missing webhook secret (security risk)
    if not os.environ.get("GITHUB_WEBHOOK_SECRET"):
        print("Warning: GITHUB_WEBHOOK_SECRET is not set!")
        print("Webhook signature verification will be skipped.")
        print("This is insecure for production deployments.")
        print("")
    
    # Get server configuration
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))
    
    print(f"Starting GitHub webhook server on {host}:{port}")
    print(f"Webhook endpoint: http://{host}:{port}/webhooks/github")
    print(f"Health check: http://{host}:{port}/health")
    
    # Run the server
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info"
    )


if __name__ == "__main__":
    main()
