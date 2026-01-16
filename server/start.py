#!/usr/bin/env python3
"""
Startup script for Hound Dashboard API Server.

This script starts the FastAPI server with sensible defaults.
"""

import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def main():
    """Start the API server."""
    import uvicorn
    
    # Get configuration from environment
    host = os.environ.get("HOUND_API_HOST", "0.0.0.0")
    port = int(os.environ.get("HOUND_API_PORT", "8000"))
    workers = int(os.environ.get("HOUND_API_WORKERS", "1"))
    reload = os.environ.get("HOUND_API_RELOAD", "false").lower() == "true"
    
    print(f"🐕 Starting Hound Dashboard API Server")
    print(f"   Host: {host}")
    print(f"   Port: {port}")
    print(f"   Workers: {workers}")
    print(f"   Reload: {reload}")
    print(f"   Database: {os.environ.get('DATABASE_URL', 'postgresql://localhost/hound')}")
    print()
    print(f"📖 API Documentation:")
    print(f"   Swagger UI: http://{host if host != '0.0.0.0' else 'localhost'}:{port}/docs")
    print(f"   ReDoc: http://{host if host != '0.0.0.0' else 'localhost'}:{port}/redoc")
    print()
    
    # Start server
    uvicorn.run(
        "server.api:app",
        host=host,
        port=port,
        workers=workers if not reload else 1,  # Workers not supported with reload
        reload=reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()
