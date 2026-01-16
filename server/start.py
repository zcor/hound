#!/usr/bin/env python3
"""
Startup script for Hound Dashboard API Server.

This script starts the FastAPI server with sensible defaults.
"""

import logging
import os
import sys
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

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
    
    logger.info("🐕 Starting Hound Dashboard API Server")
    logger.info(f"   Host: {host}")
    logger.info(f"   Port: {port}")
    logger.info(f"   Workers: {workers}")
    logger.info(f"   Reload: {reload}")
    logger.info(f"   Database: {os.environ.get('DATABASE_URL', 'postgresql://localhost/hound')}")
    logger.info("")
    logger.info("📖 API Documentation:")
    logger.info(f"   Swagger UI: http://{host if host != '0.0.0.0' else 'localhost'}:{port}/docs")
    logger.info(f"   ReDoc: http://{host if host != '0.0.0.0' else 'localhost'}:{port}/redoc")
    logger.info("")
    
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
