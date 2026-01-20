"""
Celery worker module for Hound SaaS.

This module provides background task execution using Celery,
allowing the web server to offload heavy operations (like running
autonomous security audits) to a separate worker fleet.

Key components:
- celery_app: Celery application instance
- tasks: Task definitions (execute_audit_task, execute_scan_task)
- redis_publisher: Redis Pub/Sub publisher for live updates
"""

from .celery_app import celery_app
from .redis_publisher import RedisPublisher

__all__ = ["celery_app", "RedisPublisher"]
