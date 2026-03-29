"""
Celery application configuration.

Configures Celery with Redis as the broker and result backend.
Supports configuration via environment variables for deployment flexibility.
"""

import os
import sys
from pathlib import Path

# Ensure the app root is in the Python path for imports
app_root = Path(__file__).parent.parent
if str(app_root) not in sys.path:
    sys.path.insert(0, str(app_root))

from celery import Celery  # noqa: E402
from celery.schedules import crontab  # noqa: E402

# Redis configuration from environment variables
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL", REDIS_URL)
CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", REDIS_URL)

# Create Celery app
celery_app = Celery(
    "hound_worker",
    broker=CELERY_BROKER_URL,
    backend=CELERY_RESULT_BACKEND,
    include=["worker.tasks"],
)

# Celery configuration
celery_app.conf.update(
    # Task settings
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    
    # Task execution settings
    task_acks_late=True,  # Acknowledge task after completion (for reliability)
    task_reject_on_worker_lost=True,  # Re-queue task if worker dies
    
    # Worker settings
    worker_prefetch_multiplier=1,  # Don't prefetch tasks (long-running audits)
    worker_concurrency=2,  # Default workers per process (can be overridden)
    
    # Task time limits (audits can run for hours)
    task_soft_time_limit=3600 * 6,  # 6 hours soft limit
    task_time_limit=3600 * 8,  # 8 hours hard limit
    
    # Result settings
    result_expires=86400,  # Results expire after 24 hours
    
    # Task routing (optional - for scaling different task types)
    task_routes={
        "worker.tasks.execute_audit_task": {"queue": "audits"},
        "worker.tasks.execute_scan_task": {"queue": "scans"},
        "worker.tasks.build_graphs_task": {"queue": "audits"},  # Graph builds are heavy
    },
    
    # Default queue
    task_default_queue="default",
)

# Optional: Configure task retry policy
celery_app.conf.task_annotations = {
    "worker.tasks.execute_audit_task": {
        "rate_limit": "2/m",  # Max 2 audits per minute per worker
    },
    "worker.tasks.execute_scan_task": {
        "rate_limit": "10/m",  # Surface scans are lighter
    },
    "worker.tasks.build_graphs_task": {
        "rate_limit": "5/m",  # Graph builds are moderately heavy
    },
}

# Celery Beat periodic schedule
celery_app.conf.beat_schedule = {
    "weekly-funnel-digest": {
        "task": "worker.tasks.send_funnel_digest_task",
        "schedule": crontab(hour=9, minute=0, day_of_week=1),  # Monday 9am UTC
    },
    "weekly-stripe-health": {
        "task": "worker.tasks.check_stripe_webhook_health_task",
        "schedule": crontab(hour=10, minute=0, day_of_week=1),  # Monday 10am UTC
    },
}
