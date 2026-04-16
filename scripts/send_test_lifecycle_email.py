#!/usr/bin/env python3
"""Send a single lifecycle email for QA.

Renders via the same LIFECYCLE_CONFIG + SendGrid dynamic-template pipeline as
production, but bypasses the SentEmail idempotency check so you can send the
same email to the same tenant repeatedly during template QA.

Usage:
    # Point at a real tenant in your local DB
    python scripts/send_test_lifecycle_email.py --code WELCOME_VERIFY --tenant-id 1 --to gerrit@firepan.com

    # Preview DEEP_AUDIT_DONE with mock extra_data
    python scripts/send_test_lifecycle_email.py --code DEEP_AUDIT_DONE --tenant-id 1 --to ian@firepan.com \
        --extra '{"project_name": "curve-finance/curve-contract", "session_id": "scan_abc", "findings_count": 12, "assessment_level": "HIGH"}'

Env required:
    SENDGRID_API_KEY=SG.xxx
    SENDGRID_TEMPLATE_ID_DEFAULT=d-xxxxx
    DATABASE_URL=postgresql://... (or sqlite:///...)
    HOUND_SECRET_KEY=...
"""

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database.models import Tenant, User, create_db_engine, create_db_session  # noqa: E402
from integrations.lifecycle_emails import (  # noqa: E402
    EmailCode,
    LIFECYCLE_CONFIG,
    _build_unsubscribe_url,
    _render_dynamic_data,
    _template_id,
    resolve_first_name,
)
from integrations.email import send_template_email  # noqa: E402


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--code", required=True, help=f"EmailCode name, one of: {', '.join(c.name for c in EmailCode)}")
    parser.add_argument("--tenant-id", type=int, required=True, help="Tenant ID to use for rendering (user lookup, unsubscribe token)")
    parser.add_argument("--to", required=True, help="Recipient email address")
    parser.add_argument("--extra", default="{}", help='JSON extra_data for template rendering, e.g. \'{"project_name":"foo"}\'')
    parser.add_argument("--dry-run", action="store_true", help="Print rendered payload but do not call SendGrid")
    args = parser.parse_args()

    try:
        code = EmailCode[args.code]
    except KeyError:
        print(f"ERROR: unknown code {args.code!r}. Options: {[c.name for c in EmailCode]}", file=sys.stderr)
        sys.exit(1)

    spec = LIFECYCLE_CONFIG.get(code)
    if spec is None:
        print(f"ERROR: no LIFECYCLE_CONFIG entry for {code.name}", file=sys.stderr)
        sys.exit(1)

    extra_data = json.loads(args.extra)

    db_url = os.environ.get("DATABASE_URL", "sqlite:///hound.db")
    engine = create_db_engine(db_url)
    db = create_db_session(engine)

    try:
        tenant = db.query(Tenant).filter(Tenant.id == args.tenant_id).first()
        if tenant is None:
            print(f"ERROR: no tenant with id={args.tenant_id} in {db_url}", file=sys.stderr)
            sys.exit(1)

        user = None
        if tenant.users:
            user = sorted(tenant.users, key=lambda u: u.created_at)[0]

        unsubscribe_url = _build_unsubscribe_url(tenant.id)
        dynamic_data = _render_dynamic_data(
            spec=spec, user=user, tenant=tenant,
            extra_data=extra_data, unsubscribe_url=unsubscribe_url,
        )

        template_id = _template_id()
        if not template_id:
            print("ERROR: SENDGRID_TEMPLATE_ID_DEFAULT not set", file=sys.stderr)
            sys.exit(1)

        print("=" * 70)
        print(f"Code: {code.name} ({code.value})")
        print(f"Recipient: {args.to}")
        print(f"Template ID: {template_id}")
        print(f"Subject: {dynamic_data['subject_line']!r}")
        print(f"First name: {dynamic_data['first_name']!r}")
        print(f"Unsubscribe URL: {unsubscribe_url}")
        print("Dynamic data keys:", list(dynamic_data.keys()))
        print("=" * 70)

        if args.dry_run:
            print("(dry run — not calling SendGrid)")
            return

        ok, err = await send_template_email(
            to_email=args.to,
            template_id=template_id,
            dynamic_data=dynamic_data,
            categories=["lifecycle-test", code.value],
            custom_args={"tenant_id": tenant.id, "email_code": code.value, "test": "1"},
        )
        if ok:
            print("Send OK.")
        else:
            print(f"Send FAILED: {err}", file=sys.stderr)
            sys.exit(2)

    finally:
        db.close()


if __name__ == "__main__":
    asyncio.run(main())
