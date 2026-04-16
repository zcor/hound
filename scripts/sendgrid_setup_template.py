#!/usr/bin/env python3
"""One-time provisioning: promote the Firepan SendGrid Design into a Dynamic Template.

Ian created a Design (`c1af79cf-a682-4888-b435-5656829d0ee6`, "Firepan Email Template")
in the SendGrid UI. Designs are HTML assets that can't be sent via /v3/mail/send —
we need a Dynamic Template with `subject = "{{subject_line}}"`. This script:

  1. Fetches the design HTML via /v3/designs/{id}
  2. Creates a Dynamic Template via /v3/templates
  3. Creates an active version with subject "{{subject_line}}" and html_content from (1)
  4. Prints the `d-xxxx` template ID for paste into .env as SENDGRID_TEMPLATE_ID_DEFAULT

Run once per environment. Safe to re-run: creates a new template version each time
(and a new template each time). For idempotent re-runs, pass --update <template_id>
to update the existing template's active version.

Usage:
    SENDGRID_API_KEY=SG.xxx python scripts/sendgrid_setup_template.py
    SENDGRID_API_KEY=SG.xxx python scripts/sendgrid_setup_template.py --update d-abc123
"""

import argparse
import json
import os
import re
import sys
from urllib.request import Request, urlopen
from urllib.error import HTTPError

DEFAULT_DESIGN_ID = "c1af79cf-a682-4888-b435-5656829d0ee6"
DEFAULT_TEMPLATE_NAME = "firepan-lifecycle-v1"
DEFAULT_SUBJECT = "{{{subject_line}}}"  # triple-braces: do NOT HTML-escape (preserve apostrophes in subject)


def _request(method: str, url: str, api_key: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {api_key}")
    req.add_header("Content-Type", "application/json")
    try:
        with urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        print(f"HTTP {e.code} on {method} {url}:\n{raw}", file=sys.stderr)
        raise


def fetch_design_html(api_key: str, design_id: str) -> str:
    design = _request("GET", f"https://api.sendgrid.com/v3/designs/{design_id}", api_key)
    html = design.get("html_content")
    if not html:
        raise RuntimeError(f"Design {design_id} has no html_content")
    print(f"Fetched design: {design.get('name')!r} ({len(html)} bytes HTML)")

    # Patch 1: body_content → raw HTML passthrough.
    # Ian's Design (c1af79cf-…) uses `{{body_content}}` (double braces, HTML-escaped)
    # for the main content block. That escapes `<p>` to `&lt;p&gt;` which renders as
    # literal text. Our LIFECYCLE_CONFIG body snippets are trusted HTML we wrote
    # ourselves, so promote to `{{{body_content}}}` (raw passthrough).
    # The other vars (subject, hero, cta_label, first_name) stay as double-braces
    # because they're plain text — the one exception is the subject field which we
    # set explicitly to `{{{subject_line}}}` below (the Design has no subject field).
    if "{{{body_content}}}" not in html:
        count = html.count("{{body_content}}")
        html = html.replace("{{body_content}}", "{{{body_content}}}")
        print(f"Promoted {count} occurrence(s) of body_content to triple-braces (raw HTML passthrough)")

    # Patch 2: remove the "Manage Preferences" link.
    # SendGrid fills `{{{unsubscribe_preferences}}}` with a URL from its Unsubscribe
    # Groups feature. We don't use Unsubscribe Groups — we have exactly one boolean
    # tenant.email_unsubscribed flag. Clicking "Manage Preferences" sent users to
    # SendGrid's default global-unsub page (reported 2026-04-16 by Ian: "both links
    # unsubscribe"). Better to remove it entirely than have a misleading link.
    mp_pattern = re.compile(
        r'(?:\s|&nbsp;)*\|(?:\s|&nbsp;)*<a\s+href="\{\{\{unsubscribe_preferences\}\}\}"[^>]*>Manage Preferences</a>',
        re.IGNORECASE,
    )
    mp_matches = mp_pattern.findall(html)
    if mp_matches:
        html = mp_pattern.sub('', html)
        print(f"Removed {len(mp_matches)} 'Manage Preferences' link(s) from footer")

    return html


def create_template(api_key: str, name: str) -> str:
    body = {"name": name, "generation": "dynamic"}
    result = _request("POST", "https://api.sendgrid.com/v3/templates", api_key, body)
    template_id = result.get("id")
    if not template_id:
        raise RuntimeError(f"Template create succeeded but no id in response: {result}")
    print(f"Created Dynamic Template: {template_id} ({name!r})")
    return template_id


def create_version(api_key: str, template_id: str, html: str, subject: str, version_name: str) -> dict:
    url = f"https://api.sendgrid.com/v3/templates/{template_id}/versions"
    body = {
        "active": 1,
        "name": version_name,
        "subject": subject,
        "html_content": html,
        "generate_plain_content": True,
    }
    result = _request("POST", url, api_key, body)
    version_id = result.get("id")
    print(f"Created version {version_id} (active=1) for template {template_id}")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--design-id", default=DEFAULT_DESIGN_ID, help="SendGrid Design ID to convert")
    parser.add_argument("--name", default=DEFAULT_TEMPLATE_NAME, help="Name for the new Dynamic Template")
    parser.add_argument("--subject", default=DEFAULT_SUBJECT, help="Subject line (uses {{handlebars}})")
    parser.add_argument("--update", default=None, help="Update an existing template_id instead of creating new")
    args = parser.parse_args()

    api_key = os.environ.get("SENDGRID_API_KEY")
    if not api_key:
        print("ERROR: SENDGRID_API_KEY environment variable not set.", file=sys.stderr)
        sys.exit(1)

    html = fetch_design_html(api_key, args.design_id)

    if args.update:
        template_id = args.update
        version_name = f"firepan-lifecycle-update"
    else:
        template_id = create_template(api_key, args.name)
        version_name = "v1"

    create_version(api_key, template_id, html, args.subject, version_name)

    print()
    print("=" * 70)
    print("SUCCESS")
    print("=" * 70)
    print(f"Template ID: {template_id}")
    print()
    print("Add this to your .env file:")
    print(f"  SENDGRID_TEMPLATE_ID_DEFAULT={template_id}")
    print()
    print("Verify in the UI:")
    print(f"  https://mc.sendgrid.com/dynamic-templates/{template_id}")


if __name__ == "__main__":
    main()
