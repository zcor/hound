# Integrations Module

This module provides external service integrations for Hound SaaS.

## Modules

### GitHub App Authentication (`github_auth.py`)

Secure authentication for GitHub App installations to clone private repos and access API.

```python
from integrations import get_installation_token, get_clone_url_with_token, get_authenticated_github_client

# Get an installation access token (cached automatically)
token = get_installation_token(installation_id=12345678)

# Get authenticated clone URL for private repos
clone_url = get_clone_url_with_token(
    "https://github.com/owner/private-repo",
    installation_id=12345678
)
# Returns: https://x-access-token:TOKEN@github.com/owner/private-repo.git

# Get PyGithub client for API calls
github = get_authenticated_github_client(installation_id=12345678)
repo = github.get_repo("owner/repo")
```

### PR Comment Bot (`pr_bot.py`)

Posts security findings as inline comments and summary on GitHub Pull Requests.

```python
from integrations import post_findings_to_pr, PRCommentBot

# Quick posting with convenience function
result = post_findings_to_pr(
    installation_id=12345678,
    repo_full_name="owner/repo",
    pr_number=42,
    findings=[
        {
            "title": "Reentrancy Vulnerability",
            "severity": "high",
            "type": "reentrancy",
            "confidence": 0.85,
            "description": "External call before state update",
            "affected": ["contracts/Vault.sol:142"],
        }
    ],
    scan_id="scan_abc123",
)

# Or use the bot class for more control
bot = PRCommentBot(
    installation_id=12345678,
    repo_full_name="owner/repo",
    pr_number=42,
)

# Delete previous Hound comments
bot.delete_previous_comments()

# Post inline comments on specific diff lines
bot.post_findings(findings, include_inline=True, include_summary=True)
```

### GitHub App Webhooks (`github_app.py`)

Handles GitHub webhook events for app installation and push events.

### Audit Trigger (`audit_trigger.py`)

Triggers audits from external events (webhooks, API calls).

## Environment Variables

```bash
# GitHub App credentials (required for GitHub integration)
GITHUB_APP_ID="123456"
GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----..."
# Or use file path:
GITHUB_APP_PRIVATE_KEY_PATH="/path/to/private-key.pem"

# Webhook secret (for webhook signature verification)
GITHUB_WEBHOOK_SECRET="your-webhook-secret"
```

## Setting Up a GitHub App

1. Go to **GitHub Settings → Developer settings → GitHub Apps → New GitHub App**

2. Configure permissions:
   - **Repository permissions:**
     - Contents: Read (to clone repos)
     - Pull requests: Write (to post comments)
     - Metadata: Read
   - **Subscribe to events:**
     - Installation
     - Push
     - Pull request

3. Generate and download a private key (`.pem` file)

4. Note your **App ID** from the app settings page

5. Set environment variables with your credentials

## Features

### Token Caching
Installation tokens are automatically cached with 5-minute buffer before expiry. No need to manage token refresh manually.

### Inline PR Comments
Findings are mapped to specific lines in the PR diff. If a finding's location isn't in the diff, it appears in the summary comment instead.

### Severity Emoji Mapping
- 🔴 Critical
- 🟠 High  
- 🟡 Medium
- 🟢 Low

### Comment Identification
All Hound comments include `<!-- hound-security-bot -->` marker for easy identification and cleanup.
