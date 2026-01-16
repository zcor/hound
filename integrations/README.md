# GitHub App Integration

This module provides GitHub App authentication and webhook handling for Hound.

## Features

- **GitHub App Authentication**: Authenticate as a GitHub App and generate installation tokens
- **Webhook Handler**: Process GitHub webhook events
- **Automatic Project Creation**: Create project entries when the app is installed on repositories
- **Push Event Audits**: Trigger security audits when code is pushed to monitored repositories

## Setup

### 1. Create a GitHub App

1. Go to GitHub Settings → Developer settings → GitHub Apps → New GitHub App
2. Configure the app:
   - **Homepage URL**: Your application URL
   - **Webhook URL**: `https://your-domain.com/webhooks/github`
   - **Webhook secret**: Generate a random secret
   - **Permissions**:
     - Repository permissions:
       - Contents: Read
       - Metadata: Read
   - **Subscribe to events**:
     - Installation
     - Push
3. Generate a private key and download the `.pem` file
4. Note your App ID

### 2. Configure Environment Variables

Set the following environment variables:

```bash
export GITHUB_APP_ID="123456"                              # Your GitHub App ID
export GITHUB_APP_PRIVATE_KEY_PATH="/path/to/private.pem"  # Path to private key
export GITHUB_WEBHOOK_SECRET="your-webhook-secret"         # Webhook secret
export DATABASE_URL="postgresql://user:pass@localhost/hound"  # Database connection
```

### 3. Run the Webhook Server

Start the webhook server to receive GitHub events:

```bash
python webhook_server.py
```

Or with custom host/port:

```bash
export HOST="0.0.0.0"
export PORT="8000"
python webhook_server.py
```

The server will be available at:
- Webhook endpoint: `http://localhost:8000/webhooks/github`
- Health check: `http://localhost:8000/health`

### 4. Install the GitHub App

1. Go to your GitHub App settings
2. Click "Install App"
3. Select the repositories you want to monitor
4. The app will create Project entries in the database for each repository

## Usage

### Get Repository Token

```python
from integrations.github_app import get_repo_token

# Get an installation token for accessing repositories
token = get_repo_token(installation_id=12345)
```

### Get Authenticated GitHub Client

```python
from integrations.github_app import get_github_client

# Get an authenticated GitHub client
client = get_github_client(installation_id=12345)

# Use the client to access repositories
repo = client.get_repo("owner/repo")
```

## Webhook Events

### installation.created

When the app is installed on repositories, this event:
1. Creates a Tenant entry (or uses existing) with the installation_id
2. Creates Project entries for each repository
3. Stores the installation_id on both Tenant and Project

### push

When code is pushed to a monitored repository, this event:
1. Checks if the repository is active in the database
2. Triggers a security audit for the specific commit
3. The audit is handled by the `run_audit_task` function

## Database Schema

The integration adds the following fields to the database models:

**Tenant**:
- `installation_id` (BigInteger): GitHub App installation ID

**Project**:
- `github_repo_id` (BigInteger): GitHub repository ID
- `installation_id` (BigInteger): GitHub App installation ID

## Testing

Run the tests with:

```bash
python -m pytest tests/test_github_integration.py -v
```

Or run all tests:

```bash
python -m pytest tests/ -v
```

## Security

- Webhook signatures are verified using HMAC-SHA256
- Private keys should be stored securely and never committed to version control
- Use environment variables for sensitive configuration
- In production, always set `GITHUB_WEBHOOK_SECRET` for signature verification

## Deployment

### Docker

```dockerfile
FROM python:3.10

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

ENV HOST=0.0.0.0
ENV PORT=8000

CMD ["python", "webhook_server.py"]
```

### systemd Service

```ini
[Unit]
Description=Hound GitHub Webhook Server
After=network.target

[Service]
Type=simple
User=hound
WorkingDirectory=/opt/hound
Environment="GITHUB_APP_ID=123456"
Environment="GITHUB_APP_PRIVATE_KEY_PATH=/opt/hound/private.pem"
Environment="GITHUB_WEBHOOK_SECRET=your-secret"
Environment="DATABASE_URL=postgresql://localhost/hound"
ExecStart=/usr/bin/python3 /opt/hound/webhook_server.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## Troubleshooting

### "Private key file not found"
Make sure the `GITHUB_APP_PRIVATE_KEY_PATH` points to a valid `.pem` file.

### "Invalid signature"
Verify that the `GITHUB_WEBHOOK_SECRET` matches the secret configured in your GitHub App settings.

### Events not being received
1. Check that the webhook URL is publicly accessible
2. Verify the webhook is configured in your GitHub App settings
3. Check the webhook delivery logs in GitHub App settings

### Database connection errors
Ensure the `DATABASE_URL` is correct and the database is accessible.
