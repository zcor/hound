# Hound Codespaces Development

## Quick Start

1. **Open in Codespace** - This will auto-install dependencies
2. **Set environment variables** (see Setup below)
3. **Run:** `bash scripts/start-dev.sh`
4. **Open forwarded port 8000** (click globe icon in Ports panel)

## Setup

### 1. Create GitHub OAuth App

Go to: https://github.com/settings/applications/new

Use these values (displayed in terminal after setup):
- **Homepage URL:** `https://YOUR-CODESPACE-NAME-3000.app.github.dev`
- **Callback URL:** `https://YOUR-CODESPACE-NAME-3000.app.github.dev/auth/callback`

### 2. Set Environment Variables

```bash
export GITHUB_CLIENT_ID="your_client_id"
export GITHUB_CLIENT_SECRET="your_secret"
export JWT_SECRET_KEY="$(openssl rand -hex 32)"
export FRONTEND_URL="https://YOUR-CODESPACE-NAME-3000.app.github.dev"
export ALLOWED_ORIGINS="https://YOUR-CODESPACE-NAME-3000.app.github.dev"
```

**Tip:** Add to `~/.bashrc` for persistence across terminal sessions.

### 3. Start Development Server

```bash
bash scripts/start-dev.sh
```

## Port Visibility

The devcontainer is configured to make port 8000 **public** automatically.
Verify in the **Ports** panel (View → Ports) that port 8000 shows "Public" visibility.

## Test Data

Test data is automatically seeded on first run:
- 1 tenant (ID=1)
- 3 projects
- 9 scans (mixed statuses)
- 15-20 findings

## Troubleshooting

### "Port 8000 is not accessible"
- Check Ports panel → Right-click port 8000 → Port Visibility → Public

### "OAuth callback fails"
- Ensure callback URL in GitHub OAuth app matches Codespace frontend URL exactly
- Check ALLOWED_ORIGINS includes frontend URL

### "Database connection errors"
- Run: `python -c "import os; from database.models import Base, create_db_engine; engine = create_db_engine(os.environ.get('DATABASE_URL', 'sqlite:///hound.db')); Base.metadata.create_all(bind=engine)"`
