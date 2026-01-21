# Hound Railway Deployment Guide

## Quick Start (Single Service - SQLite)

For simple single-tenant deployment with SQLite:

1. **Connect GitHub repo to Railway**
2. **Set environment variables:**
   ```
   OPENAI_API_KEY=sk-...
   DEEPSEEK_API_KEY=sk-...  (optional, 95% cheaper)
   ```
3. **Deploy!** Railway auto-detects the Dockerfile

---

## Production Setup (Multi-Service)

### Step 1: Create Railway Project
```bash
# Install Railway CLI
npm install -g @railway/cli

# Login and create project
railway login
railway init
```

### Step 2: Add Database Services

In Railway dashboard:
1. Click **"New"** → **"Database"** → **"PostgreSQL"**
2. Click **"New"** → **"Database"** → **"Redis"**

Railway automatically creates `DATABASE_URL` and `REDIS_URL` variables.

### Step 3: Deploy API Service

1. Click **"New"** → **"GitHub Repo"**
2. Select your `hound` repository
3. Railway detects `railway.json` and uses it

### Step 4: Set Environment Variables

In the API service settings, add:

```env
# Required - LLM API Keys (at least one)
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
DEEPSEEK_API_KEY=sk-...

# Auto-set by Railway plugins (don't manually set these)
# DATABASE_URL=postgresql://...
# REDIS_URL=redis://...

# Optional - GitHub Integration
GITHUB_APP_ID=123456
GITHUB_APP_PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----...
GITHUB_WEBHOOK_SECRET=your-webhook-secret
```

### Step 5: Link Services

In Railway dashboard:
1. Go to API service → **Variables**
2. Click **"Reference"** to link `DATABASE_URL` from PostgreSQL
3. Click **"Reference"** to link `REDIS_URL` from Redis

---

## Environment Variables Reference

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENAI_API_KEY` | Yes* | OpenAI API key |
| `ANTHROPIC_API_KEY` | No | Anthropic API key |
| `DEEPSEEK_API_KEY` | No | DeepSeek API key (95% cheaper) |
| `DATABASE_URL` | Auto | PostgreSQL connection string |
| `REDIS_URL` | Auto | Redis connection string |
| `GITHUB_APP_ID` | No | For GitHub App integration |
| `GITHUB_APP_PRIVATE_KEY` | No | GitHub App private key |

*At least one LLM API key is required

---

## Costs Estimate

### Railway Pricing (Hobby Plan - $5/month)
- **API Service**: ~$2-5/month (depends on usage)
- **PostgreSQL**: ~$1-3/month
- **Redis**: ~$1-2/month
- **Total**: ~$5-10/month

### LLM API Costs
- **DeepSeek**: ~$0.14/million input tokens, $0.28/million output (~95% cheaper)
- **OpenAI GPT-4**: ~$30/million input tokens
- **Anthropic Claude**: ~$15/million input tokens

**Recommendation**: Use DeepSeek for development/testing, OpenAI for production audits.

---

## Custom Domain

1. Railway dashboard → API service → **Settings** → **Domains**
2. Add custom domain: `api.yourdomain.com`
3. Add DNS CNAME record pointing to Railway

---

## Scaling

Railway auto-scales based on traffic. For high load:

1. **Horizontal scaling**: Railway handles this automatically
2. **Add Celery workers**: Deploy a second service with:
   ```
   Start Command: celery -A worker.tasks worker --loglevel=info
   ```

---

## Troubleshooting

### Check Logs
```bash
railway logs
```

### Health Check
```bash
curl https://your-app.railway.app/health
```

### Database Migration
```bash
railway run python -c "from database.models import init_db; init_db()"
```
