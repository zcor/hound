# Token Usage & Cost Tracking

Hound now includes comprehensive token usage and cost tracking to help you monitor LLM expenses.

## Features

- **Automatic Token Tracking**: All LLM calls are automatically logged to the database
- **Cost Calculation**: Costs are calculated based on current model pricing (January 2026)
- **Project-level Tracking**: See which projects consume the most tokens
- **Model Breakdown**: Understand which models you're using most
- **Profile Analysis**: Track token usage by agent profile (scout, strategist, finalize, etc.)
- **Admin Dashboard**: Visual cost dashboard with charts and statistics

## Accessing Cost Data

### Admin Panel

1. Visit `/admin/cost-dashboard` for a visual overview
2. Or go to `/admin` and click "Token Usage" in the sidebar
3. View detailed logs at `/admin/token-usage-log/list`

### API Endpoints

Get cost statistics programmatically:

```bash
# Get stats for last 30 days
curl http://localhost:8000/admin/token-stats

# Filter by project
curl http://localhost:8000/admin/token-stats?project_id=1

# Custom time range
curl http://localhost:8000/admin/token-stats?days=7
```

### Response Format

```json
{
  "period_days": 30,
  "totals": {
    "tokens": 1234567,
    "cost_usd": 12.34,
    "calls": 450,
    "avg_cost_per_call": 0.0274
  },
  "by_model": [
    {"model": "gpt-4o-mini", "tokens": 800000, "cost_usd": 8.50, "calls": 300},
    {"model": "claude-3-5-sonnet", "tokens": 434567, "cost_usd": 3.84, "calls": 150}
  ],
  "by_provider": [...],
  "by_profile": [...],
  "by_project": [...],
  "daily_trend": [...]
}
```

## Model Pricing (Per 1M Tokens)

Current pricing as of January 2026:

### OpenAI
- **gpt-4o**: $2.50 input / $10.00 output
- **gpt-4o-mini**: $0.15 input / $0.60 output
- **o1**: $15.00 input / $60.00 output
- **o1-mini**: $3.00 input / $12.00 output

### Anthropic
- **claude-opus-4**: $15.00 input / $75.00 output
- **claude-sonnet-4**: $3.00 input / $15.00 output
- **claude-3-5-haiku**: $0.80 input / $4.00 output

### Google
- **gemini-2.0-flash**: $0.10 input / $0.40 output
- **gemini-1.5-pro**: $1.25 input / $5.00 output

### DeepSeek
- **deepseek-reasoner**: $0.55 input / $2.19 output
- **deepseek-chat**: $0.14 input / $0.28 output

### xAI
- **grok-2**: $2.00 input / $10.00 output

Pricing is updated periodically. Edit `database/models.py` to update rates.

## Database Schema

The `token_usage_logs` table stores:

```python
class TokenUsageLog:
    project_id: int           # Link to project
    session_id: str          # Link to audit session
    tenant_id: int           # Multi-tenancy support
    provider: str            # openai, anthropic, google, etc.
    model: str               # gpt-4o, claude-3-opus, etc.
    profile: str             # agent, graph, guidance, etc.
    input_tokens: int        # Prompt tokens
    output_tokens: int       # Completion tokens
    total_tokens: int        # Sum
    cost_usd: float          # Calculated cost
    endpoint: str            # API endpoint that triggered call
    created_at: datetime     # Timestamp
```

## Usage in Code

### Setting Context

When making API calls, set the context to associate token usage with projects:

```python
from llm.token_tracker import set_token_context

# At the start of an API request
set_token_context(
    project_id=project.id,
    session_id=session.session_id,
    tenant_id=tenant.id,
    endpoint="/audits/start"
)

# Make LLM calls - they will be automatically tracked
llm = UnifiedLLMClient(cfg=config, profile="agent")
response = llm.raw(system="...", user="...")

# Clear context when done
from llm.token_tracker import clear_token_context
clear_token_context()
```

### Manual Tracking

Token tracking happens automatically via the `UnifiedLLMClient`, but you can also track manually:

```python
from llm.token_tracker import get_token_tracker

tracker = get_token_tracker()
tracker.track_usage(
    provider="openai",
    model="gpt-4o-mini",
    input_tokens=1000,
    output_tokens=500,
    profile="custom"
)
```

## Cost Optimization Tips

1. **Use cheaper models for simple tasks**: `gpt-4o-mini` and `claude-3-5-haiku` are great for basic analysis
2. **Monitor by profile**: See which agent profiles consume the most - optimize those first
3. **Set project budgets**: Use the API to get project-specific costs and set alerts
4. **Track trends**: Use the daily trend data to spot cost spikes
5. **Review high-cost projects**: The dashboard shows top projects - review if costs are justified

## Migration

To add the table to an existing database:

```bash
# Using Python
python3 -c "from database.models import create_db_engine, TokenUsageLog; engine = create_db_engine('$DATABASE_URL'); TokenUsageLog.__table__.create(engine, checkfirst=True)"

# Or using SQL migration file
psql $DATABASE_URL < database/migrations/add_token_usage_log.sql
```

## Future Enhancements

- Budget alerts and notifications
- Cost forecasting based on trends
- Per-user cost tracking
- Export cost reports to CSV/PDF
- Integration with billing systems
