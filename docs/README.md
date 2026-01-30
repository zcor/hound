# Hound Documentation

## Quick Start
- [Main README](../README.md) - Installation and basic usage

## Technical Documentation
- [API Reference](API_REFERENCE.md) - Complete REST and WebSocket API documentation
- [Developer Guide](DEVELOPER_GUIDE.md) - Development setup, testing, and contributing
- [Module Documentation](MODULES.md) - Detailed module-by-module technical reference

## User Guides
- [Surface Scan](SURFACE_SCAN.md) - Fast lightweight security scanning
- [Cloud Storage Guide](cloud_storage_guide.md) - Configuring S3/MinIO storage
- [Railway Deployment](railway_deployment.md) - Deploy to Railway
- [Cost Tracking](cost_tracking.md) - Monitor LLM costs

## Architecture & Design
- [Architecture Overview](architecture/README.md) - Technical deep-dives
  - [Technical Overview](architecture/technical_overview.md) - Core concepts
  - [SaaS Architecture](architecture/saas_architecture.md) - Production system design
  - [Cloud Storage](architecture/cloud_storage.md) - Storage backend design
  - [Headless Agent](architecture/headless_agent.md) - SaaS hardening
  - [Coverage Tracking](architecture/coverage_tracking.md) - Coverage analysis
  - [PR Reporter](architecture/pr_reporter.md) - GitHub PR integration

## Component Documentation
- [Database](../database/README.md) - SQLAlchemy models and migrations
- [Server API](../server/README.md) - FastAPI endpoints and deployment
- [Worker](../worker/README.md) - Celery background workers
- [Integrations](../integrations/README.md) - GitHub App & external services
- [Frontend](../frontend/README.md) - Next.js dashboard
- [Chatbot](../chatbot/README.md) - Interactive chat interface

## Examples
- [DeepSeek Setup](../examples/deepseek_example.md) - Cost-efficient LLM configuration
- [GitHub PR Comments](../examples/github_pr_comment.py) - Posting findings to PRs
- [Storage Backend](../examples/storage_backend_example.py) - Custom storage setup

## For Developers

### Getting Started
1. Read the [Developer Guide](DEVELOPER_GUIDE.md) for setup instructions
2. Check [Module Documentation](MODULES.md) to understand the codebase
3. Review [API Reference](API_REFERENCE.md) for integration patterns

### Key Resources
- **Contributing:** See [Developer Guide - Contributing](DEVELOPER_GUIDE.md#contributing)
- **Testing:** See [Developer Guide - Testing](DEVELOPER_GUIDE.md#testing)
- **Code Style:** See [Developer Guide - Code Style](DEVELOPER_GUIDE.md#code-style)

### Architecture Resources
- [Agent System](architecture/technical_overview.md#3-dynamic-model-switching) - Scout/Strategist pattern
- [Knowledge Graphs](architecture/technical_overview.md#1-dynamic-knowledge-graphs) - Graph construction
- [Hypothesis System](architecture/technical_overview.md#2-iterative-hypothesis--belief-system) - Finding tracking

## For API Users

- [API Reference](API_REFERENCE.md) - Complete endpoint documentation
- [WebSocket Protocol](API_REFERENCE.md#websocket-api) - Real-time updates
- [Authentication](API_REFERENCE.md#authentication) - Admin key setup
- [Error Handling](API_REFERENCE.md#error-handling) - Error codes and responses

## For SaaS Operators

- [SaaS Architecture](architecture/saas_architecture.md) - System overview
- [Server README](../server/README.md) - API server deployment
- [Worker README](../worker/README.md) - Background task processing
- [Docker Deployment](../README.md#docker-quickstart-saas-mode) - Docker Compose setup
