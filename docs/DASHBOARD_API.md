# Dashboard API Documentation

This document describes the API endpoints implemented for the Firepan Dashboard integration.

## Overview

The Dashboard API provides endpoints for user management, organization information, repository management, scan execution, and findings aggregation. All endpoints support multi-tenancy through the `tenant_id` parameter.

## Authentication

Most endpoints require a `tenant_id` parameter to identify the user/organization context. This is obtained from the GitHub App installation process.

## Base URL

```
http://localhost:8000  # Development
https://api.hound.firepan.com  # Production
```

## Endpoints

### User & Organization Management

#### GET /users/me

Get current user profile information.

**Query Parameters:**
- `tenant_id` (required): Tenant ID from authentication context

**Response:**
```json
{
  "id": 1,
  "name": "testorg",
  "email": "test@example.com",
  "org_id": 1,
  "org_name": "test_org",
  "org_type": "Organization",
  "role": "admin"
}
```

**Status Codes:**
- 200: Success
- 404: User/Organization not found

---

#### GET /organizations/{org_id}

Get organization details by ID.

**Path Parameters:**
- `org_id` (required): Organization ID

**Response:**
```json
{
  "id": 1,
  "name": "test_org",
  "github_account_login": "testorg",
  "github_account_type": "Organization",
  "status": "active",
  "contact_email": "test@example.com",
  "created_at": "2026-02-16T16:37:36.965541",
  "updated_at": "2026-02-16T16:37:36.965545"
}
```

**Status Codes:**
- 200: Success
- 404: Organization not found

---

#### GET /organizations/{org_id}/members

List members of an organization.

**Path Parameters:**
- `org_id` (required): Organization ID

**Response:**
```json
[
  {
    "id": 1,
    "name": "testorg",
    "email": "test@example.com",
    "role": "owner"
  }
]
```

**Status Codes:**
- 200: Success
- 404: Organization not found

**Note:** In the current architecture, this returns the organization owner. Future enhancements will integrate with GitHub API to fetch actual org members.

---

### Subscriptions & Usage

#### GET /subscriptions/current

Get current subscription information for user/organization.

**Query Parameters:**
- `tenant_id` (required): Tenant ID from authentication context

**Response:**
```json
{
  "tenant_id": 1,
  "org_name": "test_org",
  "plan": "free",
  "status": "active",
  "created_at": "2026-02-16T16:37:36.965541"
}
```

**Status Codes:**
- 200: Success
- 404: Tenant not found

---

#### GET /usage/current-month

Get usage and billing statistics for the current billing period.

**Query Parameters:**
- `tenant_id` (required): Tenant ID from authentication context

**Response:**
```json
{
  "tenant_id": 1,
  "period": "2026-02",
  "scans_count": 15,
  "findings_count": 42,
  "total_cost_usd": 12.50,
  "token_usage": {
    "input_tokens": 150000,
    "output_tokens": 75000,
    "total_tokens": 225000
  }
}
```

**Status Codes:**
- 200: Success
- 404: Tenant not found

---

### Repositories & Scanning

#### GET /repositories

List all connected GitHub repositories for tenant/user.

**Query Parameters:**
- `tenant_id` (required): Tenant ID from authentication context
- `page` (optional): Page number (default: 1)
- `page_size` (optional): Items per page (default: 20, max: 100)
- `search` (optional): Search repository name

**Response:**
```json
{
  "repositories": [
    {
      "id": 1,
      "name": "test-repo",
      "git_url": "https://github.com/testorg/test-repo",
      "github_repo_id": null,
      "description": "Test repository",
      "status": "active",
      "last_scan_at": "2026-02-16T16:30:00.000000",
      "scans_count": 5,
      "findings_count": 12,
      "created_at": "2026-02-16T16:37:36.990433"
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 20
}
```

**Status Codes:**
- 200: Success

---

#### POST /repositories/{repository_id}/scan

Trigger a new scan for a repository.

**Path Parameters:**
- `repository_id` (required): Repository ID

**Response:**
```json
{
  "execution_id": "scan_0418c18e7f5d_1771259916",
  "repository_id": 1,
  "status": "pending",
  "message": "Scan queued successfully"
}
```

**Status Codes:**
- 200: Success
- 404: Repository not found

---

#### GET /repositories/{repository_id}/scans

List scan history for a repository.

**Path Parameters:**
- `repository_id` (required): Repository ID

**Query Parameters:**
- `page` (optional): Page number (default: 1)
- `page_size` (optional): Items per page (default: 20, max: 100)

**Response:**
```json
{
  "repository_id": 1,
  "scans": [
    {
      "execution_id": "scan_test_456",
      "status": "completed",
      "risk_score": 75,
      "risk_level": "high",
      "findings_count": 5,
      "started_at": "2026-02-16T16:30:00.000000",
      "completed_at": "2026-02-16T16:35:00.000000"
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 20
}
```

**Status Codes:**
- 200: Success
- 404: Repository not found

---

### Findings (Cross-Project)

#### GET /findings

List all findings (hypotheses) for organization/user with filtering.

**Query Parameters:**
- `tenant_id` (required): Tenant ID from authentication context
- `page` (optional): Page number (default: 1)
- `page_size` (optional): Items per page (default: 20, max: 100)
- `severity` (optional): Filter by severity (critical, high, medium, low)
- `status` (optional): Filter by status (proposed, investigating, confirmed, rejected, resolved)
- `repository_id` (optional): Filter by repository ID

**Response:**
```json
{
  "findings": [
    {
      "id": 1,
      "hypothesis_id": "hyp_20250116_120000_xyz789",
      "title": "SQL Injection in login endpoint",
      "description": "The login endpoint is vulnerable to SQL injection attacks",
      "vulnerability_type": "SQL Injection",
      "status": "confirmed",
      "confidence": 0.9,
      "severity": "high",
      "node_refs": ["node1", "node2"],
      "evidence": {"code_snippet": "SELECT * FROM users WHERE id = <user_input>"},
      "reported_by_model": "gpt-4o",
      "junior_model": "gpt-4o-mini",
      "senior_model": "gpt-4o",
      "created_at": "2026-02-16T16:30:00.000000",
      "updated_at": "2026-02-16T16:35:00.000000"
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 20
}
```

**Status Codes:**
- 200: Success

---

#### GET /findings/stats

Get summary statistics for findings by severity, status, and repository.

**Query Parameters:**
- `tenant_id` (required): Tenant ID from authentication context

**Response:**
```json
{
  "total": 42,
  "by_severity": {
    "critical": 5,
    "high": 12,
    "medium": 20,
    "low": 5
  },
  "by_status": {
    "proposed": 10,
    "investigating": 5,
    "confirmed": 15,
    "rejected": 8,
    "resolved": 4
  },
  "by_repository": {
    "test-repo": 25,
    "another-repo": 17
  }
}
```

**Status Codes:**
- 200: Success

---

### Surface Scans (Enhanced)

#### GET /surface/scans

List all surface scans with optional tenant filtering.

**Query Parameters:**
- `tenant_id` (optional): Filter by tenant ID
- `page` (optional): Page number (default: 1)
- `page_size` (optional): Items per page (default: 20, max: 100)
- `risk_level` (optional): Filter by risk level (critical, high, medium, low)
- `status` (optional): Filter by status (pending, running, completed, failed)
- `search` (optional): Search repo name

**Response:**
```json
{
  "scans": [
    {
      "execution_id": "scan_0418c18e7f5d_1771259916",
      "repo_name": "test-repo",
      "repo_url": "https://github.com/testorg/test-repo",
      "risk_score": 75,
      "risk_level": "high",
      "finding_count": 5,
      "contracts_scanned": 10,
      "status": "completed",
      "created_at": "2026-02-16T16:38:36.301474",
      "summary": "Found 5 potential security issues"
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 20
}
```

**Status Codes:**
- 200: Success

---

## Error Responses

All endpoints return consistent error responses:

```json
{
  "detail": "Error message describing what went wrong"
}
```

Common HTTP status codes:
- 400: Bad Request - Invalid parameters
- 404: Not Found - Resource not found
- 500: Internal Server Error - Unexpected error

---

## Rate Limiting

Currently, there is no rate limiting on most endpoints. Authentication endpoints (`/auth/start` and `/auth/complete`) have rate limits:
- `/auth/start`: 20 requests per minute per IP
- `/auth/complete`: 10 requests per minute per IP

---

## OpenAPI Documentation

Interactive API documentation is available at:
- Swagger UI: `/docs`
- ReDoc: `/redoc`

---

## Examples

### cURL Examples

**Get user profile:**
```bash
curl -X GET "http://localhost:8000/users/me?tenant_id=1" \
  -H "accept: application/json"
```

**List repositories:**
```bash
curl -X GET "http://localhost:8000/repositories?tenant_id=1&page=1&page_size=10" \
  -H "accept: application/json"
```

**Trigger repository scan:**
```bash
curl -X POST "http://localhost:8000/repositories/1/scan" \
  -H "accept: application/json"
```

**Get findings with filters:**
```bash
curl -X GET "http://localhost:8000/findings?tenant_id=1&severity=high&status=confirmed" \
  -H "accept: application/json"
```

### Python Examples

```python
import requests

BASE_URL = "http://localhost:8000"
TENANT_ID = 1

# Get user profile
response = requests.get(f"{BASE_URL}/users/me", params={"tenant_id": TENANT_ID})
user = response.json()
print(f"User: {user['name']}")

# List repositories
response = requests.get(
    f"{BASE_URL}/repositories",
    params={"tenant_id": TENANT_ID, "page": 1, "page_size": 10}
)
repos = response.json()
print(f"Found {repos['total']} repositories")

# Trigger scan
repo_id = repos['repositories'][0]['id']
response = requests.post(f"{BASE_URL}/repositories/{repo_id}/scan")
scan = response.json()
print(f"Scan started: {scan['execution_id']}")

# Get findings statistics
response = requests.get(f"{BASE_URL}/findings/stats", params={"tenant_id": TENANT_ID})
stats = response.json()
print(f"Total findings: {stats['total']}")
print(f"Critical: {stats['by_severity']['critical']}")
```

---

## Implementation Notes

- All endpoints follow RESTful conventions
- Pagination uses `page` and `page_size` parameters
- Filtering supports multiple criteria
- Tenant isolation ensures data security
- Database queries are optimized with eager loading
- Comprehensive error handling with descriptive messages
- Full backward compatibility maintained

---

## Support

For issues or questions, please contact the development team or open an issue on GitHub.
