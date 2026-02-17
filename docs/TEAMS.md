# Team-Based Access System

This document describes the team-based access control system for Hound, which automatically synchronizes repository collaborators from GitHub to manage access to scan results.

## Overview

The team-based access system provides automatic access control for repository scan results based on GitHub repository collaborators. When a user adds a GitHub repository to Hound, they can sync the collaborators to create a team, ensuring that all contributors have appropriate access to security findings.

## Key Features

- **Automatic Team Creation**: Teams are automatically created based on GitHub repositories
- **Collaborator Sync**: GitHub collaborators are synced as team members
- **Role-Based Access**: Team members have roles (admin, member, viewer) based on their GitHub permissions
- **Access Control**: Only team members can view scan results and findings
- **Real-time Sync**: Teams can be re-synced at any time to reflect changes in GitHub collaborators

## Architecture

### Database Models

#### Team Model

The `Team` model represents a team associated with a GitHub repository:

```python
class Team(Base):
    __tablename__ = "teams"
    
    id: int                          # Primary key
    name: str                        # Display name (e.g., "owner/repo Team")
    github_repo_id: int              # GitHub's repository ID (unique)
    github_repo_name: str            # Full repository name (e.g., "owner/repo")
    last_synced_at: datetime         # Last sync timestamp
    created_at: datetime             # Team creation timestamp
    updated_at: datetime             # Last update timestamp
```

#### TeamMember Model

The `TeamMember` model links users to teams:

```python
class TeamMember(Base):
    __tablename__ = "team_members"
    
    id: int                          # Primary key
    team_id: int                     # Foreign key to teams
    user_id: int                     # Foreign key to users
    role: str                        # "admin", "member", or "viewer"
    joined_at: datetime              # When user joined the team
```

#### Repository-Team Link

Projects (repositories) are linked to teams via the `team_id` foreign key:

```python
class Project(Base):
    # ... other fields ...
    team_id: int                     # Foreign key to teams (nullable)
    team: relationship("Team")       # Relationship to Team model
```

### GitHub Service

The `GitHubService` class provides methods for interacting with the GitHub API:

- `get_repo_details(owner, repo)` - Fetch repository metadata
- `get_repo_collaborators(owner, repo)` - Fetch all collaborators with permissions
- `check_user_access(owner, repo, username)` - Check if a user has access

The `parse_github_url()` helper function extracts owner/repo from various GitHub URL formats.

## API Endpoints

### POST /repositories/{repo_id}/sync-team

Synchronize team members from GitHub repository collaborators.

**Authentication**: Required (JWT token)

**Request**: No body required

**Response**:
```json
{
  "team_id": 1,
  "team_name": "owner/repo Team",
  "github_repo_name": "owner/repo",
  "members_count": 3,
  "members": [
    {
      "github_login": "user1",
      "avatar_url": "https://...",
      "role": "admin"
    },
    {
      "github_login": "user2",
      "avatar_url": "https://...",
      "role": "member"
    }
  ]
}
```

**Behavior**:
1. Fetches all collaborators from GitHub API
2. Creates or updates the Team record
3. Creates stub User records for collaborators not yet in the system
4. Adds users to the team with appropriate roles
5. Links the repository to the team

**Error Codes**:
- `401` - Not authenticated or missing GitHub token
- `403` - User doesn't have access to the repository
- `404` - Repository not found
- `500` - GitHub API error

### GET /teams/{team_id}/members

Get all members of a team.

**Authentication**: Required (JWT token)

**Authorization**: User must be a member of the team

**Response**:
```json
{
  "team": {
    "id": 1,
    "name": "owner/repo Team",
    "github_repo_name": "owner/repo",
    "last_synced_at": "2024-01-15T12:00:00Z"
  },
  "members": [
    {
      "id": 1,
      "user_id": 123,
      "github_login": "user1",
      "github_avatar_url": "https://...",
      "email": "user1@example.com",
      "role": "admin",
      "joined_at": "2024-01-15T12:00:00Z"
    }
  ]
}
```

**Error Codes**:
- `401` - Not authenticated
- `403` - User is not a member of the team
- `404` - Team not found

## Usage Guide

### Initial Setup

1. **Add Repository**: User adds a GitHub repository to Hound
2. **Sync Team**: User calls the sync endpoint to create the team
3. **Access Control**: Team members can now access scan results

### Syncing Collaborators

To sync collaborators:

```bash
curl -X POST https://api.hound.example.com/repositories/123/sync-team \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

This will:
- Fetch current collaborators from GitHub
- Add new collaborators to the team
- Update roles for existing members
- Create user accounts for new collaborators

### Viewing Team Members

To view team members:

```bash
curl https://api.hound.example.com/teams/1/members \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Re-syncing

Teams can be re-synced at any time to reflect changes in GitHub collaborators:

- When a collaborator is added to the GitHub repository
- When a collaborator's permissions change
- When a collaborator is removed from the GitHub repository

Note: Currently, removing a collaborator from GitHub does not automatically remove them from the team. This is by design to preserve audit history.

## Security Considerations

### OAuth Scopes

The GitHub OAuth flow requires the `repo` scope to access repository collaborators:

```python
GITHUB_SCOPES = "user:email repo"
```

This allows Hound to:
- Read repository metadata
- List repository collaborators
- Check user access to repositories

### Access Token Storage

User GitHub access tokens are stored in two forms:

1. **Encrypted Token** (`github_token_encrypted`): Fernet-encrypted for secure storage
2. **Plain Token** (`github_access_token`): For API calls (should be encrypted in production)

**Production Recommendation**: Encrypt the `github_access_token` field or use a secrets management service.

### Authorization Flow

1. User authenticates via GitHub OAuth
2. Access token is stored in the User model
3. When syncing teams, the token is used to call GitHub API
4. User must have collaborator access to sync a repository
5. Only team members can view team information

### Rate Limiting

GitHub API rate limits:
- **Authenticated requests**: 5,000 requests per hour
- **Unauthenticated requests**: 60 requests per hour

The `last_synced_at` timestamp can be used to implement caching and avoid unnecessary API calls.

## Database Migration

To apply the database migration:

```bash
# PostgreSQL
psql -h localhost -U hound -d hound < database/migrations/add_teams_and_team_members.sql

# SQLite (development)
sqlite3 hound.db < database/migrations/add_teams_and_team_members.sql
```

Or using SQLAlchemy:

```python
from database.models import Base, create_db_engine

engine = create_db_engine("postgresql://...")
Base.metadata.create_all(engine)
```

## Testing

Run the team tests:

```bash
pytest tests/test_teams.py -v
```

Tests cover:
- Team and TeamMember model creation
- Team sync endpoint with mocked GitHub API
- Team members endpoint authorization
- GitHub URL parsing helper functions

## Future Enhancements

Potential improvements for the team system:

1. **Automatic Removal**: Remove team members when they're removed from GitHub
2. **Role Mapping**: More granular role mapping from GitHub permissions
3. **Team Invitations**: Allow team admins to invite non-collaborators
4. **Team Activity Log**: Track team changes and access history
5. **Multiple Teams**: Allow repositories to belong to multiple teams
6. **Team Settings**: Configurable team permissions and notification preferences
7. **Webhook Integration**: Automatic sync via GitHub webhooks

## Troubleshooting

### "GitHub access token not found"

**Cause**: User hasn't authenticated with GitHub or token has expired

**Solution**: User needs to re-authenticate via GitHub OAuth

### "You need admin access to this repository"

**Cause**: User doesn't have admin access to fetch collaborators

**Solution**: Only repository admins can sync teams. Use a service account or grant admin access.

### "Invalid GitHub URL"

**Cause**: Repository URL is not a valid GitHub URL

**Solution**: Ensure the repository URL follows one of these formats:
- `https://github.com/owner/repo`
- `git@github.com:owner/repo.git`

### Rate Limit Errors

**Cause**: Exceeded GitHub API rate limit

**Solution**: 
- Wait for rate limit to reset (shown in error response)
- Implement caching using `last_synced_at`
- Use GitHub App authentication for higher limits

## API Examples

### Python

```python
import httpx

# Sync team from repository collaborators
async def sync_team(repo_id: int, token: str):
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"https://api.hound.example.com/repositories/{repo_id}/sync-team",
            headers={"Authorization": f"Bearer {token}"}
        )
        return response.json()

# Get team members
async def get_team_members(team_id: int, token: str):
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"https://api.hound.example.com/teams/{team_id}/members",
            headers={"Authorization": f"Bearer {token}"}
        )
        return response.json()
```

### JavaScript

```javascript
// Sync team from repository collaborators
async function syncTeam(repoId, token) {
  const response = await fetch(
    `https://api.hound.example.com/repositories/${repoId}/sync-team`,
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    }
  );
  return response.json();
}

// Get team members
async function getTeamMembers(teamId, token) {
  const response = await fetch(
    `https://api.hound.example.com/teams/${teamId}/members`,
    {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    }
  );
  return response.json();
}
```

## Related Documentation

- [GitHub OAuth Documentation](https://docs.github.com/en/developers/apps/building-oauth-apps)
- [GitHub API - Collaborators](https://docs.github.com/en/rest/collaborators)
- [Hound Security Documentation](SECURITY.md)
- [Hound API Documentation](API.md)
