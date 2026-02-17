"""
Tests for team-based access control functionality.
"""

import os
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database.models import Base, Project, Team, TeamMember, Tenant, User
from server.auth_utils import create_access_token

# Set test database URL before importing app
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from server.api import app, get_db


# Test database setup
@pytest.fixture(scope="function")
def test_db(tmp_path):
    """Create a test database using SQLite in a temp file."""
    db_path = tmp_path / "test.db"
    db_url = f"sqlite:///{db_path}"
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    # Create tables
    Base.metadata.create_all(bind=engine)

    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(test_db):
    """Create a test client with dependency override."""

    def override_get_db():
        try:
            yield test_db
        finally:
            pass

    def override_get_engine():
        return test_db.get_bind()

    app.dependency_overrides[get_db] = override_get_db
    import server.api as api_module
    original_get_engine = api_module.get_engine
    original_engine = api_module._engine
    
    api_module._engine = test_db.get_bind()
    api_module.get_engine = override_get_engine
    
    with TestClient(app) as test_client:
        yield test_client
    
    app.dependency_overrides.clear()
    api_module.get_engine = original_get_engine
    api_module._engine = original_engine


@pytest.fixture
def sample_tenant(test_db):
    """Create a sample tenant for testing."""
    tenant = Tenant(name="test_organization")
    test_db.add(tenant)
    test_db.commit()
    test_db.refresh(tenant)
    return tenant


@pytest.fixture
def sample_user(test_db, sample_tenant):
    """Create a sample user for testing."""
    user = User(
        github_id=12345678,
        github_login="testuser",
        email="test@example.com",
        name="Test User",
        avatar_url="https://avatars.githubusercontent.com/u/12345678",
        tenant_id=sample_tenant.id,
        github_access_token="ghp_test_token_12345"
    )
    test_db.add(user)
    test_db.commit()
    test_db.refresh(user)
    return user


@pytest.fixture
def sample_project(test_db, sample_tenant):
    """Create a sample project for testing."""
    project = Project(
        tenant_id=sample_tenant.id,
        name="test-repo",
        full_name="testorg/test-repo",
        git_url="https://github.com/testorg/test-repo",
        github_repo_id=987654321,
        default_branch="main",
        is_private=False,
        status="active"
    )
    test_db.add(project)
    test_db.commit()
    test_db.refresh(project)
    return project


@pytest.fixture
def auth_headers(sample_user):
    """Create authentication headers with JWT token."""
    token = create_access_token({
        "user_id": sample_user.id,
        "tenant_id": sample_user.tenant_id,
        "github_login": sample_user.github_login
    })
    return {"Authorization": f"Bearer {token}"}


class TestTeamModels:
    """Test Team and TeamMember database models."""
    
    def test_create_team(self, test_db):
        """Test creating a team."""
        team = Team(
            name="testorg/test-repo Team",
            github_repo_id=123456789,
            github_repo_name="testorg/test-repo"
        )
        test_db.add(team)
        test_db.commit()
        test_db.refresh(team)
        
        assert team.id is not None
        assert team.name == "testorg/test-repo Team"
        assert team.github_repo_id == 123456789
    
    def test_create_team_member(self, test_db, sample_user):
        """Test creating a team member."""
        team = Team(
            name="testorg/test-repo Team",
            github_repo_id=123456789,
            github_repo_name="testorg/test-repo"
        )
        test_db.add(team)
        test_db.commit()
        test_db.refresh(team)
        
        team_member = TeamMember(
            team_id=team.id,
            user_id=sample_user.id,
            role="admin"
        )
        test_db.add(team_member)
        test_db.commit()
        test_db.refresh(team_member)
        
        assert team_member.id is not None
        assert team_member.team_id == team.id
        assert team_member.user_id == sample_user.id
        assert team_member.role == "admin"
    
    def test_team_member_unique_constraint(self, test_db, sample_user):
        """Test that team_id and user_id combination is unique."""
        team = Team(
            name="testorg/test-repo Team",
            github_repo_id=123456789,
            github_repo_name="testorg/test-repo"
        )
        test_db.add(team)
        test_db.commit()
        test_db.refresh(team)
        
        # Add first team member
        team_member1 = TeamMember(
            team_id=team.id,
            user_id=sample_user.id,
            role="admin"
        )
        test_db.add(team_member1)
        test_db.commit()
        
        # Try to add duplicate - should fail
        team_member2 = TeamMember(
            team_id=team.id,
            user_id=sample_user.id,
            role="member"
        )
        test_db.add(team_member2)
        
        with pytest.raises(Exception):  # SQLAlchemy will raise IntegrityError
            test_db.commit()


class TestTeamSyncEndpoint:
    """Test the team sync endpoint."""
    
    @patch("server.services.github_service.GitHubService.check_user_access")
    @patch("server.services.github_service.GitHubService.get_repo_details")
    @patch("server.services.github_service.GitHubService.get_repo_collaborators")
    def test_sync_team_creates_team_and_members(
        self, 
        mock_get_collaborators,
        mock_get_repo_details,
        mock_check_user_access,
        client, 
        test_db,
        sample_user,
        sample_project,
        auth_headers
    ):
        """Test that syncing team creates team and members."""
        # Mock GitHub API responses
        mock_check_user_access.return_value = True
        mock_get_repo_details.return_value = {
            "id": 987654321,
            "name": "test-repo",
            "full_name": "testorg/test-repo",
            "private": False
        }
        mock_get_collaborators.return_value = [
            {
                "login": "testuser",
                "id": 12345678,
                "avatar_url": "https://avatars.githubusercontent.com/u/12345678",
                "permissions": {"admin": True, "push": True, "pull": True}
            },
            {
                "login": "collaborator1",
                "id": 87654321,
                "avatar_url": "https://avatars.githubusercontent.com/u/87654321",
                "permissions": {"admin": False, "push": True, "pull": True}
            }
        ]
        
        # Sync team
        response = client.post(
            f"/repositories/{sample_project.id}/sync-team",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "team_id" in data
        assert "team_name" in data
        assert data["members_count"] == 2
        assert len(data["members"]) == 2
        
        # Verify team was created in database
        team = test_db.query(Team).filter_by(github_repo_id=987654321).first()
        assert team is not None
        assert team.github_repo_name == "testorg/test-repo"
        
        # Verify team members were created
        members = test_db.query(TeamMember).filter_by(team_id=team.id).all()
        assert len(members) == 2
    
    def test_sync_team_requires_authentication(self, client, sample_project):
        """Test that syncing team requires authentication."""
        response = client.post(f"/repositories/{sample_project.id}/sync-team")
        assert response.status_code == 401
    
    def test_sync_team_requires_github_token(
        self, 
        client, 
        test_db,
        sample_user,
        sample_project,
        auth_headers
    ):
        """Test that syncing team requires GitHub access token."""
        # Remove GitHub access token
        sample_user.github_access_token = None
        test_db.commit()
        
        response = client.post(
            f"/repositories/{sample_project.id}/sync-team",
            headers=auth_headers
        )
        
        assert response.status_code == 401
        assert "GitHub access token not found" in response.json()["detail"]
    
    def test_sync_team_repository_not_found(self, client, auth_headers):
        """Test syncing team for non-existent repository."""
        response = client.post(
            "/repositories/99999/sync-team",
            headers=auth_headers
        )
        
        assert response.status_code == 404
        assert "Repository not found" in response.json()["detail"]


class TestTeamMembersEndpoint:
    """Test the team members endpoint."""
    
    def test_get_team_members(
        self, 
        client, 
        test_db,
        sample_user,
        auth_headers
    ):
        """Test getting team members."""
        # Create team
        team = Team(
            name="testorg/test-repo Team",
            github_repo_id=123456789,
            github_repo_name="testorg/test-repo"
        )
        test_db.add(team)
        test_db.commit()
        test_db.refresh(team)
        
        # Add user as team member
        team_member = TeamMember(
            team_id=team.id,
            user_id=sample_user.id,
            role="admin"
        )
        test_db.add(team_member)
        test_db.commit()
        
        # Get team members
        response = client.get(
            f"/teams/{team.id}/members",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "team" in data
        assert "members" in data
        assert data["team"]["id"] == team.id
        assert len(data["members"]) == 1
        assert data["members"][0]["github_login"] == "testuser"
    
    def test_get_team_members_requires_authentication(self, client, test_db):
        """Test that getting team members requires authentication."""
        team = Team(
            name="testorg/test-repo Team",
            github_repo_id=123456789,
            github_repo_name="testorg/test-repo"
        )
        test_db.add(team)
        test_db.commit()
        test_db.refresh(team)
        
        response = client.get(f"/teams/{team.id}/members")
        assert response.status_code == 401
    
    def test_get_team_members_requires_membership(
        self, 
        client, 
        test_db,
        sample_user,
        auth_headers
    ):
        """Test that user must be a team member to view members."""
        # Create team without adding user as member
        team = Team(
            name="testorg/test-repo Team",
            github_repo_id=123456789,
            github_repo_name="testorg/test-repo"
        )
        test_db.add(team)
        test_db.commit()
        test_db.refresh(team)
        
        response = client.get(
            f"/teams/{team.id}/members",
            headers=auth_headers
        )
        
        assert response.status_code == 403
        assert "not a member" in response.json()["detail"]
    
    def test_get_team_members_team_not_found(self, client, auth_headers):
        """Test getting members for non-existent team."""
        response = client.get(
            "/teams/99999/members",
            headers=auth_headers
        )
        
        assert response.status_code == 404
        assert "Team not found" in response.json()["detail"]


class TestGitHubServiceHelpers:
    """Test GitHub service helper functions."""
    
    def test_parse_github_url_https(self):
        """Test parsing HTTPS GitHub URL."""
        from server.services.github_service import parse_github_url
        
        owner, repo = parse_github_url("https://github.com/owner/repo")
        assert owner == "owner"
        assert repo == "repo"
    
    def test_parse_github_url_https_with_git(self):
        """Test parsing HTTPS GitHub URL with .git extension."""
        from server.services.github_service import parse_github_url
        
        owner, repo = parse_github_url("https://github.com/owner/repo.git")
        assert owner == "owner"
        assert repo == "repo"
    
    def test_parse_github_url_ssh(self):
        """Test parsing SSH GitHub URL."""
        from server.services.github_service import parse_github_url
        
        owner, repo = parse_github_url("git@github.com:owner/repo.git")
        assert owner == "owner"
        assert repo == "repo"
    
    def test_parse_github_url_invalid(self):
        """Test parsing invalid GitHub URL."""
        from server.services.github_service import parse_github_url
        
        with pytest.raises(ValueError, match="Invalid GitHub URL"):
            parse_github_url("https://gitlab.com/owner/repo")
        
        with pytest.raises(ValueError, match="Invalid GitHub URL"):
            parse_github_url("not-a-url")
