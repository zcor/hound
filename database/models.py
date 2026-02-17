"""
SQLAlchemy models for Hound database schema.

This module defines the database schema to replace local JSON files and directories
with a PostgreSQL relational database for better scalability and multi-tenancy support.
"""

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    TypeDecorator,
    UniqueConstraint,
    create_engine,
)
from sqlalchemy.dialects.postgresql import ARRAY as PG_ARRAY, JSONB
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

Base = declarative_base()


# Type adapter for JSON columns that uses JSONB on PostgreSQL and JSON elsewhere
class JSONType(TypeDecorator):
    """
    Platform-independent JSON type.
    
    Uses JSONB on PostgreSQL for better performance and indexing,
    falls back to JSON on other databases like SQLite for testing.
    """
    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(JSONB())
        else:
            return dialect.type_descriptor(JSON())


# Type adapter for ARRAY columns that uses PostgreSQL ARRAY or JSON elsewhere
class ArrayType(TypeDecorator):
    """
    Platform-independent array type.
    
    Uses ARRAY on PostgreSQL for native array support,
    falls back to JSON on other databases like SQLite for testing.
    """
    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(PG_ARRAY(String))
        else:
            return dialect.type_descriptor(JSON())


class Tenant(Base):
    """
    Tenant/Organization table for multi-tenancy support.
    
    Allows multiple organizations to use the same Hound instance
    with isolated data.
    """
    __tablename__ = "tenants"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False, unique=True)
    installation_id = Column(BigInteger, nullable=True, unique=True, index=True)  # GitHub App installation ID (one tenant per installation)
    status = Column(String(50), nullable=False, default="pending")  # pending, approved, active
    contact_email = Column(String(255), nullable=True)  # Email from signup flow
    github_account_login = Column(String(255), nullable=True)  # GitHub username or org name
    github_account_type = Column(String(50), nullable=True)  # "User" or "Organization"
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    projects = relationship("Project", back_populates="tenant", cascade="all, delete-orphan")
    scan_executions = relationship("ScanExecution", back_populates="tenant", cascade="all, delete-orphan")
    users = relationship("User", back_populates="tenant", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Tenant(id={self.id}, name='{self.name}')>"


class User(Base):
    """
    User table for GitHub OAuth authentication.
    
    Stores user information from GitHub OAuth for authentication
    and authorization using JWT tokens.
    """
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    github_id = Column(BigInteger, unique=True, index=True, nullable=False)
    github_login = Column(String(255), unique=True, index=True, nullable=False)
    email = Column(String(255), index=True)  # Not unique - users can have null/private emails
    name = Column(String(255))
    avatar_url = Column(String(500))
    github_token_encrypted = Column(Text, nullable=True)  # Fernet-encrypted GitHub OAuth token
    github_connected_at = Column(DateTime, nullable=True)  # When the GitHub token was stored
    github_access_token = Column(String(500), nullable=True)  # GitHub OAuth access token for API calls
    
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    tenant = relationship("Tenant", back_populates="users")
    
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f"<User(github_login='{self.github_login}', tenant_id={self.tenant_id})>"


class Team(Base):
    """
    Team table for managing repository-based team access.
    
    A Team is automatically created for each repository and synced with 
    GitHub collaborators to control access to scan results.
    """
    __tablename__ = "teams"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)  # e.g., "acme-org/api-backend Team"
    github_repo_id = Column(BigInteger, unique=True, nullable=False, index=True)  # GitHub's repo ID
    github_repo_name = Column(String(512), nullable=False)  # "acme-org/api-backend"
    last_synced_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=True, onupdate=lambda: datetime.now(timezone.utc))
    
    # Relationships
    members = relationship("TeamMember", back_populates="team", cascade="all, delete-orphan")
    repositories = relationship("Project", back_populates="team")
    
    def __repr__(self):
        return f"<Team(id={self.id}, name='{self.name}', github_repo_id={self.github_repo_id})>"


class TeamMember(Base):
    """
    TeamMember table for tracking team membership.
    
    Links users to teams with role-based access control.
    """
    __tablename__ = "team_members"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    team_id = Column(Integer, ForeignKey("teams.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(String(50), nullable=False, default="member")  # "admin", "member", "viewer"
    joined_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    team = relationship("Team", back_populates="members")
    user = relationship("User")
    
    __table_args__ = (
        UniqueConstraint('team_id', 'user_id', name='uq_team_user'),
    )
    
    def __repr__(self):
        return f"<TeamMember(id={self.id}, team_id={self.team_id}, user_id={self.user_id}, role='{self.role}')>"


class Project(Base):
    """
    Project table corresponding to project.json and registry.json.
    
    Stores project metadata including:
    - name: Project identifier
    - source_path/git_url: Path to source code or git repository
    - description: Project description
    - status: Project status (active, archived, etc.)
    """
    __tablename__ = "projects"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    name = Column(String(255), nullable=False, index=True)

    # Project names must be unique within a tenant, not globally
    __table_args__ = (
        UniqueConstraint('tenant_id', 'name', name='uq_project_tenant_name'),
    )
    source_path = Column(String(1024), nullable=True)  # Local path
    git_url = Column(String(1024), nullable=True)  # Git repository URL
    github_repo_id = Column(BigInteger, nullable=True, index=True)  # GitHub repository ID
    installation_id = Column(BigInteger, nullable=True, index=True)  # GitHub App installation ID
    full_name = Column(String(512), nullable=True)  # owner/repo format
    default_branch = Column(String(255), nullable=True, default="main")
    is_private = Column(Boolean, nullable=False, default=False)
    description = Column(Text, nullable=True)
    status = Column(String(50), nullable=False, default="active")
    team_id = Column(Integer, ForeignKey("teams.id"), nullable=True, index=True)  # Link to team for access control
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_accessed = Column(DateTime, nullable=False, default=datetime.utcnow)
    
    # Relationships
    tenant = relationship("Tenant", back_populates="projects")
    team = relationship("Team", back_populates="repositories")
    audit_sessions = relationship("AuditSession", back_populates="project", cascade="all, delete-orphan")
    graphs = relationship("Graph", back_populates="project", cascade="all, delete-orphan")
    hypotheses = relationship("Hypothesis", back_populates="project", cascade="all, delete-orphan")
    scan_executions = relationship("ScanExecution", back_populates="project", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Project(id={self.id}, name='{self.name}', status='{self.status}')>"


class AuditSession(Base):
    """
    AuditSession table corresponding to SessionInfo in session_manager.py.
    
    Tracks audit sessions with:
    - session_id: Unique session identifier
    - status: Session status (active, completed, interrupted)
    - start_time, end_time: Session timing
    - models: LLM models used (stored as JSON)
    - token_usage: Token usage statistics (stored as JSON)
    - coverage: Code coverage statistics (stored as JSON)
    - investigations: Investigation details (stored as JSON)
    """
    __tablename__ = "audit_sessions"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=True)  # Optional - can be set later
    session_id = Column(String(255), nullable=False, unique=True, index=True)
    status = Column(String(50), nullable=False, default="active")
    start_time = Column(DateTime, nullable=False, default=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    
    # JSON fields for flexible data storage
    models = Column(JSONType, nullable=True)  # LLM models used (scout, strategist, etc.)
    token_usage = Column(JSONType, nullable=True)  # Token usage statistics
    coverage = Column(JSONType, nullable=True)  # Code coverage statistics
    investigations = Column(JSONType, nullable=True)  # Investigation details
    session_metadata = Column(JSONType, nullable=True)  # Additional metadata
    
    # Relationships
    project = relationship("Project", back_populates="audit_sessions")
    
    def __repr__(self):
        return f"<AuditSession(id={self.id}, session_id='{self.session_id}', status='{self.status}')>"


class Graph(Base):
    """
    Graph table to store JSON graph data from graphs/*.json files.
    
    Stores knowledge graph data including:
    - name: Graph display name
    - internal_name: Internal identifier
    - data: Complete graph structure (nodes, edges, metadata) as JSONB
    """
    __tablename__ = "graphs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    name = Column(String(255), nullable=False)
    internal_name = Column(String(255), nullable=True)
    data = Column(JSONType, nullable=False)  # Complete graph structure
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    project = relationship("Project", back_populates="graphs")
    
    def __repr__(self):
        return f"<Graph(id={self.id}, name='{self.name}', project_id={self.project_id})>"


class Hypothesis(Base):
    """
    Hypothesis table to replace hypotheses.json.
    
    Stores vulnerability hypotheses with:
    - hypothesis_id: Unique identifier (e.g., hyp_20250115_123456_abc123)
    - title: Hypothesis title
    - description: Detailed description
    - vulnerability_type: Type of vulnerability
    - status: Hypothesis status (proposed, investigating, supported, confirmed, rejected, refuted)
    - confidence: Confidence score (0.0-1.0)
    - severity: Severity level (critical, high, medium, low)
    - node_refs: Array of node IDs referenced
    - evidence: Evidence data (stored as JSONB)
    - reported_by_model: LLM model that reported this
    - junior_model, senior_model: Junior and senior LLM models
    """
    __tablename__ = "hypotheses"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    hypothesis_id = Column(String(255), nullable=False, unique=True, index=True)
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=False)
    vulnerability_type = Column(String(255), nullable=False)
    status = Column(String(50), nullable=False, default="proposed")
    confidence = Column(Float, nullable=False, default=0.5)
    severity = Column(String(50), nullable=False, default="medium")
    node_refs = Column(ArrayType, nullable=True)  # Array of node IDs
    evidence = Column(JSONType, nullable=True)  # Evidence data
    reported_by_model = Column(String(255), nullable=True)
    junior_model = Column(String(255), nullable=True)
    senior_model = Column(String(255), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    project = relationship("Project", back_populates="hypotheses")
    
    def __repr__(self):
        return f"<Hypothesis(id={self.id}, hypothesis_id='{self.hypothesis_id}', title='{self.title}', status='{self.status}')>"


class ScanExecution(Base):
    """
    ScanExecution table for Surface Scan results.
    
    Stores lightweight surface scan execution data for lead generation:
    - execution_id: Unique identifier for the scan execution
    - repo_url/repo_name: Repository identification
    - risk_score/risk_level: Calculated risk assessment
    - findings: Detected vulnerabilities and quality issues (stored as JSONB)
    - quality_metrics: Code quality indicators (stored as JSONB)
    - scan_config: Configuration used for the scan (stored as JSONB)
    - artifacts_path: S3/blob path to full scan artifacts
    """
    __tablename__ = "scan_executions"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=True)  # Optional link to full project
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    
    # Scan identification
    execution_id = Column(String(255), nullable=False, unique=True, index=True)
    repo_url = Column(String(1024), nullable=True)  # GitHub URL if applicable
    repo_name = Column(String(255), nullable=False, index=True)
    
    # Scan results
    status = Column(String(50), nullable=False, default="pending")  # pending, running, completed, failed
    risk_score = Column(Integer, nullable=True)  # 0-100 risk score
    risk_level = Column(String(50), nullable=True)  # critical, high, medium, low
    
    # Detailed findings and metrics (JSONB for flexibility)
    findings = Column(JSONType, nullable=True)  # List of Finding objects
    quality_metrics = Column(JSONType, nullable=True)  # QualityMetrics object
    summary = Column(Text, nullable=True)  # Human-readable summary
    
    # Scan configuration and metadata
    scan_config = Column(JSONType, nullable=True)  # llm_budget, model, patterns enabled, etc.
    llm_calls_made = Column(Integer, nullable=False, default=0)
    contracts_scanned = Column(Integer, nullable=False, default=0)
    contracts_total = Column(Integer, nullable=False, default=0)
    
    # Artifact storage reference (S3/MinIO path for full reports, code snippets, etc.)
    artifacts_path = Column(String(1024), nullable=True)
    
    # Error handling
    error_message = Column(Text, nullable=True)
    
    # Timing
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    project = relationship("Project", back_populates="scan_executions")
    tenant = relationship("Tenant", back_populates="scan_executions")
    
    def __repr__(self):
        return f"<ScanExecution(id={self.id}, execution_id='{self.execution_id}', repo='{self.repo_name}', status='{self.status}')>"


class TokenUsageLog(Base):
    """
    TokenUsageLog table for tracking LLM token usage and costs.
    
    Stores per-request token usage for cost analysis:
    - project_id: Link to project (optional for system-wide tracking)
    - session_id: Link to audit session (optional)
    - provider: LLM provider (openai, anthropic, google, etc.)
    - model: Specific model used (gpt-4o, claude-3-opus, etc.)
    - profile: Usage profile (agent, graph, guidance, finalize, etc.)
    - input_tokens, output_tokens: Token counts
    - cost_usd: Calculated cost in USD
    """
    __tablename__ = "token_usage_logs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=True)
    session_id = Column(String(255), nullable=True, index=True)  # Audit session ID
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True)
    
    # Provider and model info
    provider = Column(String(100), nullable=False, index=True)  # openai, anthropic, google, deepseek, xai
    model = Column(String(255), nullable=False, index=True)  # gpt-4o, claude-3-opus, etc.
    profile = Column(String(100), nullable=True, index=True)  # agent, graph, guidance, finalize, scout, strategist
    
    # Token counts
    input_tokens = Column(Integer, nullable=False, default=0)
    output_tokens = Column(Integer, nullable=False, default=0)
    total_tokens = Column(Integer, nullable=False, default=0)
    
    # Cost calculation (in USD)
    cost_usd = Column(Float, nullable=True)  # Calculated cost based on model pricing
    
    # Request context
    request_type = Column(String(100), nullable=True)  # raw, structured, stream
    endpoint = Column(String(255), nullable=True)  # API endpoint that triggered this
    
    # Timing
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    
    # Relationships
    project = relationship("Project", backref="token_usage_logs")
    tenant = relationship("Tenant", backref="token_usage_logs")
    
    def __repr__(self):
        return f"<TokenUsageLog(id={self.id}, model='{self.model}', tokens={self.total_tokens}, cost=${self.cost_usd or 0:.4f})>"


# Model pricing table (per 1M tokens) - Updated January 2026
MODEL_PRICING = {
    # OpenAI
    "gpt-4o": {"input": 2.50, "output": 10.00},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "gpt-4-turbo": {"input": 10.00, "output": 30.00},
    "gpt-4": {"input": 30.00, "output": 60.00},
    "gpt-3.5-turbo": {"input": 0.50, "output": 1.50},
    "o1": {"input": 15.00, "output": 60.00},
    "o1-mini": {"input": 3.00, "output": 12.00},
    "o1-preview": {"input": 15.00, "output": 60.00},
    # Anthropic
    "claude-3-opus": {"input": 15.00, "output": 75.00},
    "claude-3-sonnet": {"input": 3.00, "output": 15.00},
    "claude-3-haiku": {"input": 0.25, "output": 1.25},
    "claude-3-5-sonnet": {"input": 3.00, "output": 15.00},
    "claude-3-5-haiku": {"input": 0.80, "output": 4.00},
    "claude-sonnet-4": {"input": 3.00, "output": 15.00},
    "claude-opus-4": {"input": 15.00, "output": 75.00},
    # Google
    "gemini-1.5-pro": {"input": 1.25, "output": 5.00},
    "gemini-1.5-flash": {"input": 0.075, "output": 0.30},
    "gemini-2.0-flash": {"input": 0.10, "output": 0.40},
    # DeepSeek
    "deepseek-chat": {"input": 0.14, "output": 0.28},
    "deepseek-coder": {"input": 0.14, "output": 0.28},
    "deepseek-reasoner": {"input": 0.55, "output": 2.19},
    # xAI
    "grok-beta": {"input": 5.00, "output": 15.00},
    "grok-2": {"input": 2.00, "output": 10.00},
}


def calculate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Calculate cost in USD for a given model and token counts."""
    # Normalize model name (handle variations)
    model_lower = model.lower()
    
    # Find matching pricing
    pricing = None
    for model_key, prices in MODEL_PRICING.items():
        if model_key in model_lower or model_lower in model_key:
            pricing = prices
            break
    
    if not pricing:
        # Default fallback pricing (conservative estimate)
        pricing = {"input": 1.00, "output": 3.00}
    
    # Calculate cost (prices are per 1M tokens)
    input_cost = (input_tokens / 1_000_000) * pricing["input"]
    output_cost = (output_tokens / 1_000_000) * pricing["output"]
    
    return round(input_cost + output_cost, 6)


# Database connection helper
def create_db_engine(database_url: str, echo: bool = False):
    """
    Create a SQLAlchemy engine for the database with connection pooling.
    
    Args:
        database_url: PostgreSQL connection URL (e.g., postgresql://user:pass@localhost/dbname)
        echo: Whether to echo SQL statements (useful for debugging)
    
    Returns:
        SQLAlchemy Engine instance
    """
    kwargs = dict(
        echo=echo,
        pool_pre_ping=True,    # Verify connections before use
        pool_recycle=1800,     # Recycle connections after 30 minutes
    )

    # SQLite uses SingletonThreadPool which doesn't support these parameters;
    # they are only valid for QueuePool (used by PostgreSQL, MySQL, etc.)
    if not database_url.startswith("sqlite"):
        kwargs.update(
            pool_size=5,       # Base pool size
            max_overflow=10,   # Allow up to 15 total connections (5 + 10)
            pool_timeout=30,   # Wait up to 30s for a connection
        )

    return create_engine(database_url, **kwargs)


def create_db_session(engine):
    """
    Create a database session.
    
    Args:
        engine: SQLAlchemy Engine instance
    
    Returns:
        SQLAlchemy Session instance
    """
    Session = sessionmaker(bind=engine)
    return Session()


def init_database(engine):
    """
    Initialize the database by creating all tables.
    
    Args:
        engine: SQLAlchemy Engine instance
    """
    Base.metadata.create_all(engine)


def drop_all_tables(engine):
    """
    Drop all tables from the database.
    
    Warning: This will delete all data!
    
    Args:
        engine: SQLAlchemy Engine instance
    """
    Base.metadata.drop_all(engine)
