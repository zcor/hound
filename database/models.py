"""
SQLAlchemy models for Hound database schema.

This module defines the database schema to replace local JSON files and directories
with a PostgreSQL relational database for better scalability and multi-tenancy support.
"""

from datetime import datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    TypeDecorator,
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
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    projects = relationship("Project", back_populates="tenant", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Tenant(id={self.id}, name='{self.name}')>"


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
    name = Column(String(255), nullable=False, unique=True, index=True)
    source_path = Column(String(1024), nullable=True)  # Local path
    git_url = Column(String(1024), nullable=True)  # Git repository URL
    github_repo_id = Column(BigInteger, nullable=True, index=True)  # GitHub repository ID
    installation_id = Column(BigInteger, nullable=True, index=True)  # GitHub App installation ID
    description = Column(Text, nullable=True)
    status = Column(String(50), nullable=False, default="active")
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_accessed = Column(DateTime, nullable=False, default=datetime.utcnow)
    
    # Relationships
    tenant = relationship("Tenant", back_populates="projects")
    audit_sessions = relationship("AuditSession", back_populates="project", cascade="all, delete-orphan")
    graphs = relationship("Graph", back_populates="project", cascade="all, delete-orphan")
    hypotheses = relationship("Hypothesis", back_populates="project", cascade="all, delete-orphan")
    
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
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
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


# Database connection helper
def create_db_engine(database_url: str, echo: bool = False):
    """
    Create a SQLAlchemy engine for the database.
    
    Args:
        database_url: PostgreSQL connection URL (e.g., postgresql://user:pass@localhost/dbname)
        echo: Whether to echo SQL statements (useful for debugging)
    
    Returns:
        SQLAlchemy Engine instance
    """
    return create_engine(database_url, echo=echo)


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
