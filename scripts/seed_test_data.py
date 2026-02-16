#!/usr/bin/env python3
"""
Seed database with test data for development and testing
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import random
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from database.models import Base, Hypothesis, Project, ScanExecution, Tenant, create_db_engine, create_db_session


def create_test_data(db: Session):
    """Create comprehensive test data"""
    print("Creating test data...")
    
    # 1. Create test tenant
    tenant = Tenant(
        id=1,
        name="Test Organization",
        created_at=datetime.now(timezone.utc) - timedelta(days=30)
    )
    db.add(tenant)
    db.flush()
    print(f"✓ Created tenant: {tenant.name}")
    
    # 2. Create projects
    projects_data = [
        {
            "name": "DeFi Protocol",
            "git_url": "https://github.com/example/defi-protocol",
            "description": "Decentralized finance lending platform"
        },
        {
            "name": "NFT Marketplace",
            "git_url": "https://github.com/example/nft-marketplace",
            "description": "NFT trading and minting platform"
        },
        {
            "name": "Token Bridge",
            "git_url": "https://github.com/example/token-bridge",
            "description": "Cross-chain token bridge"
        }
    ]
    
    projects = []
    for proj_data in projects_data:
        project = Project(
            tenant_id=tenant.id,
            name=proj_data["name"],
            git_url=proj_data["git_url"],
            description=proj_data["description"],
            status="active",
            created_at=datetime.now(timezone.utc) - timedelta(days=random.randint(5, 25))
        )
        db.add(project)
        db.flush()
        projects.append(project)
        print(f"✓ Created project: {project.name}")
    
    # 3. Create scan executions with findings
    statuses = ["completed", "completed", "completed", "running", "failed", "queued"]
    risk_levels = ["low", "medium", "high", "critical"]
    
    scan_count = 0
    finding_count = 0
    
    for project in projects:
        # Create 3 scans per project
        for i in range(3):
            status = statuses[scan_count % len(statuses)]
            risk_score = random.randint(30, 95) if status == "completed" else 0
            risk_level = random.choice(risk_levels) if status == "completed" else "low"
            
            scan = ScanExecution(
                execution_id=f"scan_{project.id}_{i}_{int(datetime.now(timezone.utc).timestamp())}",
                project_id=project.id,
                tenant_id=tenant.id,
                repo_name=project.name,
                repo_url=project.git_url,
                status=status,
                risk_score=risk_score,
                risk_level=risk_level,
                contracts_scanned=random.randint(5, 20) if status == "completed" else 0,
                contracts_total=random.randint(15, 30),
                llm_calls_made=random.randint(50, 200) if status == "completed" else 0,
                summary=f"Security scan of {project.name}" if status == "completed" else None,
                error_message="Timeout during analysis" if status == "failed" else None,
                started_at=datetime.now(timezone.utc) - timedelta(hours=random.randint(1, 72)),
                completed_at=datetime.now(timezone.utc) - timedelta(hours=random.randint(0, 48)) if status == "completed" else None,
                created_at=datetime.now(timezone.utc) - timedelta(hours=random.randint(1, 72))
            )
            db.add(scan)
            db.flush()
            scan_count += 1
            
            # Add findings for completed scans (using Hypothesis model)
            num_findings = 0
            if status == "completed":
                num_findings = random.randint(1, 4)
                findings_templates = [
                    {
                        "title": "Reentrancy Vulnerability",
                        "severity": "critical",
                        "vulnerability_type": "Smart Contract",
                        "description": "External call before state update allows reentrancy attack in contracts/Vault.sol:45",
                    },
                    {
                        "title": "Integer Overflow",
                        "severity": "high",
                        "vulnerability_type": "Smart Contract",
                        "description": "Unchecked arithmetic operation can overflow in contracts/Token.sol:128",
                    },
                    {
                        "title": "Missing Access Control",
                        "severity": "high",
                        "vulnerability_type": "Access Control",
                        "description": "Critical function lacks authorization check in contracts/Admin.sol:92",
                    },
                    {
                        "title": "Gas Optimization Opportunity",
                        "severity": "low",
                        "vulnerability_type": "Optimization",
                        "description": "Loop can be optimized to reduce gas costs in contracts/Utils.sol:67",
                    }
                ]
                
                # Generate timestamp once per scan to avoid duplicates
                scan_timestamp = int(datetime.now(timezone.utc).timestamp())
                for j in range(num_findings):
                    template = findings_templates[j % len(findings_templates)]
                    hypothesis_id = f"hyp_{scan.execution_id}_{j}_{scan_timestamp}"
                    hypothesis = Hypothesis(
                        hypothesis_id=hypothesis_id,
                        project_id=project.id,
                        title=template["title"],
                        description=template["description"],
                        vulnerability_type=template["vulnerability_type"],
                        status="confirmed",
                        confidence=random.uniform(0.7, 0.95),
                        severity=template["severity"],
                        evidence={"finding_type": "automated", "verified_by": "llm", "scan_id": scan.execution_id},
                        created_at=scan.created_at + timedelta(minutes=random.randint(5, 30))
                    )
                    db.add(hypothesis)
                    finding_count += 1
            
            print(f"✓ Created scan: {scan.execution_id} ({status}) with {num_findings} findings")
    
    db.commit()
    print("\n✅ Test data created successfully!")
    print("   - 1 tenant")
    print(f"   - {len(projects)} projects")
    print(f"   - {scan_count} scans")
    print(f"   - {finding_count} findings")

def main():
    # Get database URL from environment
    DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///hound.db")
    
    # Create engine
    engine = create_db_engine(DATABASE_URL)
    
    # Create tables
    Base.metadata.create_all(bind=engine)
    print("✓ Database tables created")
    
    # Create session
    db = create_db_session(engine)
    
    try:
        # Clear existing test data
        db.query(Hypothesis).delete()
        db.query(ScanExecution).delete()
        db.query(Project).delete()
        db.query(Tenant).delete()
        db.commit()
        print("✓ Cleared existing test data")
        
        # Create new test data
        create_test_data(db)
    finally:
        db.close()

if __name__ == "__main__":
    main()
