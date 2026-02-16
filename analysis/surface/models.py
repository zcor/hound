"""Data models for surface scan results."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class Finding(BaseModel):
    """A potential vulnerability or quality issue found during scanning."""

    pattern_id: str = Field(description="Unique pattern identifier (e.g., REENTRANCY-001)")
    title: str = Field(description="Human-readable title of the finding")
    severity: Literal["critical", "high", "medium", "low"] = Field(description="Severity level")
    category: Literal["vulnerability", "quality"] = Field(description="Finding category")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score 0.0-1.0")
    location: str = Field(description="File path and line number (e.g., src/Vault.sol:42)")
    code_snippet: str = Field(description="Relevant code snippet")
    description: str = Field(description="Detailed description of the issue")
    llm_verified: bool = Field(default=False, description="Whether LLM has verified this finding")
    llm_notes: str | None = Field(default=None, description="Notes from LLM verification")


class QualityMetrics(BaseModel):
    """Code quality metrics for a repository."""

    solidity_version: str | None = Field(default=None, description="Detected Solidity version")
    vyper_version: str | None = Field(default=None, description="Detected Vyper version")
    has_tests: bool = Field(default=False, description="Whether tests were detected")
    test_count: int = Field(default=0, description="Number of test files found")
    has_natspec: bool = Field(default=False, description="Whether NatSpec documentation exists")
    contract_count: int = Field(default=0, description="Number of contracts found")
    total_loc: int = Field(default=0, description="Total lines of code")
    has_events: bool = Field(default=False, description="Whether events are used")
    uses_safemath: bool = Field(default=False, description="Whether SafeMath is used (pre-0.8)")
    has_access_control: bool = Field(default=False, description="Whether access control patterns detected")


class ScanResult(BaseModel):
    """Result of scanning a single repository."""

    repo_url: str | None = Field(default=None, description="GitHub URL if applicable")
    repo_path: str = Field(description="Local path to repository")
    repo_name: str = Field(description="Repository name for display")
    scan_timestamp: datetime = Field(default_factory=datetime.now, description="When scan was performed")
    risk_score: int = Field(ge=0, le=100, description="Overall risk score 0-100")
    risk_level: Literal["critical", "high", "medium", "low"] = Field(description="Risk level category")
    findings: list[Finding] = Field(default_factory=list, description="List of findings")
    quality_metrics: QualityMetrics = Field(default_factory=QualityMetrics, description="Quality metrics")
    contracts_scanned: int = Field(default=0, description="Number of contracts analyzed")
    contracts_total: int = Field(default=0, description="Total contracts in repo")
    llm_calls_used: int = Field(default=0, description="Number of LLM calls made")
    scan_duration_seconds: float = Field(default=0.0, description="Scan duration in seconds")
    summary: str = Field(default="", description="LLM-generated summary")
    error: str | None = Field(default=None, description="Error message if scan failed")

    @property
    def finding_counts(self) -> dict[str, int]:
        """Count findings by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    def to_csv_row(self) -> dict:
        """Convert to CSV-compatible dictionary."""
        counts = self.finding_counts
        return {
            "repo_url": self.repo_url or "",
            "repo_name": self.repo_name,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "critical_count": counts["critical"],
            "high_count": counts["high"],
            "medium_count": counts["medium"],
            "low_count": counts["low"],
            "total_findings": len(self.findings),
            "contracts_scanned": self.contracts_scanned,
            "has_tests": self.quality_metrics.has_tests,
            "solidity_version": self.quality_metrics.solidity_version or "",
            "scan_duration_seconds": round(self.scan_duration_seconds, 2),
            "summary": self.summary[:200] if self.summary else "",
            "error": self.error or "",
        }


class BatchResult(BaseModel):
    """Result of batch scanning multiple repositories."""

    results: list[ScanResult] = Field(default_factory=list, description="Individual scan results")
    total_repos: int = Field(default=0, description="Total repos attempted")
    successful: int = Field(default=0, description="Successfully scanned")
    failed: int = Field(default=0, description="Failed to scan")
    total_duration_seconds: float = Field(default=0.0, description="Total batch duration")
    checkpoint_path: str | None = Field(default=None, description="Path to checkpoint file")

    def add_result(self, result: ScanResult) -> None:
        """Add a scan result to the batch."""
        self.results.append(result)
        if result.error:
            self.failed += 1
        else:
            self.successful += 1
