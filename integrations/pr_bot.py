"""
GitHub PR Commenter Bot for Hound SaaS.

Posts security findings as inline PR comments and summary comments.
Maps vulnerability locations to PR diff lines for precise annotations.
"""

import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from github import Github
from github.GithubException import GithubException
from github.PullRequest import PullRequest
from github.Repository import Repository

from .github_auth import get_authenticated_github_client


@dataclass
class FindingLocation:
    """Represents a finding's location in code."""
    file_path: str
    line_number: int
    end_line: int | None = None
    
    @classmethod
    def from_node_ref(cls, node_ref: str) -> Optional["FindingLocation"]:
        """
        Parse a node reference to extract file and line information.
        
        Supports formats:
        - "path/to/file.sol:42"
        - "path/to/file.sol:42-50"
        - "path/to/file.sol#L42"
        - "path/to/file.sol#L42-L50"
        """
        if not node_ref:
            return None
        
        # Try pattern: file.sol:42 or file.sol:42-50
        match = re.match(r'^(.+?):(\d+)(?:-(\d+))?$', node_ref)
        if match:
            file_path = match.group(1)
            line = int(match.group(2))
            end_line = int(match.group(3)) if match.group(3) else None
            return cls(file_path=file_path, line_number=line, end_line=end_line)
        
        # Try pattern: file.sol#L42 or file.sol#L42-L50
        match = re.match(r'^(.+?)#L(\d+)(?:-L(\d+))?$', node_ref)
        if match:
            file_path = match.group(1)
            line = int(match.group(2))
            end_line = int(match.group(3)) if match.group(3) else None
            return cls(file_path=file_path, line_number=line, end_line=end_line)
        
        # Just a file path without line number
        if '.' in node_ref and not node_ref.startswith('.'):
            return cls(file_path=node_ref, line_number=1)
        
        return None


@dataclass
class PRComment:
    """Represents a comment to post on a PR."""
    body: str
    file_path: str | None = None
    line_number: int | None = None
    is_inline: bool = False
    side: str = "RIGHT"  # LEFT for deletions, RIGHT for additions


class PRCommentBot:
    """
    Posts security findings as comments on GitHub Pull Requests.
    
    Features:
    - Posts inline comments on specific lines in the PR diff
    - Posts summary comment with all findings
    - Maps finding locations to PR diff positions
    - Handles rate limiting gracefully
    """
    
    # Severity emoji mapping
    SEVERITY_EMOJI = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
    }
    
    # Comment header to identify Hound comments
    COMMENT_HEADER = "<!-- hound-security-bot -->"
    
    def __init__(
        self,
        installation_id: int,
        repo_full_name: str,
        pr_number: int,
    ):
        """
        Initialize the PR comment bot.
        
        Args:
            installation_id: GitHub App installation ID
            repo_full_name: Repository full name (owner/repo)
            pr_number: Pull request number
        """
        self.installation_id = installation_id
        self.repo_full_name = repo_full_name
        self.pr_number = pr_number
        
        self._github: Github | None = None
        self._repo: Repository | None = None
        self._pr: PullRequest | None = None
        self._diff_files: dict | None = None
    
    @property
    def github(self) -> Github:
        """Get authenticated GitHub client."""
        if self._github is None:
            self._github = get_authenticated_github_client(self.installation_id)
        return self._github
    
    @property
    def repo(self) -> Repository:
        """Get the repository object."""
        if self._repo is None:
            self._repo = self.github.get_repo(self.repo_full_name)
        return self._repo
    
    @property
    def pr(self) -> PullRequest:
        """Get the pull request object."""
        if self._pr is None:
            self._pr = self.repo.get_pull(self.pr_number)
        return self._pr
    
    def _get_diff_files(self) -> dict[str, dict]:
        """
        Get the PR diff files with line mappings.
        
        Returns:
            Dict mapping file paths to their diff information
        """
        if self._diff_files is not None:
            return self._diff_files
        
        self._diff_files = {}
        
        for file in self.pr.get_files():
            file_info = {
                "filename": file.filename,
                "status": file.status,  # added, removed, modified, renamed
                "patch": file.patch or "",
                "additions": file.additions,
                "deletions": file.deletions,
                "changes": file.changes,
                "line_map": {},  # Maps source line -> diff position
            }
            
            # Parse patch to build line mapping
            if file.patch:
                file_info["line_map"] = self._parse_patch_line_map(file.patch)
            
            self._diff_files[file.filename] = file_info
            
            # Also map by previous filename for renames
            if file.previous_filename:
                self._diff_files[file.previous_filename] = file_info
        
        return self._diff_files
    
    def _parse_patch_line_map(self, patch: str) -> dict[int, int]:
        """
        Parse a unified diff patch to map source lines to diff positions.
        
        The diff position is needed for posting inline comments.
        
        Args:
            patch: Unified diff patch string
            
        Returns:
            Dict mapping source line numbers to diff positions
        """
        line_map = {}
        diff_position = 0
        current_line = 0
        
        for line in patch.split('\n'):
            diff_position += 1
            
            if line.startswith('@@'):
                # Parse hunk header: @@ -old_start,old_count +new_start,new_count @@
                match = re.match(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@', line)
                if match:
                    current_line = int(match.group(1)) - 1
            elif line.startswith('-'):
                # Deleted line - don't increment current_line
                pass
            elif line.startswith('+'):
                # Added line
                current_line += 1
                line_map[current_line] = diff_position
            else:
                # Context line
                current_line += 1
                line_map[current_line] = diff_position
        
        return line_map
    
    def _find_line_in_diff(
        self,
        file_path: str,
        line_number: int
    ) -> tuple[str, int] | None:
        """
        Find a line in the PR diff and return its position.
        
        Args:
            file_path: Path to the file
            line_number: Line number in the file
            
        Returns:
            Tuple of (filename, diff_position) or None if not in diff
        """
        diff_files = self._get_diff_files()
        
        # Normalize file path (remove leading ./ or /)
        normalized_path = file_path.lstrip("./")
        
        # Try exact match first
        if normalized_path in diff_files:
            file_info = diff_files[normalized_path]
            if line_number in file_info["line_map"]:
                return (file_info["filename"], file_info["line_map"][line_number])
        
        # Try matching by filename only (in case paths differ)
        filename = os.path.basename(normalized_path)
        for path, file_info in diff_files.items():
            if os.path.basename(path) == filename:
                if line_number in file_info["line_map"]:
                    return (file_info["filename"], file_info["line_map"][line_number])
        
        # Try partial path match
        for path, file_info in diff_files.items():
            if path.endswith(normalized_path) or normalized_path.endswith(path):
                if line_number in file_info["line_map"]:
                    return (file_info["filename"], file_info["line_map"][line_number])
        
        return None
    
    def _format_finding_comment(self, finding: dict) -> str:
        """
        Format a finding as a markdown comment.
        
        Args:
            finding: Finding dictionary from report generator
            
        Returns:
            Formatted markdown string
        """
        severity = finding.get("severity", "medium").lower()
        emoji = self.SEVERITY_EMOJI.get(severity, "⚪")
        
        title = finding.get("title", "Security Finding")
        vuln_type = finding.get("type", "unknown")
        confidence = finding.get("confidence", 0)
        description = finding.get("description", "")
        professional_desc = finding.get("professional_description", description)
        remediation = finding.get("remediation", "")
        
        # Build comment
        lines = [
            self.COMMENT_HEADER,
            f"## {emoji} {severity.upper()}: {title}",
            "",
            f"**Type:** {vuln_type}",
            f"**Confidence:** {confidence:.0%}" if isinstance(confidence, float) else f"**Confidence:** {confidence}",
            "",
            "### Description",
            professional_desc or description,
        ]
        
        if remediation:
            lines.extend([
                "",
                "### Remediation",
                remediation,
            ])
        
        # Add code samples if available
        code_samples = finding.get("code_samples", [])
        if code_samples:
            lines.extend([
                "",
                "### Affected Code",
            ])
            for sample in code_samples[:2]:  # Limit to 2 samples
                sample_path = sample.get("path", "")
                sample_code = sample.get("code", "")
                if sample_code:
                    lang = "solidity" if sample_path.endswith(".sol") else ""
                    lines.extend([
                        f"```{lang}",
                        sample_code[:500],  # Limit code length
                        "```",
                    ])
        
        lines.extend([
            "",
            "---",
            "_🐕 Found by [Hound](https://github.com/muellerberndt/hound) Security Scanner_",
        ])
        
        return "\n".join(lines)
    
    def _format_inline_comment(self, finding: dict) -> str:
        """
        Format a finding as a short inline comment.
        
        Args:
            finding: Finding dictionary
            
        Returns:
            Short markdown string for inline comment
        """
        severity = finding.get("severity", "medium").lower()
        emoji = self.SEVERITY_EMOJI.get(severity, "⚪")
        title = finding.get("title", "Security Finding")
        confidence = finding.get("confidence", 0)
        description = finding.get("description", "")[:200]
        
        lines = [
            self.COMMENT_HEADER,
            f"{emoji} **{severity.upper()}**: {title}",
            "",
            description,
            "",
            f"_Confidence: {confidence:.0%}_" if isinstance(confidence, float) else f"_Confidence: {confidence}_",
        ]
        
        return "\n".join(lines)
    
    def _format_summary_comment(self, findings: list[dict], scan_id: str = "") -> str:
        """
        Format a summary comment with all findings.
        
        Args:
            findings: List of finding dictionaries
            scan_id: Optional scan ID for reference
            
        Returns:
            Formatted markdown summary
        """
        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in findings:
            sev = finding.get("severity", "medium").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        total = len(findings)
        
        lines = [
            self.COMMENT_HEADER,
            "# 🐕 Hound Security Scan Results",
            "",
            f"**Total Findings:** {total}",
            "",
            "| Severity | Count |",
            "|----------|-------|",
            f"| {self.SEVERITY_EMOJI['critical']} Critical | {severity_counts['critical']} |",
            f"| {self.SEVERITY_EMOJI['high']} High | {severity_counts['high']} |",
            f"| {self.SEVERITY_EMOJI['medium']} Medium | {severity_counts['medium']} |",
            f"| {self.SEVERITY_EMOJI['low']} Low | {severity_counts['low']} |",
            "",
        ]
        
        if findings:
            lines.extend([
                "## Findings Summary",
                "",
                "| Severity | Title | Type | Confidence |",
                "|----------|-------|------|------------|",
            ])
            
            for finding in findings:
                sev = finding.get("severity", "medium").lower()
                emoji = self.SEVERITY_EMOJI.get(sev, "⚪")
                title = finding.get("title", "Unknown")[:50]
                vuln_type = finding.get("type", "unknown")
                confidence = finding.get("confidence", 0)
                conf_str = f"{confidence:.0%}" if isinstance(confidence, float) else str(confidence)
                
                lines.append(f"| {emoji} {sev} | {title} | {vuln_type} | {conf_str} |")
            
            lines.append("")
        
        # Add timestamp and scan reference
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        lines.extend([
            "---",
            f"_Scan completed: {timestamp}_",
        ])
        
        if scan_id:
            lines.append(f"_Scan ID: `{scan_id}`_")
        
        lines.append("_🐕 [Hound](https://github.com/muellerberndt/hound) - AI Security Scanner_")
        
        return "\n".join(lines)
    
    def _extract_locations_from_finding(self, finding: dict) -> list[FindingLocation]:
        """
        Extract all file locations from a finding.
        
        Args:
            finding: Finding dictionary
            
        Returns:
            List of FindingLocation objects
        """
        locations = []
        
        # Try node_refs / affected array
        affected = finding.get("affected", []) or finding.get("node_refs", [])
        for ref in affected:
            if isinstance(ref, str):
                loc = FindingLocation.from_node_ref(ref)
                if loc:
                    locations.append(loc)
        
        # Try code_samples
        for sample in finding.get("code_samples", []):
            path = sample.get("path", "")
            line = sample.get("start_line") or sample.get("line")
            if path and line:
                locations.append(FindingLocation(
                    file_path=path,
                    line_number=int(line)
                ))
        
        # Try properties
        props = finding.get("properties", {})
        if isinstance(props, dict):
            if "file" in props or "path" in props:
                path = props.get("file") or props.get("path")
                line = props.get("line", 1)
                if path:
                    locations.append(FindingLocation(
                        file_path=path,
                        line_number=int(line)
                    ))
        
        return locations
    
    def post_inline_comment(
        self,
        finding: dict,
        file_path: str,
        diff_position: int,
        commit_sha: str,
    ) -> bool:
        """
        Post an inline comment on a specific line in the PR diff.
        
        Args:
            finding: Finding dictionary
            file_path: File path in the diff
            diff_position: Position in the diff
            commit_sha: Commit SHA to comment on
            
        Returns:
            True if comment was posted successfully
        """
        try:
            body = self._format_inline_comment(finding)
            
            self.pr.create_review_comment(
                body=body,
                commit=self.repo.get_commit(commit_sha),
                path=file_path,
                position=diff_position,
            )
            return True
            
        except GithubException as e:
            if e.status == 422:
                # Unprocessable - likely line not in diff
                return False
            raise
    
    def post_summary_comment(
        self,
        findings: list[dict],
        scan_id: str = "",
    ) -> bool:
        """
        Post a summary comment on the PR.
        
        Args:
            findings: List of finding dictionaries
            scan_id: Optional scan ID for reference
            
        Returns:
            True if comment was posted successfully
        """
        try:
            body = self._format_summary_comment(findings, scan_id)
            self.pr.create_issue_comment(body)
            return True
        except GithubException:
            return False
    
    def post_finding_comment(self, finding: dict) -> bool:
        """
        Post a detailed comment for a single finding.
        
        Args:
            finding: Finding dictionary
            
        Returns:
            True if comment was posted successfully
        """
        try:
            body = self._format_finding_comment(finding)
            self.pr.create_issue_comment(body)
            return True
        except GithubException:
            return False
    
    def delete_previous_comments(self) -> int:
        """
        Delete previous Hound comments on the PR.
        
        Returns:
            Number of comments deleted
        """
        deleted = 0
        
        try:
            # Delete issue comments
            for comment in self.pr.get_issue_comments():
                if self.COMMENT_HEADER in (comment.body or ""):
                    comment.delete()
                    deleted += 1
            
            # Delete review comments
            for comment in self.pr.get_review_comments():
                if self.COMMENT_HEADER in (comment.body or ""):
                    comment.delete()
                    deleted += 1
                    
        except GithubException:
            pass
        
        return deleted
    
    def post_findings(
        self,
        findings: list[dict],
        scan_id: str = "",
        include_inline: bool = True,
        include_summary: bool = True,
        delete_previous: bool = True,
        max_inline_comments: int = 10,
    ) -> dict:
        """
        Post all findings to the PR.
        
        This is the main method to call for posting findings.
        
        Args:
            findings: List of confirmed findings from report generator
            scan_id: Optional scan ID for reference
            include_inline: Whether to post inline comments on diff lines
            include_summary: Whether to post a summary comment
            delete_previous: Whether to delete previous Hound comments
            max_inline_comments: Maximum number of inline comments to post
            
        Returns:
            Dict with posting results
        """
        result = {
            "success": True,
            "summary_posted": False,
            "inline_comments_posted": 0,
            "inline_comments_failed": 0,
            "findings_not_in_diff": 0,
            "previous_deleted": 0,
            "errors": [],
        }
        
        try:
            # Delete previous comments if requested
            if delete_previous:
                result["previous_deleted"] = self.delete_previous_comments()
            
            # Get the head commit SHA for inline comments
            head_sha = self.pr.head.sha
            
            # Post inline comments for findings in the diff
            if include_inline and findings:
                inline_count = 0
                
                for finding in findings:
                    if inline_count >= max_inline_comments:
                        break
                    
                    locations = self._extract_locations_from_finding(finding)
                    posted_for_finding = False
                    
                    for loc in locations:
                        if posted_for_finding:
                            break
                        
                        diff_info = self._find_line_in_diff(loc.file_path, loc.line_number)
                        
                        if diff_info:
                            file_path, diff_position = diff_info
                            
                            success = self.post_inline_comment(
                                finding=finding,
                                file_path=file_path,
                                diff_position=diff_position,
                                commit_sha=head_sha,
                            )
                            
                            if success:
                                result["inline_comments_posted"] += 1
                                inline_count += 1
                                posted_for_finding = True
                            else:
                                result["inline_comments_failed"] += 1
                    
                    if not posted_for_finding and locations:
                        result["findings_not_in_diff"] += 1
            
            # Post summary comment
            if include_summary:
                result["summary_posted"] = self.post_summary_comment(findings, scan_id)
                
        except Exception as e:
            result["success"] = False
            result["errors"].append(str(e))
        
        return result


def post_findings_to_pr(
    installation_id: int,
    repo_full_name: str,
    pr_number: int,
    findings: list[dict],
    scan_id: str = "",
    **kwargs,
) -> dict:
    """
    Convenience function to post findings to a PR.
    
    Args:
        installation_id: GitHub App installation ID
        repo_full_name: Repository full name (owner/repo)
        pr_number: Pull request number
        findings: List of confirmed findings
        scan_id: Optional scan ID
        **kwargs: Additional arguments passed to post_findings
        
    Returns:
        Dict with posting results
        
    Example:
        from analysis.report_generator import ReportGenerator
        
        generator = ReportGenerator(project_dir, config)
        findings = generator._get_confirmed_findings()
        
        result = post_findings_to_pr(
            installation_id=12345678,
            repo_full_name="owner/repo",
            pr_number=123,
            findings=findings,
            scan_id="scan_abc123",
        )
    """
    bot = PRCommentBot(
        installation_id=installation_id,
        repo_full_name=repo_full_name,
        pr_number=pr_number,
    )
    
    return bot.post_findings(findings, scan_id=scan_id, **kwargs)
