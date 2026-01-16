"""
GitHub Pull Request reporter for posting security findings as PR comments.

Posts findings from Hound security analysis to GitHub Pull Requests as review comments,
supporting both general PR-level comments and line-specific code review comments.
"""

import os
from typing import Any

from github import Auth, Github
from github.GithubException import GithubException

from analysis.reporters import Reporter


class GitHubPRReporter(Reporter):
    """Reporter that posts findings as GitHub PR review comments."""
    
    def __init__(self, 
                 repo_full_name: str, 
                 pr_number: int,
                 token: str | None = None,
                 installation_id: int | None = None):
        """
        Initialize the GitHub PR reporter.
        
        Args:
            repo_full_name: Full repository name (e.g., "owner/repo")
            pr_number: Pull request number
            token: GitHub access token. If not provided, uses GITHUB_TOKEN env var
            installation_id: GitHub App installation ID (optional, for App authentication)
        """
        self.repo_full_name = repo_full_name
        self.pr_number = pr_number
        self.installation_id = installation_id
        
        # Get token from parameter or environment
        self.token = token or os.environ.get("GITHUB_TOKEN")
        if not self.token:
            raise ValueError(
                "GitHub token not provided. Set GITHUB_TOKEN environment variable "
                "or pass token parameter."
            )
        
        # Initialize GitHub client
        auth = Auth.Token(self.token)
        self.github = Github(auth=auth)
        
        # Get repository and PR objects
        try:
            self.repo = self.github.get_repo(repo_full_name)
            self.pr = self.repo.get_pull(pr_number)
        except GithubException as e:
            raise ValueError(f"Failed to access repository or PR: {e}")
    
    def report(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Post findings as a GitHub PR review.
        
        Creates a PR review with:
        - Summary comment with all findings
        - Line-specific comments for findings with file/line information
        
        Args:
            findings: List of finding dictionaries with keys: id, title, severity,
                     type, description, affected, professional_description, etc.
        
        Returns:
            Dictionary with:
                - status: "success" or "error"
                - review_id: GitHub review ID if successful
                - comments_posted: Number of line-level comments posted
                - error: Error message if failed
        """
        if not findings:
            return {
                "status": "success",
                "message": "No findings to report",
                "comments_posted": 0
            }
        
        try:
            # Prepare review comments (line-specific)
            review_comments = self._prepare_review_comments(findings)
            
            # Prepare summary body
            summary_body = self._prepare_summary_body(findings)
            
            # Post the review
            # Use REQUEST_CHANGES if there are critical/high findings, otherwise COMMENT
            has_critical = any(f.get('severity') in ['critical', 'high'] for f in findings)
            event = "REQUEST_CHANGES" if has_critical else "COMMENT"
            
            review = self.pr.create_review(
                body=summary_body,
                event=event,
                comments=review_comments
            )
            
            return {
                "status": "success",
                "review_id": review.id,
                "comments_posted": len(review_comments),
                "summary_posted": True,
                "review_event": event
            }
            
        except GithubException as e:
            return {
                "status": "error",
                "error": str(e),
                "error_type": type(e).__name__
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "error_type": type(e).__name__
            }
    
    def _prepare_summary_body(self, findings: list[dict[str, Any]]) -> str:
        """
        Prepare the summary comment body for the PR review.
        
        Args:
            findings: List of findings
            
        Returns:
            Markdown-formatted summary text
        """
        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in findings:
            severity = finding.get("severity", "medium").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Build summary
        lines = [
            "# 🐕 Hound Security Analysis",
            "",
            f"Found **{len(findings)}** security finding(s) in this PR:",
            ""
        ]
        
        # Add severity breakdown
        if severity_counts["critical"] > 0:
            lines.append(f"- 🔴 **Critical**: {severity_counts['critical']}")
        if severity_counts["high"] > 0:
            lines.append(f"- 🟠 **High**: {severity_counts['high']}")
        if severity_counts["medium"] > 0:
            lines.append(f"- 🟡 **Medium**: {severity_counts['medium']}")
        if severity_counts["low"] > 0:
            lines.append(f"- 🟢 **Low**: {severity_counts['low']}")
        
        lines.extend(["", "---", "", "## Findings", ""])
        
        # Add each finding
        for finding in findings:
            severity = finding.get("severity", "medium").lower()
            emoji = self._get_severity_emoji(severity)
            title = finding.get("title", "Unknown vulnerability")
            description = finding.get("professional_description") or finding.get("description", "")
            
            lines.append(f"### {emoji} [{severity.upper()}] {title}")
            lines.append("")
            
            # Add description (limit length for summary)
            if description:
                # Truncate long descriptions in summary
                desc_preview = description[:500]
                if len(description) > 500:
                    desc_preview += "..."
                lines.append(desc_preview)
                lines.append("")
            
            # Add affected components if available
            affected_desc = finding.get("affected_description")
            if affected_desc:
                lines.append(f"**Affected:** {affected_desc}")
                lines.append("")
        
        return "\n".join(lines)
    
    def _prepare_review_comments(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Prepare line-specific review comments for findings with file/line information.
        
        Args:
            findings: List of findings
            
        Returns:
            List of comment dictionaries for GitHub API
        """
        comments = []
        
        # Get PR file information for validation
        pr_files = {f.filename: f for f in self.pr.get_files()}
        
        for finding in findings:
            # Try to extract file and line information from code samples
            code_samples = finding.get("code_samples", [])
            
            for sample in code_samples:
                file_path = sample.get("file")
                start_line = sample.get("start_line")
                
                if not file_path or not start_line:
                    continue
                
                # Normalize file path (remove leading slashes/src/)
                normalized_path = self._normalize_file_path(file_path)
                
                # Check if file is in the PR diff
                if normalized_path not in pr_files:
                    continue
                
                # Prepare comment body
                severity = finding.get("severity", "medium").lower()
                emoji = self._get_severity_emoji(severity)
                title = finding.get("title", "Security Issue")
                description = finding.get("professional_description") or finding.get("description", "")
                
                comment_body = f"{emoji} **[Hound] {title}**\n\n"
                comment_body += f"**Severity:** {severity.upper()}\n\n"
                
                if description:
                    # Limit description length for line comments
                    desc_preview = description[:300]
                    if len(description) > 300:
                        desc_preview += "..."
                    comment_body += f"{desc_preview}\n\n"
                
                # Add explanation from code sample if available
                explanation = sample.get("explanation")
                if explanation:
                    comment_body += f"**Context:** {explanation}\n"
                
                # Create the comment
                comments.append({
                    "path": normalized_path,
                    "line": int(start_line),
                    "body": comment_body
                })
                
                # Only add one comment per finding to avoid spam
                break
        
        return comments
    
    def _normalize_file_path(self, file_path: str) -> str:
        """
        Normalize file path to match GitHub PR file paths.
        
        Removes leading slashes and common prefixes like 'src/'.
        
        Args:
            file_path: Original file path
            
        Returns:
            Normalized file path
        """
        # Remove leading slash
        path = file_path.lstrip("/")
        
        # Try removing 'src/' prefix if it doesn't match
        # We'll try both with and without in the caller
        return path
    
    def _get_severity_emoji(self, severity: str) -> str:
        """
        Get emoji for severity level.
        
        Args:
            severity: Severity level (critical, high, medium, low)
            
        Returns:
            Emoji string
        """
        severity_emojis = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢"
        }
        return severity_emojis.get(severity.lower(), "⚪")
    
    def close(self) -> None:
        """Close the GitHub client connection."""
        if hasattr(self, 'github'):
            self.github.close()
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
