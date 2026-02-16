"""
Unit tests for GitHub PR reporter.

Tests the GitHubPRReporter class that posts security findings to GitHub PRs.
"""

import os
import unittest
from unittest.mock import Mock, patch

from analysis.reporters.github_pr import GitHubPRReporter


class TestGitHubPRReporter(unittest.TestCase):
    """Test GitHub PR reporter functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.repo_name = "test-org/test-repo"
        self.pr_number = 123
        self.token = "test_token_123"
        
        # Sample findings for testing
        self.sample_findings = [
            {
                "id": "hyp_001",
                "title": "SQL Injection Vulnerability",
                "severity": "critical",
                "type": "injection",
                "description": "SQL injection found in user input handling",
                "professional_description": "A SQL injection vulnerability exists in the user authentication module where user input is directly concatenated into SQL queries without proper sanitization.",
                "affected": ["AuthModule", "UserController"],
                "affected_description": "the AuthModule and UserController components",
                "confidence": 0.95,
                "code_samples": [
                    {
                        "file": "src/auth/controller.py",
                        "start_line": 45,
                        "end_line": 50,
                        "code": "query = f\"SELECT * FROM users WHERE username='{username}'\"",
                        "language": "python",
                        "explanation": "User input directly concatenated into SQL query"
                    }
                ]
            },
            {
                "id": "hyp_002",
                "title": "Missing Access Control",
                "severity": "high",
                "type": "access_control",
                "description": "Endpoint lacks authorization checks",
                "professional_description": "The admin endpoint does not verify user permissions before allowing access to sensitive operations.",
                "affected": ["AdminController"],
                "affected_description": "the AdminController",
                "confidence": 0.88,
                "code_samples": [
                    {
                        "file": "src/admin/controller.py",
                        "start_line": 120,
                        "end_line": 125,
                        "code": "def delete_user(user_id):\n    db.delete(user_id)",
                        "language": "python",
                        "explanation": "No authorization check before deletion"
                    }
                ]
            },
            {
                "id": "hyp_003",
                "title": "Weak Cryptography",
                "severity": "medium",
                "type": "crypto",
                "description": "Using weak hashing algorithm",
                "professional_description": "The system uses MD5 for password hashing, which is cryptographically broken.",
                "affected": ["PasswordHasher"],
                "affected_description": "the PasswordHasher module",
                "confidence": 0.92,
                "code_samples": []
            }
        ]
    
    @patch('analysis.reporters.github_pr.Github')
    def test_initialization_with_token(self, mock_github_class):
        """Test reporter initialization with explicit token."""
        mock_github = Mock()
        mock_repo = Mock()
        mock_pr = Mock()
        mock_github.get_repo.return_value = mock_repo
        mock_repo.get_pull.return_value = mock_pr
        mock_github_class.return_value = mock_github
        
        reporter = GitHubPRReporter(
            repo_full_name=self.repo_name,
            pr_number=self.pr_number,
            token=self.token
        )
        
        self.assertEqual(reporter.repo_full_name, self.repo_name)
        self.assertEqual(reporter.pr_number, self.pr_number)
        self.assertEqual(reporter.token, self.token)
        mock_github.get_repo.assert_called_once_with(self.repo_name)
        mock_repo.get_pull.assert_called_once_with(self.pr_number)
    
    @patch.dict(os.environ, {'GITHUB_TOKEN': 'env_token_456'})
    @patch('analysis.reporters.github_pr.Github')
    def test_initialization_with_env_token(self, mock_github_class):
        """Test reporter initialization with environment variable token."""
        mock_github = Mock()
        mock_repo = Mock()
        mock_pr = Mock()
        mock_github.get_repo.return_value = mock_repo
        mock_repo.get_pull.return_value = mock_pr
        mock_github_class.return_value = mock_github
        
        reporter = GitHubPRReporter(
            repo_full_name=self.repo_name,
            pr_number=self.pr_number
        )
        
        self.assertEqual(reporter.token, 'env_token_456')
    
    @patch.dict(os.environ, {}, clear=True)
    @patch('analysis.reporters.github_pr.Github')
    def test_initialization_without_token_raises_error(self, mock_github_class):
        """Test that initialization fails without token."""
        with self.assertRaises(ValueError) as context:
            GitHubPRReporter(
                repo_full_name=self.repo_name,
                pr_number=self.pr_number
            )
        
        self.assertIn("GitHub token not provided", str(context.exception))
    
    @patch('analysis.reporters.github_pr.Github')
    def test_report_empty_findings(self, mock_github_class):
        """Test reporting with no findings."""
        mock_github = Mock()
        mock_repo = Mock()
        mock_pr = Mock()
        mock_github.get_repo.return_value = mock_repo
        mock_repo.get_pull.return_value = mock_pr
        mock_github_class.return_value = mock_github
        
        reporter = GitHubPRReporter(
            repo_full_name=self.repo_name,
            pr_number=self.pr_number,
            token=self.token
        )
        
        result = reporter.report([])
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["comments_posted"], 0)
        mock_pr.create_review.assert_not_called()
    
    @patch('analysis.reporters.github_pr.Github')
    def test_report_with_findings(self, mock_github_class):
        """Test posting findings as PR review."""
        mock_github = Mock()
        mock_repo = Mock()
        mock_pr = Mock()
        mock_review = Mock()
        mock_review.id = 789
        
        # Mock PR files to allow line comments
        mock_file = Mock()
        mock_file.filename = "src/auth/controller.py"
        mock_pr.get_files.return_value = [mock_file]
        mock_pr.create_review.return_value = mock_review
        
        mock_github.get_repo.return_value = mock_repo
        mock_repo.get_pull.return_value = mock_pr
        mock_github_class.return_value = mock_github
        
        reporter = GitHubPRReporter(
            repo_full_name=self.repo_name,
            pr_number=self.pr_number,
            token=self.token
        )
        
        result = reporter.report(self.sample_findings)
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["review_id"], 789)
        self.assertTrue(result["summary_posted"])
        
        # Verify create_review was called
        mock_pr.create_review.assert_called_once()
        call_kwargs = mock_pr.create_review.call_args[1]
        
        # Should request changes due to critical finding
        self.assertEqual(call_kwargs["event"], "REQUEST_CHANGES")
        
        # Check summary body contains findings
        body = call_kwargs["body"]
        self.assertIn("Hound Security Analysis", body)
        self.assertIn("SQL Injection Vulnerability", body)
        self.assertIn("🔴", body)  # Critical emoji
        self.assertIn("🟠", body)  # High emoji
    
    @patch('analysis.reporters.github_pr.Github')
    def test_report_with_line_comments(self, mock_github_class):
        """Test that line-specific comments are created correctly."""
        mock_github = Mock()
        mock_repo = Mock()
        mock_pr = Mock()
        mock_review = Mock()
        mock_review.id = 790
        
        # Mock PR files
        mock_file1 = Mock()
        mock_file1.filename = "src/auth/controller.py"
        mock_file2 = Mock()
        mock_file2.filename = "src/admin/controller.py"
        mock_pr.get_files.return_value = [mock_file1, mock_file2]
        mock_pr.create_review.return_value = mock_review
        
        mock_github.get_repo.return_value = mock_repo
        mock_repo.get_pull.return_value = mock_pr
        mock_github_class.return_value = mock_github
        
        reporter = GitHubPRReporter(
            repo_full_name=self.repo_name,
            pr_number=self.pr_number,
            token=self.token
        )
        
        reporter.report(self.sample_findings)
        
        # Check that comments were created
        call_kwargs = mock_pr.create_review.call_args[1]
        comments = call_kwargs["comments"]
        
        # Should have 2 line comments (first two findings have code samples)
        self.assertGreaterEqual(len(comments), 1)
        
        # Check first comment structure
        first_comment = comments[0]
        self.assertIn("path", first_comment)
        self.assertIn("line", first_comment)
        self.assertIn("body", first_comment)
        self.assertIn("[Hound]", first_comment["body"])
        self.assertIn("SQL Injection", first_comment["body"])
    
    @patch('analysis.reporters.github_pr.Github')
    def test_severity_emoji_mapping(self, mock_github_class):
        """Test that severity levels map to correct emojis."""
        mock_github = Mock()
        mock_repo = Mock()
        mock_pr = Mock()
        mock_github.get_repo.return_value = mock_repo
        mock_repo.get_pull.return_value = mock_pr
        mock_github_class.return_value = mock_github
        
        reporter = GitHubPRReporter(
            repo_full_name=self.repo_name,
            pr_number=self.pr_number,
            token=self.token
        )
        
        self.assertEqual(reporter._get_severity_emoji("critical"), "🔴")
        self.assertEqual(reporter._get_severity_emoji("high"), "🟠")
        self.assertEqual(reporter._get_severity_emoji("medium"), "🟡")
        self.assertEqual(reporter._get_severity_emoji("low"), "🟢")
        self.assertEqual(reporter._get_severity_emoji("unknown"), "⚪")
    
    @patch('analysis.reporters.github_pr.Github')
    def test_normalize_file_path(self, mock_github_class):
        """Test file path normalization."""
        mock_github = Mock()
        mock_repo = Mock()
        mock_pr = Mock()
        mock_github.get_repo.return_value = mock_repo
        mock_repo.get_pull.return_value = mock_pr
        mock_github_class.return_value = mock_github
        
        reporter = GitHubPRReporter(
            repo_full_name=self.repo_name,
            pr_number=self.pr_number,
            token=self.token
        )
        
        # Test various path formats
        self.assertEqual(
            reporter._normalize_file_path("/src/auth/controller.py"),
            "src/auth/controller.py"
        )
        self.assertEqual(
            reporter._normalize_file_path("src/auth/controller.py"),
            "src/auth/controller.py"
        )
    
    @patch('analysis.reporters.github_pr.Github')
    def test_context_manager(self, mock_github_class):
        """Test that reporter works as context manager."""
        mock_github = Mock()
        mock_repo = Mock()
        mock_pr = Mock()
        mock_github.get_repo.return_value = mock_repo
        mock_repo.get_pull.return_value = mock_pr
        mock_github.close = Mock()
        mock_github_class.return_value = mock_github
        
        with GitHubPRReporter(
            repo_full_name=self.repo_name,
            pr_number=self.pr_number,
            token=self.token
        ) as reporter:
            self.assertIsNotNone(reporter)
        
        # Verify close was called
        mock_github.close.assert_called_once()
    
    @patch('analysis.reporters.github_pr.Github')
    def test_report_handles_github_exception(self, mock_github_class):
        """Test error handling when GitHub API fails."""
        from github.GithubException import GithubException
        
        mock_github = Mock()
        mock_repo = Mock()
        mock_pr = Mock()
        mock_pr.get_files.return_value = []
        mock_pr.create_review.side_effect = GithubException(
            status=403,
            data={"message": "API rate limit exceeded"}
        )
        
        mock_github.get_repo.return_value = mock_repo
        mock_repo.get_pull.return_value = mock_pr
        mock_github_class.return_value = mock_github
        
        reporter = GitHubPRReporter(
            repo_full_name=self.repo_name,
            pr_number=self.pr_number,
            token=self.token
        )
        
        result = reporter.report(self.sample_findings)
        
        self.assertEqual(result["status"], "error")
        self.assertIn("error", result)
        self.assertEqual(result["error_type"], "GithubException")
    
    @patch('analysis.reporters.github_pr.Github')
    def test_summary_body_formatting(self, mock_github_class):
        """Test that summary body is properly formatted."""
        mock_github = Mock()
        mock_repo = Mock()
        mock_pr = Mock()
        mock_github.get_repo.return_value = mock_repo
        mock_repo.get_pull.return_value = mock_pr
        mock_github_class.return_value = mock_github
        
        reporter = GitHubPRReporter(
            repo_full_name=self.repo_name,
            pr_number=self.pr_number,
            token=self.token
        )
        
        summary = reporter._prepare_summary_body(self.sample_findings)
        
        # Check markdown formatting
        self.assertIn("# 🐕 Hound Security Analysis", summary)
        self.assertIn("## Findings", summary)
        self.assertIn("🔴 **Critical**: 1", summary)
        self.assertIn("🟠 **High**: 1", summary)
        self.assertIn("🟡 **Medium**: 1", summary)
        
        # Check all findings are included
        self.assertIn("SQL Injection Vulnerability", summary)
        self.assertIn("Missing Access Control", summary)
        self.assertIn("Weak Cryptography", summary)
    
    @patch('analysis.reporters.github_pr.Github')
    def test_medium_severity_uses_comment_event(self, mock_github_class):
        """Test that medium/low severity uses COMMENT instead of REQUEST_CHANGES."""
        mock_github = Mock()
        mock_repo = Mock()
        mock_pr = Mock()
        mock_review = Mock()
        mock_review.id = 791
        
        mock_pr.get_files.return_value = []
        mock_pr.create_review.return_value = mock_review
        
        mock_github.get_repo.return_value = mock_repo
        mock_repo.get_pull.return_value = mock_pr
        mock_github_class.return_value = mock_github
        
        reporter = GitHubPRReporter(
            repo_full_name=self.repo_name,
            pr_number=self.pr_number,
            token=self.token
        )
        
        # Only medium severity finding
        medium_findings = [self.sample_findings[2]]
        
        reporter.report(medium_findings)
        
        call_kwargs = mock_pr.create_review.call_args[1]
        self.assertEqual(call_kwargs["event"], "COMMENT")


if __name__ == "__main__":
    unittest.main()
