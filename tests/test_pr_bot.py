"""
Tests for GitHub PR Comment Bot.
"""

from unittest.mock import Mock, patch


class TestFindingLocation:
    """Tests for FindingLocation parsing."""
    
    def test_parse_colon_format(self):
        """Test parsing file.sol:42 format."""
        from integrations.pr_bot import FindingLocation
        loc = FindingLocation.from_node_ref("contracts/Token.sol:42")
        
        assert loc is not None
        assert loc.file_path == "contracts/Token.sol"
        assert loc.line_number == 42
        assert loc.end_line is None
    
    def test_parse_colon_range_format(self):
        """Test parsing file.sol:42-50 format."""
        from integrations.pr_bot import FindingLocation
        loc = FindingLocation.from_node_ref("contracts/Token.sol:42-50")
        
        assert loc is not None
        assert loc.file_path == "contracts/Token.sol"
        assert loc.line_number == 42
        assert loc.end_line == 50
    
    def test_parse_hash_format(self):
        """Test parsing file.sol#L42 format."""
        from integrations.pr_bot import FindingLocation
        loc = FindingLocation.from_node_ref("contracts/Token.sol#L42")
        
        assert loc is not None
        assert loc.file_path == "contracts/Token.sol"
        assert loc.line_number == 42
    
    def test_parse_hash_range_format(self):
        """Test parsing file.sol#L42-L50 format."""
        from integrations.pr_bot import FindingLocation
        loc = FindingLocation.from_node_ref("contracts/Token.sol#L42-L50")
        
        assert loc is not None
        assert loc.file_path == "contracts/Token.sol"
        assert loc.line_number == 42
        assert loc.end_line == 50
    
    def test_parse_file_only(self):
        """Test parsing just a file path."""
        from integrations.pr_bot import FindingLocation
        loc = FindingLocation.from_node_ref("contracts/Token.sol")
        
        assert loc is not None
        assert loc.file_path == "contracts/Token.sol"
        assert loc.line_number == 1
    
    def test_parse_empty_returns_none(self):
        """Test that empty string returns None."""
        from integrations.pr_bot import FindingLocation
        loc = FindingLocation.from_node_ref("")
        assert loc is None
    
    def test_parse_none_returns_none(self):
        """Test that None returns None."""
        from integrations.pr_bot import FindingLocation
        loc = FindingLocation.from_node_ref(None)
        assert loc is None
    
    def test_parse_invalid_returns_none(self):
        """Test that invalid refs return None."""
        from integrations.pr_bot import FindingLocation
        loc = FindingLocation.from_node_ref("not-a-file-ref")
        assert loc is None


class TestPRCommentBot:
    """Tests for PRCommentBot class."""
    
    @patch('integrations.pr_bot.get_authenticated_github_client')
    def test_initialization(self, mock_get_client):
        """Test bot initialization."""
        from integrations.pr_bot import PRCommentBot
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        bot = PRCommentBot(
            installation_id=12345,
            repo_full_name="owner/repo",
            pr_number=42,
        )
        
        assert bot.installation_id == 12345
        assert bot.repo_full_name == "owner/repo"
        assert bot.pr_number == 42
    
    @patch('integrations.pr_bot.get_authenticated_github_client')
    def test_format_finding_comment(self, mock_get_client):
        """Test formatting a finding as a comment."""
        from integrations.pr_bot import PRCommentBot
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        bot = PRCommentBot(
            installation_id=12345,
            repo_full_name="owner/repo",
            pr_number=42,
        )
        
        finding = {
            "title": "Reentrancy Vulnerability",
            "severity": "high",
            "type": "reentrancy",
            "confidence": 0.85,
            "description": "External call before state update",
            "remediation": "Use checks-effects-interactions pattern",
        }
        
        comment = bot._format_finding_comment(finding)
        
        assert "<!-- hound-security-bot -->" in comment
        assert "HIGH" in comment
        assert "Reentrancy Vulnerability" in comment
        assert "External call before state update" in comment
        assert "checks-effects-interactions" in comment
        assert "🟠" in comment  # Orange for high severity
    
    @patch('integrations.pr_bot.get_authenticated_github_client')
    def test_format_summary_comment(self, mock_get_client):
        """Test formatting a summary comment."""
        from integrations.pr_bot import PRCommentBot
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        bot = PRCommentBot(
            installation_id=12345,
            repo_full_name="owner/repo",
            pr_number=42,
        )
        
        findings = [
            {"severity": "critical", "title": "Finding 1", "type": "overflow", "confidence": 0.9},
            {"severity": "high", "title": "Finding 2", "type": "reentrancy", "confidence": 0.8},
            {"severity": "medium", "title": "Finding 3", "type": "dos", "confidence": 0.7},
            {"severity": "low", "title": "Finding 4", "type": "gas", "confidence": 0.6},
        ]
        
        comment = bot._format_summary_comment(findings, scan_id="scan_123")
        
        assert "<!-- hound-security-bot -->" in comment
        assert "Hound Security Scan Results" in comment
        assert "Total Findings:** 4" in comment
        assert "scan_123" in comment
        assert "| 🔴 Critical | 1 |" in comment
        assert "| 🟠 High | 1 |" in comment
    
    @patch('integrations.pr_bot.get_authenticated_github_client')
    def test_extract_locations_from_finding(self, mock_get_client):
        """Test extracting locations from a finding."""
        from integrations.pr_bot import PRCommentBot
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        bot = PRCommentBot(
            installation_id=12345,
            repo_full_name="owner/repo",
            pr_number=42,
        )
        
        finding = {
            "affected": ["contracts/Token.sol:42", "contracts/Token.sol:100"],
            "code_samples": [
                {"path": "contracts/Vault.sol", "start_line": 50, "code": "..."}
            ],
        }
        
        locations = bot._extract_locations_from_finding(finding)
        
        assert len(locations) == 3
        assert locations[0].file_path == "contracts/Token.sol"
        assert locations[0].line_number == 42
        assert locations[2].file_path == "contracts/Vault.sol"
        assert locations[2].line_number == 50
    
    @patch('integrations.pr_bot.get_authenticated_github_client')
    def test_parse_patch_line_map(self, mock_get_client):
        """Test parsing a unified diff patch."""
        from integrations.pr_bot import PRCommentBot
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        bot = PRCommentBot(
            installation_id=12345,
            repo_full_name="owner/repo",
            pr_number=42,
        )
        
        patch = """@@ -10,6 +10,8 @@ contract Token {
     uint256 public totalSupply;
 
     function transfer(address to, uint256 amount) external {
+        // vulnerable code
+        to.call{value: amount}("");
         balances[msg.sender] -= amount;
         balances[to] += amount;
     }"""
        
        line_map = bot._parse_patch_line_map(patch)
        
        # Lines 10-12 are context (unchanged)
        # Lines 13-14 are added (+ lines)
        # Lines 15-16 are context
        assert 10 in line_map or 11 in line_map  # Context lines
        assert 13 in line_map  # Added line
        assert 14 in line_map  # Added line


class TestPostFindingsToPR:
    """Tests for the convenience function."""
    
    @patch('integrations.pr_bot.PRCommentBot')
    def test_creates_bot_and_posts(self, mock_bot_class):
        """Test that convenience function creates bot and posts."""
        from integrations.pr_bot import post_findings_to_pr
        mock_bot = Mock()
        mock_bot.post_findings.return_value = {
            "success": True,
            "summary_posted": True,
            "inline_comments_posted": 2,
        }
        mock_bot_class.return_value = mock_bot
        
        findings = [{"title": "Test", "severity": "high"}]
        
        result = post_findings_to_pr(
            installation_id=12345,
            repo_full_name="owner/repo",
            pr_number=42,
            findings=findings,
            scan_id="scan_123",
        )
        
        assert result["success"] is True
        mock_bot_class.assert_called_once_with(
            installation_id=12345,
            repo_full_name="owner/repo",
            pr_number=42,
        )
        mock_bot.post_findings.assert_called_once()


class TestSeverityMapping:
    """Tests for severity emoji mapping."""
    
    @patch('integrations.pr_bot.get_authenticated_github_client')
    def test_critical_severity(self, mock_get_client):
        """Test critical severity gets red emoji."""
        from integrations.pr_bot import PRCommentBot
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        bot = PRCommentBot(12345, "owner/repo", 42)
        
        finding = {"title": "Critical Bug", "severity": "critical", "description": "Bad"}
        comment = bot._format_inline_comment(finding)
        
        assert "🔴" in comment
        assert "CRITICAL" in comment
    
    @patch('integrations.pr_bot.get_authenticated_github_client')
    def test_high_severity(self, mock_get_client):
        """Test high severity gets orange emoji."""
        from integrations.pr_bot import PRCommentBot
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        bot = PRCommentBot(12345, "owner/repo", 42)
        
        finding = {"title": "High Bug", "severity": "high", "description": "Bad"}
        comment = bot._format_inline_comment(finding)
        
        assert "🟠" in comment
        assert "HIGH" in comment
    
    @patch('integrations.pr_bot.get_authenticated_github_client')
    def test_medium_severity(self, mock_get_client):
        """Test medium severity gets yellow emoji."""
        from integrations.pr_bot import PRCommentBot
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        bot = PRCommentBot(12345, "owner/repo", 42)
        
        finding = {"title": "Medium Bug", "severity": "medium", "description": "Meh"}
        comment = bot._format_inline_comment(finding)
        
        assert "🟡" in comment
        assert "MEDIUM" in comment
    
    @patch('integrations.pr_bot.get_authenticated_github_client')
    def test_low_severity(self, mock_get_client):
        """Test low severity gets green emoji."""
        from integrations.pr_bot import PRCommentBot
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        bot = PRCommentBot(12345, "owner/repo", 42)
        
        finding = {"title": "Low Bug", "severity": "low", "description": "Minor"}
        comment = bot._format_inline_comment(finding)
        
        assert "🟢" in comment
        assert "LOW" in comment


class TestDeletePreviousComments:
    """Tests for deleting previous Hound comments."""
    
    @patch('integrations.pr_bot.get_authenticated_github_client')
    def test_deletes_issue_comments(self, mock_get_client):
        """Test deleting previous issue comments."""
        from integrations.pr_bot import PRCommentBot
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        bot = PRCommentBot(12345, "owner/repo", 42)
        
        # Mock PR with comments
        mock_comment1 = Mock()
        mock_comment1.body = "<!-- hound-security-bot -->\nOld finding"
        mock_comment2 = Mock()
        mock_comment2.body = "Normal user comment"
        mock_comment3 = Mock()
        mock_comment3.body = "<!-- hound-security-bot -->\nAnother old finding"
        
        bot._pr = Mock()
        bot._pr.get_issue_comments.return_value = [
            mock_comment1, mock_comment2, mock_comment3
        ]
        bot._pr.get_review_comments.return_value = []
        
        deleted = bot.delete_previous_comments()
        
        assert deleted == 2
        mock_comment1.delete.assert_called_once()
        mock_comment2.delete.assert_not_called()
        mock_comment3.delete.assert_called_once()
