"""
Test suite for auto-fix PR creation functionality.

Tests the AutoPRFixer class and related functionality.
"""

import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from integrations.auto_pr_fixer import AutoPRFixer, create_fix_pr_for_findings


@pytest.fixture
def mock_github():
    """Mock GitHub client."""
    with patch('integrations.auto_pr_fixer.get_authenticated_github_client') as mock:
        gh = Mock()
        repo = Mock()
        repo.create_pull = Mock(return_value=Mock(number=123, html_url="https://github.com/owner/repo/pull/123"))
        gh.get_repo = Mock(return_value=repo)
        mock.return_value = gh
        yield mock


@pytest.fixture
def mock_clone_url():
    """Mock clone URL with token."""
    with patch('integrations.auto_pr_fixer.get_clone_url_with_token') as mock:
        mock.return_value = "https://x-access-token:token@github.com/owner/repo.git"
        yield mock


@pytest.fixture
def sample_findings():
    """Sample findings for testing."""
    return [
        {
            "pattern_id": "REENTRANCY-001",
            "title": "Potential Reentrancy",
            "severity": "high",
            "location": "contracts/Token.sol:42",
            "description": "External call before state update",
            "confidence": 0.8,
        },
        {
            "pattern_id": "UNCHECKED-CALL-001",
            "title": "Unchecked low-level call",
            "severity": "high",
            "location": "contracts/Vault.sol:15",
            "description": ".call() without return check",
            "confidence": 0.9,
        },
        {
            "pattern_id": "TXORIGIN-001",
            "title": "tx.origin usage",
            "severity": "high",
            "location": "contracts/Auth.sol:28",
            "description": "Using tx.origin for authentication",
            "confidence": 0.95,
        },
    ]


def test_auto_pr_fixer_init():
    """Test AutoPRFixer initialization."""
    fixer = AutoPRFixer(
        installation_id=12345,
        repo_full_name="owner/repo",
        base_branch="main"
    )
    
    assert fixer.installation_id == 12345
    assert fixer.repo_full_name == "owner/repo"
    assert fixer.base_branch == "main"


def test_can_fix_returns_true_for_fixable_patterns():
    """Test can_fix returns True for fixable patterns."""
    fixer = AutoPRFixer(12345, "owner/repo")
    
    fixable_finding = {
        "pattern_id": "REENTRANCY-001",
        "title": "Test",
    }
    
    assert fixer.can_fix(fixable_finding) is True


def test_can_fix_returns_false_for_unknown_patterns():
    """Test can_fix returns False for unknown patterns."""
    fixer = AutoPRFixer(12345, "owner/repo")
    
    unknown_finding = {
        "pattern_id": "UNKNOWN-PATTERN",
        "title": "Test",
    }
    
    assert fixer.can_fix(unknown_finding) is False


def test_generate_pr_title_single_finding(sample_findings):
    """Test PR title generation for single finding."""
    fixer = AutoPRFixer(12345, "owner/repo")
    
    title = fixer._generate_pr_title([sample_findings[0]])
    
    assert "Fix" in title
    assert "Potential Reentrancy" in title


def test_generate_pr_title_multiple_findings(sample_findings):
    """Test PR title generation for multiple findings."""
    fixer = AutoPRFixer(12345, "owner/repo")
    
    title = fixer._generate_pr_title(sample_findings)
    
    assert "Fix" in title
    assert "3" in title
    assert "high" in title


def test_generate_pr_body_contains_required_sections(sample_findings):
    """Test PR body contains all required sections."""
    fixer = AutoPRFixer(12345, "owner/repo")
    
    body = fixer._generate_pr_body(sample_findings, "scan_123")
    
    assert "Automated Security Fixes" in body
    assert "Fixed Issues" in body
    assert "Applied Fixes" in body
    assert "Important" in body
    assert "scan_123" in body
    assert "Hound" in body


def test_generate_pr_body_groups_by_severity(sample_findings):
    """Test PR body groups findings by severity."""
    fixer = AutoPRFixer(12345, "owner/repo")
    
    body = fixer._generate_pr_body(sample_findings)
    
    # Check for severity sections
    assert "HIGH" in body
    assert "🟠" in body  # High severity emoji


def test_fix_tx_origin():
    """Test tx.origin fix."""
    fixer = AutoPRFixer(12345, "owner/repo")
    
    # Create temp file with tx.origin
    with tempfile.TemporaryDirectory() as tmpdir:
        file_path = Path(tmpdir) / "Auth.sol"
        file_path.write_text(
            "contract Auth {\n"
            "    function isOwner() public view returns (bool) {\n"
            "        return tx.origin == owner;\n"
            "    }\n"
            "}\n"
        )
        
        finding = {
            "pattern_id": "TXORIGIN-001",
            "location": "Auth.sol:3",
        }
        
        fixer._fix_tx_origin(tmpdir, finding)
        
        fixed_content = file_path.read_text()
        assert "msg.sender" in fixed_content
        assert "tx.origin" not in fixed_content


def test_fix_integer_overflow():
    """Test integer overflow fix."""
    fixer = AutoPRFixer(12345, "owner/repo")
    
    # Create temp file with old Solidity version
    with tempfile.TemporaryDirectory() as tmpdir:
        file_path = Path(tmpdir) / "Token.sol"
        file_path.write_text(
            "pragma solidity ^0.7.0;\n"
            "contract Token {\n"
            "    uint256 public totalSupply;\n"
            "}\n"
        )
        
        finding = {
            "pattern_id": "OVERFLOW-001",
            "location": "Token.sol:3",
        }
        
        fixer._fix_integer_overflow(tmpdir, finding)
        
        fixed_content = file_path.read_text()
        assert "0.8.0" in fixed_content


@patch('subprocess.run')
def test_clone_and_fix_creates_branch(mock_run, sample_findings):
    """Test that clone_and_fix creates a new branch."""
    fixer = AutoPRFixer(12345, "owner/repo")
    
    result = {
        "fixes_applied": 0,
        "fixes_failed": 0,
        "errors": [],
    }
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create dummy files
        Path(tmpdir, "contracts").mkdir()
        Path(tmpdir, "contracts", "Token.sol").write_text("contract Token {}")
        
        # Mock git operations to succeed
        mock_run.return_value = Mock(returncode=0)
        
        fixer._clone_and_fix(
            "https://github.com/owner/repo.git",
            tmpdir,
            "hound-fixes-test",
            sample_findings,
            result,
        )
        
        # Verify git checkout was called
        calls = [str(call) for call in mock_run.call_args_list]
        assert any("checkout" in str(call) and "hound-fixes-test" in str(call) for call in calls)


def test_create_fix_pr_returns_error_for_no_fixable_findings():
    """Test that create_fix_pr returns error when no fixable findings."""
    fixer = AutoPRFixer(12345, "owner/repo")
    
    unfixable_findings = [
        {
            "pattern_id": "UNKNOWN-001",
            "title": "Unknown issue",
        }
    ]
    
    result = fixer.create_fix_pr(unfixable_findings)
    
    assert result["success"] is False
    assert "No fixable findings" in result["errors"][0]


def test_create_fix_pr_for_findings_convenience_function(mock_github, mock_clone_url):
    """Test convenience function."""
    with patch('integrations.auto_pr_fixer.AutoPRFixer.create_fix_pr') as mock_create:
        mock_create.return_value = {
            "success": True,
            "pr_number": 123,
            "pr_url": "https://github.com/owner/repo/pull/123",
        }
        
        result = create_fix_pr_for_findings(
            installation_id=12345,
            repo_full_name="owner/repo",
            findings=[{"pattern_id": "REENTRANCY-001", "title": "Test"}],
        )
        
        assert result["success"] is True
        assert result["pr_number"] == 123


def test_fix_reentrancy_adds_import():
    """Test that reentrancy fix adds ReentrancyGuard import."""
    fixer = AutoPRFixer(12345, "owner/repo")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        file_path = Path(tmpdir) / "Token.sol"
        file_path.write_text(
            "pragma solidity ^0.8.0;\n"
            "\n"
            "contract Token {\n"
            "    function withdraw() public {\n"
            "        // vulnerable code\n"
            "    }\n"
            "}\n"
        )
        
        finding = {
            "pattern_id": "REENTRANCY-001",
            "location": "Token.sol:5",
        }
        
        fixer._fix_reentrancy(tmpdir, finding)
        
        fixed_content = file_path.read_text()
        assert "ReentrancyGuard" in fixed_content


def test_fix_unchecked_call_adds_require():
    """Test that unchecked call fix adds require statement."""
    fixer = AutoPRFixer(12345, "owner/repo")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        file_path = Path(tmpdir) / "Vault.sol"
        file_path.write_text(
            "contract Vault {\n"
            "    function send() public {\n"
            "        payable(msg.sender).call{value: 1 ether}(\"\");\n"
            "    }\n"
            "}\n"
        )
        
        finding = {
            "pattern_id": "UNCHECKED-CALL-001",
            "location": "Vault.sol:3",
        }
        
        fixer._fix_unchecked_call(tmpdir, finding)
        
        fixed_content = file_path.read_text()
        assert "bool success" in fixed_content or "require" in fixed_content


def test_fix_missing_access_control_adds_onlyowner():
    """Test that access control fix adds onlyOwner."""
    fixer = AutoPRFixer(12345, "owner/repo")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        file_path = Path(tmpdir) / "Admin.sol"
        file_path.write_text(
            "contract Admin {\n"
            "    function setOwner() public {\n"
            "        // sensitive operation\n"
            "    }\n"
            "}\n"
        )
        
        finding = {
            "pattern_id": "ACCESS-001",
            "location": "Admin.sol:2",
        }
        
        fixer._fix_missing_access_control(tmpdir, finding)
        
        fixed_content = file_path.read_text()
        assert "Ownable" in fixed_content or "onlyOwner" in fixed_content
