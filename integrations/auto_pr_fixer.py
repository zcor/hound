"""
Automatic PR creation with fixes for detected security issues.

When Hound detects errors in code during scans, this module can:
- Generate fixes for common vulnerabilities
- Create a new branch with the fixes
- Open a pull request with the changes
- Add detailed descriptions and recommendations
"""

import logging
import shutil
import tempfile
from datetime import datetime
from pathlib import Path

from github import Github
from github.Repository import Repository

from integrations.github_auth import get_authenticated_github_client, get_clone_url_with_token

logger = logging.getLogger(__name__)


class AutoPRFixer:
    """
    Automatically creates PRs with fixes for detected security issues.
    
    Features:
    - Generates fixes for common vulnerability patterns
    - Creates feature branches
    - Opens PRs with detailed descriptions
    - Links back to original scan results
    """
    
    # Map vulnerability patterns to fix generators
    FIX_GENERATORS = {
        "REENTRANCY-001": "_fix_reentrancy",
        "UNCHECKED-CALL-001": "_fix_unchecked_call",
        "ACCESS-001": "_fix_missing_access_control",
        "TXORIGIN-001": "_fix_tx_origin",
        "OVERFLOW-001": "_fix_integer_overflow",
    }
    
    def __init__(
        self,
        installation_id: int,
        repo_full_name: str,
        base_branch: str = "main",
    ):
        """
        Initialize the auto PR fixer.
        
        Args:
            installation_id: GitHub App installation ID
            repo_full_name: Repository full name (owner/repo)
            base_branch: Base branch to create PR against (default: main)
        """
        self.installation_id = installation_id
        self.repo_full_name = repo_full_name
        self.base_branch = base_branch
        
        self._github: Github | None = None
        self._repo: Repository | None = None
    
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
    
    def can_fix(self, finding: dict) -> bool:
        """
        Check if we can automatically fix a finding.
        
        Args:
            finding: Finding dictionary from scanner
            
        Returns:
            True if we have a fix generator for this pattern
        """
        pattern_id = finding.get("pattern_id", "")
        return pattern_id in self.FIX_GENERATORS
    
    def create_fix_pr(
        self,
        findings: list[dict],
        scan_id: str | None = None,
        auto_merge: bool = False,
    ) -> dict:
        """
        Create a PR with fixes for the provided findings.
        
        This is the main method to call for creating fix PRs.
        
        Args:
            findings: List of findings to fix
            scan_id: Optional scan ID for reference
            auto_merge: Whether to enable auto-merge if checks pass
            
        Returns:
            Dict with PR creation results
        """
        result = {
            "success": False,
            "pr_number": None,
            "pr_url": None,
            "branch_name": None,
            "fixes_applied": 0,
            "fixes_failed": 0,
            "errors": [],
        }
        
        # Filter to fixable findings
        fixable = [f for f in findings if self.can_fix(f)]
        
        if not fixable:
            result["errors"].append("No fixable findings provided")
            return result
        
        logger.info(f"Creating fix PR for {len(fixable)} findings in {self.repo_full_name}")
        
        try:
            # Create branch name
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            branch_name = f"hound-fixes-{timestamp}"
            result["branch_name"] = branch_name
            
            # Clone repository to temp directory
            temp_dir = tempfile.mkdtemp(prefix="hound_fix_")
            
            try:
                # Clone repo
                clone_url = get_clone_url_with_token(
                    f"https://github.com/{self.repo_full_name}",
                    self.installation_id
                )
                
                self._clone_and_fix(
                    clone_url,
                    temp_dir,
                    branch_name,
                    fixable,
                    result
                )
                
                # Create PR
                if result["fixes_applied"] > 0:
                    pr_title = self._generate_pr_title(fixable)
                    pr_body = self._generate_pr_body(fixable, scan_id)
                    
                    pr = self.repo.create_pull(
                        title=pr_title,
                        body=pr_body,
                        head=branch_name,
                        base=self.base_branch,
                    )
                    
                    result["pr_number"] = pr.number
                    result["pr_url"] = pr.html_url
                    result["success"] = True
                    
                    # Enable auto-merge if requested
                    if auto_merge:
                        try:
                            pr.enable_automerge()
                        except Exception as e:
                            logger.warning(f"Failed to enable auto-merge: {e}")
                    
                    logger.info(f"Created fix PR #{pr.number}: {pr.html_url}")
                
            finally:
                # Cleanup temp directory
                shutil.rmtree(temp_dir, ignore_errors=True)
                
        except Exception as e:
            logger.exception(f"Failed to create fix PR: {e}")
            result["errors"].append(str(e))
        
        return result
    
    def _clone_and_fix(
        self,
        clone_url: str,
        temp_dir: str,
        branch_name: str,
        findings: list[dict],
        result: dict,
    ):
        """Clone repository and apply fixes."""
        import subprocess
        
        try:
            # Clone repository
            subprocess.run(
                ["git", "clone", clone_url, temp_dir],
                check=True,
                capture_output=True,
            )
            
            # Create new branch
            subprocess.run(
                ["git", "checkout", "-b", branch_name],
                cwd=temp_dir,
                check=True,
                capture_output=True,
            )
            
            # Apply fixes
            for finding in findings:
                try:
                    self._apply_fix(temp_dir, finding)
                    result["fixes_applied"] += 1
                except Exception as e:
                    logger.warning(f"Failed to apply fix for {finding.get('title')}: {e}")
                    result["fixes_failed"] += 1
                    result["errors"].append(f"Fix failed: {finding.get('title')} - {e}")
            
            # Commit and push
            if result["fixes_applied"] > 0:
                subprocess.run(
                    ["git", "add", "-A"],
                    cwd=temp_dir,
                    check=True,
                )
                
                commit_msg = f"🐕 Fix {result['fixes_applied']} security issue(s) detected by Hound"
                subprocess.run(
                    ["git", "commit", "-m", commit_msg],
                    cwd=temp_dir,
                    check=True,
                    capture_output=True,
                )
                
                subprocess.run(
                    ["git", "push", "origin", branch_name],
                    cwd=temp_dir,
                    check=True,
                    capture_output=True,
                )
                
        except subprocess.CalledProcessError as e:
            raise Exception(f"Git operation failed: {e.stderr.decode() if e.stderr else str(e)}")
    
    def _apply_fix(self, repo_path: str, finding: dict):
        """Apply a fix for a single finding."""
        pattern_id = finding.get("pattern_id", "")
        
        if pattern_id not in self.FIX_GENERATORS:
            raise ValueError(f"No fix generator for pattern {pattern_id}")
        
        # Get fix generator method
        fix_method_name = self.FIX_GENERATORS[pattern_id]
        fix_method = getattr(self, fix_method_name)
        
        # Apply fix
        fix_method(repo_path, finding)
    
    def _fix_reentrancy(self, repo_path: str, finding: dict):
        """Fix reentrancy vulnerability by adding ReentrancyGuard."""
        location = finding.get("location", "")
        if not location or ":" not in location:
            raise ValueError("Invalid location format")
        
        file_path, line_str = location.rsplit(":", 1)
        line_num = int(line_str)
        
        full_path = Path(repo_path) / file_path
        if not full_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        content = full_path.read_text()
        lines = content.split('\n')
        
        # Add ReentrancyGuard import if not present
        has_import = any("ReentrancyGuard" in line for line in lines)
        
        if not has_import:
            # Find import section
            import_idx = 0
            for i, line in enumerate(lines):
                if line.strip().startswith("import"):
                    import_idx = i + 1
            
            lines.insert(import_idx, 'import "@openzeppelin/contracts/security/ReentrancyGuard.sol";')
        
        # Add nonReentrant modifier to vulnerable function
        # Find the function containing the vulnerability
        for i in range(max(0, line_num - 5), min(len(lines), line_num + 5)):
            if "function" in lines[i]:
                # Add nonReentrant if not present
                if "nonReentrant" not in lines[i]:
                    # Find the opening brace
                    if "{" in lines[i]:
                        lines[i] = lines[i].replace("{", "nonReentrant {")
                    else:
                        # Check next few lines
                        for j in range(i + 1, min(len(lines), i + 5)):
                            if "{" in lines[j]:
                                lines[j] = "    nonReentrant " + lines[j]
                                break
                break
        
        # Write back
        full_path.write_text('\n'.join(lines))
    
    def _fix_unchecked_call(self, repo_path: str, finding: dict):
        """Fix unchecked low-level call by adding return value check."""
        location = finding.get("location", "")
        if not location or ":" not in location:
            raise ValueError("Invalid location format")
        
        file_path, line_str = location.rsplit(":", 1)
        line_num = int(line_str)
        
        full_path = Path(repo_path) / file_path
        if not full_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        content = full_path.read_text()
        lines = content.split('\n')
        
        # Find the call and add check
        if line_num <= len(lines):
            line = lines[line_num - 1]
            
            # If .call() is not captured, add capture and check
            if ".call" in line and "(" in line:
                indent = len(line) - len(line.lstrip())
                indent_str = " " * indent
                
                # Replace line to capture return value
                if not line.strip().startswith("("):
                    lines[line_num - 1] = f"{indent_str}(bool success, ) = {line.strip()}"
                    # Add require check on next line
                    lines.insert(line_num, f'{indent_str}require(success, "Call failed");')
        
        # Write back
        full_path.write_text('\n'.join(lines))
    
    def _fix_missing_access_control(self, repo_path: str, finding: dict):
        """Fix missing access control by adding onlyOwner modifier."""
        location = finding.get("location", "")
        if not location or ":" not in location:
            raise ValueError("Invalid location format")
        
        file_path, line_str = location.rsplit(":", 1)
        line_num = int(line_str)
        
        full_path = Path(repo_path) / file_path
        if not full_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        content = full_path.read_text()
        lines = content.split('\n')
        
        # Add Ownable import if not present
        has_ownable = any("Ownable" in line for line in lines)
        
        if not has_ownable:
            # Find import section
            import_idx = 0
            for i, line in enumerate(lines):
                if line.strip().startswith("import"):
                    import_idx = i + 1
            
            lines.insert(import_idx, 'import "@openzeppelin/contracts/access/Ownable.sol";')
            
            # Inherit Ownable in contract
            for i, line in enumerate(lines):
                if "contract" in line and "{" in line:
                    if "is" not in line:
                        lines[i] = line.replace("{", "is Ownable {")
                    elif "Ownable" not in line:
                        lines[i] = line.replace("is", "is Ownable,")
                    break
        
        # Add onlyOwner modifier to function
        for i in range(max(0, line_num - 5), min(len(lines), line_num + 5)):
            if "function" in lines[i]:
                # Add onlyOwner if not present
                if "onlyOwner" not in lines[i] and "only" not in lines[i].lower():
                    if "{" in lines[i]:
                        lines[i] = lines[i].replace("{", "onlyOwner {")
                    else:
                        # Check next few lines
                        for j in range(i + 1, min(len(lines), i + 5)):
                            if "{" in lines[j]:
                                lines[j] = "    onlyOwner " + lines[j]
                                break
                break
        
        # Write back
        full_path.write_text('\n'.join(lines))
    
    def _fix_tx_origin(self, repo_path: str, finding: dict):
        """Fix tx.origin usage by replacing with msg.sender."""
        location = finding.get("location", "")
        if not location or ":" not in location:
            raise ValueError("Invalid location format")
        
        file_path, line_str = location.rsplit(":", 1)
        line_num = int(line_str)
        
        full_path = Path(repo_path) / file_path
        if not full_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        content = full_path.read_text()
        lines = content.split('\n')
        
        # Replace tx.origin with msg.sender
        if line_num <= len(lines):
            lines[line_num - 1] = lines[line_num - 1].replace("tx.origin", "msg.sender")
        
        # Write back
        full_path.write_text('\n'.join(lines))
    
    def _fix_integer_overflow(self, repo_path: str, finding: dict):
        """Fix integer overflow by adding SafeMath or upgrading to Solidity 0.8+."""
        location = finding.get("location", "")
        if not location or ":" not in location:
            raise ValueError("Invalid location format")
        
        file_path, line_str = location.rsplit(":", 1)
        
        full_path = Path(repo_path) / file_path
        if not full_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        content = full_path.read_text()
        lines = content.split('\n')
        
        # Check current Solidity version
        version_line = next((line for line in lines if "pragma solidity" in line), None)
        
        if version_line:
            # Update to ^0.8.0 if using older version
            if "0.8" not in version_line:
                for i, line in enumerate(lines):
                    if "pragma solidity" in line:
                        lines[i] = "pragma solidity ^0.8.0;"
                        break
        
        # Write back
        full_path.write_text('\n'.join(lines))
    
    def _generate_pr_title(self, findings: list[dict]) -> str:
        """Generate PR title based on findings."""
        if len(findings) == 1:
            return f"🐕 Fix: {findings[0].get('title', 'Security issue')}"
        else:
            severity_counts = {}
            for f in findings:
                sev = f.get("severity", "medium")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            # Get highest severity
            for sev in ["critical", "high", "medium", "low"]:
                if sev in severity_counts:
                    return f"🐕 Fix {len(findings)} {sev} security issues"
            
            return f"🐕 Fix {len(findings)} security issues"
    
    def _generate_pr_body(self, findings: list[dict], scan_id: str | None = None) -> str:
        """Generate PR body with fix details."""
        lines = [
            "# 🐕 Automated Security Fixes by Hound",
            "",
            f"This PR contains automated fixes for **{len(findings)}** security issue(s) detected by Hound.",
            "",
            "## Fixed Issues",
            "",
        ]
        
        # Group by severity
        by_severity = {}
        for f in findings:
            sev = f.get("severity", "medium")
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(f)
        
        # Add sections by severity
        severity_emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
        }
        
        for severity in ["critical", "high", "medium", "low"]:
            if severity not in by_severity:
                continue
            
            emoji = severity_emoji.get(severity, "⚪")
            issues = by_severity[severity]
            
            lines.append(f"### {emoji} {severity.upper()} ({len(issues)})")
            lines.append("")
            
            for finding in issues:
                title = finding.get("title", "Unknown")
                location = finding.get("location", "")
                description = finding.get("description", "")
                
                lines.append(f"- **{title}**")
                if location:
                    lines.append(f"  - Location: `{location}`")
                if description:
                    lines.append(f"  - {description[:100]}...")
                lines.append("")
        
        lines.extend([
            "## Applied Fixes",
            "",
            "The following fixes were automatically applied:",
            "",
        ])
        
        # List fix types
        fix_types = set()
        for finding in findings:
            pattern_id = finding.get("pattern_id", "")
            if pattern_id == "REENTRANCY-001":
                fix_types.add("✅ Added `ReentrancyGuard` protection")
            elif pattern_id == "UNCHECKED-CALL-001":
                fix_types.add("✅ Added return value checks for low-level calls")
            elif pattern_id == "ACCESS-001":
                fix_types.add("✅ Added `onlyOwner` access control")
            elif pattern_id == "TXORIGIN-001":
                fix_types.add("✅ Replaced `tx.origin` with `msg.sender`")
            elif pattern_id == "OVERFLOW-001":
                fix_types.add("✅ Upgraded Solidity version to 0.8+ (built-in overflow protection)")
        
        for fix_type in sorted(fix_types):
            lines.append(f"- {fix_type}")
        
        lines.extend([
            "",
            "## ⚠️ Important",
            "",
            "**These are automated fixes.** Please:",
            "1. Review all changes carefully",
            "2. Run your test suite to ensure nothing broke",
            "3. Consider a professional security audit for production code",
            "",
            "## Next Steps",
            "",
            "- [ ] Review the changes",
            "- [ ] Run tests",
            "- [ ] Update documentation if needed",
            "- [ ] Consider additional security measures",
            "",
            "---",
        ])
        
        if scan_id:
            lines.append(f"_Scan ID: `{scan_id}`_")
        
        lines.append("_🐕 [Hound](https://github.com/muellerberndt/hound) - Automated Security Analysis_")
        
        return "\n".join(lines)


def create_fix_pr_for_findings(
    installation_id: int,
    repo_full_name: str,
    findings: list[dict],
    scan_id: str | None = None,
    base_branch: str = "main",
    auto_merge: bool = False,
) -> dict:
    """
    Convenience function to create a fix PR.
    
    Args:
        installation_id: GitHub App installation ID
        repo_full_name: Repository full name (owner/repo)
        findings: List of findings to fix
        scan_id: Optional scan ID for reference
        base_branch: Base branch for PR (default: main)
        auto_merge: Whether to enable auto-merge
        
    Returns:
        Dict with PR creation results
        
    Example:
        result = create_fix_pr_for_findings(
            installation_id=12345678,
            repo_full_name="owner/repo",
            findings=fixable_findings,
            scan_id="scan_abc123",
        )
        
        if result["success"]:
            print(f"Created PR: {result['pr_url']}")
    """
    fixer = AutoPRFixer(
        installation_id=installation_id,
        repo_full_name=repo_full_name,
        base_branch=base_branch,
    )
    
    return fixer.create_fix_pr(findings, scan_id, auto_merge)
