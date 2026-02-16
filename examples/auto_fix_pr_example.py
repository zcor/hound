#!/usr/bin/env python3
"""
Example: Auto-create fix PRs when errors are detected.

This example demonstrates how to use Hound's auto-fix feature to
automatically create pull requests with fixes for detected vulnerabilities.

Usage:
    python examples/auto_fix_pr_example.py
    
    # Or with custom repo
    python examples/auto_fix_pr_example.py --repo owner/repo --installation-id 12345678
"""

import argparse
import os
import sys
from pathlib import Path

# Add parent directory to path so we can import from integrations
sys.path.insert(0, str(Path(__file__).parent.parent))

from integrations.auto_pr_fixer import create_fix_pr_for_findings


def example_1_create_fix_pr_with_findings():
    """
    Example 1: Create a fix PR with manually specified findings.
    
    This is useful when you have findings from a scan and want to
    create a fix PR for them.
    """
    print("=" * 60)
    print("Example 1: Create Fix PR with Findings")
    print("=" * 60)
    
    # These would typically come from a Hound scan
    findings = [
        {
            "pattern_id": "REENTRANCY-001",
            "title": "Potential Reentrancy",
            "severity": "high",
            "location": "contracts/Token.sol:42",
            "description": "External call before state update in withdraw function",
            "confidence": 0.8,
        },
        {
            "pattern_id": "UNCHECKED-CALL-001",
            "title": "Unchecked low-level call",
            "severity": "high",
            "location": "contracts/Vault.sol:15",
            "description": ".call() without return value check",
            "confidence": 0.9,
        },
        {
            "pattern_id": "TXORIGIN-001",
            "title": "tx.origin usage",
            "severity": "high",
            "location": "contracts/Auth.sol:28",
            "description": "Using tx.origin for authentication - use msg.sender instead",
            "confidence": 0.95,
        },
    ]
    
    # Get from environment
    installation_id = int(os.environ.get("GITHUB_INSTALLATION_ID", "0"))
    repo_full_name = os.environ.get("GITHUB_REPO", "owner/repo")
    
    if installation_id == 0:
        print("⚠️  GITHUB_INSTALLATION_ID not set in environment")
        print("   Set it to run this example:")
        print("   export GITHUB_INSTALLATION_ID=12345678")
        return
    
    print(f"\n📋 Creating fix PR for {len(findings)} findings...")
    print(f"   Repository: {repo_full_name}")
    print(f"   Installation ID: {installation_id}")
    
    try:
        result = create_fix_pr_for_findings(
            installation_id=installation_id,
            repo_full_name=repo_full_name,
            findings=findings,
            scan_id="example_scan_001",
            base_branch="main",
            auto_merge=False,  # Safety: require manual merge
        )
        
        if result["success"]:
            print("\n✅ Fix PR created successfully!")
            print(f"   PR #{result['pr_number']}: {result['pr_url']}")
            print(f"   Branch: {result['branch_name']}")
            print(f"   Fixes applied: {result['fixes_applied']}")
            
            if result['fixes_failed'] > 0:
                print(f"\n⚠️  {result['fixes_failed']} fixes failed:")
                for error in result['errors']:
                    print(f"   - {error}")
        else:
            print("\n❌ Failed to create fix PR:")
            for error in result['errors']:
                print(f"   - {error}")
                
    except Exception as e:
        print(f"\n❌ Error: {e}")


def example_2_filter_fixable_findings():
    """
    Example 2: Filter findings to only those that can be fixed.
    
    Not all patterns have automated fixes. This example shows how to
    filter findings to only those that can be automatically fixed.
    """
    print("\n" + "=" * 60)
    print("Example 2: Filter Fixable Findings")
    print("=" * 60)
    
    from integrations.auto_pr_fixer import AutoPRFixer
    
    installation_id = int(os.environ.get("GITHUB_INSTALLATION_ID", "0"))
    repo_full_name = os.environ.get("GITHUB_REPO", "owner/repo")
    
    if installation_id == 0:
        print("⚠️  GITHUB_INSTALLATION_ID not set")
        return
    
    # Mix of fixable and non-fixable findings
    all_findings = [
        {"pattern_id": "REENTRANCY-001", "title": "Reentrancy", "severity": "high"},
        {"pattern_id": "COMPLEX-LOGIC-001", "title": "Complex Logic", "severity": "medium"},
        {"pattern_id": "UNCHECKED-CALL-001", "title": "Unchecked Call", "severity": "high"},
        {"pattern_id": "FRONTRUN-001", "title": "Frontrunning Risk", "severity": "medium"},
        {"pattern_id": "TXORIGIN-001", "title": "tx.origin", "severity": "high"},
    ]
    
    fixer = AutoPRFixer(installation_id, repo_full_name)
    
    fixable = [f for f in all_findings if fixer.can_fix(f)]
    unfixable = [f for f in all_findings if not fixer.can_fix(f)]
    
    print("\n📊 Finding Analysis:")
    print(f"   Total findings: {len(all_findings)}")
    print(f"   Fixable: {len(fixable)}")
    print(f"   Not fixable: {len(unfixable)}")
    
    print("\n✅ Fixable findings:")
    for f in fixable:
        print(f"   - {f['pattern_id']}: {f['title']}")
    
    print("\n⚠️  Non-fixable findings (require manual review):")
    for f in unfixable:
        print(f"   - {f['pattern_id']}: {f['title']}")


def example_3_scan_and_auto_fix():
    """
    Example 3: Run a scan and automatically create fix PR.
    
    This example shows the complete workflow:
    1. Run a surface scan
    2. Filter for fixable issues
    3. Create a fix PR automatically
    """
    print("\n" + "=" * 60)
    print("Example 3: Scan and Auto-Fix")
    print("=" * 60)
    
    from analysis.surface.scanner import SurfaceScanner
    from integrations.auto_pr_fixer import AutoPRFixer
    
    installation_id = int(os.environ.get("GITHUB_INSTALLATION_ID", "0"))
    repo_url = os.environ.get("GITHUB_REPO_URL", "https://github.com/owner/repo")
    repo_full_name = os.environ.get("GITHUB_REPO", "owner/repo")
    
    if installation_id == 0:
        print("⚠️  GITHUB_INSTALLATION_ID not set")
        return
    
    print(f"\n🔍 Scanning repository: {repo_url}")
    
    # Run surface scan
    scanner = SurfaceScanner(llm_budget=5, quiet=False)
    
    try:
        scan_result = scanner.scan(repo_url)
        
        if scan_result.error:
            print(f"\n❌ Scan failed: {scan_result.error}")
            return
        
        print("\n📊 Scan complete!")
        print(f"   Risk score: {scan_result.risk_score}/100 ({scan_result.risk_level})")
        print(f"   Findings: {len(scan_result.findings)}")
        
        # Convert findings to fix format
        findings = []
        for f in scan_result.findings:
            findings.append({
                "pattern_id": f.pattern_id,
                "title": f.title,
                "severity": f.severity,
                "location": f.location,
                "description": f.description,
                "confidence": f.confidence,
            })
        
        # Filter fixable findings
        fixer = AutoPRFixer(installation_id, repo_full_name)
        fixable = [f for f in findings if fixer.can_fix(f)]
        
        if not fixable:
            print("\n⚠️  No fixable findings detected")
            return
        
        print(f"\n🔧 Found {len(fixable)} fixable issues")
        print("   Creating fix PR...")
        
        # Create fix PR
        result = fixer.create_fix_pr(
            fixable,
            scan_id=scan_result.repo_name,
            auto_merge=False,
        )
        
        if result["success"]:
            print("\n✅ Fix PR created!")
            print(f"   {result['pr_url']}")
        else:
            print("\n❌ Failed to create PR:")
            for error in result['errors']:
                print(f"   - {error}")
                
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Examples of auto-fix PR creation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--example",
        type=int,
        choices=[1, 2, 3],
        help="Which example to run (1, 2, or 3). If not specified, runs all.",
    )
    parser.add_argument(
        "--repo",
        help="GitHub repository (owner/repo)",
    )
    parser.add_argument(
        "--installation-id",
        type=int,
        help="GitHub App installation ID",
    )
    
    args = parser.parse_args()
    
    # Override environment if provided
    if args.repo:
        os.environ["GITHUB_REPO"] = args.repo
    if args.installation_id:
        os.environ["GITHUB_INSTALLATION_ID"] = str(args.installation_id)
    
    print("🐕 Hound Auto-Fix PR Examples")
    print()
    
    # Check for required credentials
    if not os.environ.get("GITHUB_APP_ID"):
        print("❌ Missing GITHUB_APP_ID environment variable")
        print("   Set up your GitHub App credentials first:")
        print("   export GITHUB_APP_ID=123456")
        print("   export GITHUB_APP_PRIVATE_KEY='...'")
        return 1
    
    if not os.environ.get("GITHUB_APP_PRIVATE_KEY") and not os.environ.get("GITHUB_APP_PRIVATE_KEY_PATH"):
        print("❌ Missing GitHub App private key")
        print("   Set GITHUB_APP_PRIVATE_KEY or GITHUB_APP_PRIVATE_KEY_PATH")
        return 1
    
    # Run examples
    if args.example == 1 or args.example is None:
        example_1_create_fix_pr_with_findings()
    
    if args.example == 2 or args.example is None:
        example_2_filter_fixable_findings()
    
    if args.example == 3 or args.example is None:
        example_3_scan_and_auto_fix()
    
    print("\n" + "=" * 60)
    print("Examples complete!")
    print("=" * 60)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
