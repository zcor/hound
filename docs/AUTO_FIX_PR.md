# Auto-Fix PR Feature

Hound can automatically create Pull Requests with fixes for detected security vulnerabilities.

## Overview

When Hound detects security issues during a scan, it can:
1. Generate fixes for common vulnerability patterns
2. Create a new branch with the applied fixes
3. Open a pull request with detailed descriptions
4. Link back to the original scan results

## Supported Fixes

The auto-fix feature currently supports these vulnerability patterns:

### 1. Reentrancy (REENTRANCY-001)
- **Fix**: Adds OpenZeppelin's `ReentrancyGuard` contract
- **Changes**: 
  - Imports `@openzeppelin/contracts/security/ReentrancyGuard.sol`
  - Adds `nonReentrant` modifier to vulnerable functions

### 2. Unchecked Low-Level Calls (UNCHECKED-CALL-001)
- **Fix**: Adds return value checks
- **Changes**:
  - Captures `(bool success, )` from `.call()`
  - Adds `require(success, "Call failed")` checks

### 3. Missing Access Control (ACCESS-001)
- **Fix**: Adds OpenZeppelin's `Ownable` contract
- **Changes**:
  - Imports `@openzeppelin/contracts/access/Ownable.sol`
  - Inherits from `Ownable`
  - Adds `onlyOwner` modifier to sensitive functions

### 4. tx.origin Usage (TXORIGIN-001)
- **Fix**: Replaces with `msg.sender`
- **Changes**:
  - Replaces all `tx.origin` references with `msg.sender`

### 5. Integer Overflow (OVERFLOW-001)
- **Fix**: Upgrades Solidity version
- **Changes**:
  - Updates `pragma solidity` to `^0.8.0` (built-in overflow protection)

## Usage

### Via API

#### Option 1: During Audit

Enable auto-fix when starting an audit:

```bash
curl -X POST http://localhost:8000/audits/start \
  -H "Content-Type: application/json" \
  -d '{
    "repo_url": "https://github.com/owner/repo",
    "installation_id": 12345678,
    "repo_full_name": "owner/repo",
    "auto_create_fix_pr": true,
    "base_branch": "main"
  }'
```

#### Option 2: After Audit Completes

Create a fix PR after an audit has completed:

```bash
curl -X POST http://localhost:8000/audits/audit_abc123/create-fix-pr \
  -H "Content-Type: application/json" \
  -d '{
    "installation_id": 12345678,
    "repo_full_name": "owner/repo",
    "base_branch": "main",
    "auto_merge": false
  }'
```

#### Option 3: Standalone (Manual Findings)

Create a fix PR with manually provided findings:

```bash
curl -X POST http://localhost:8000/github/create-fix-pr \
  -H "Content-Type: application/json" \
  -d '{
    "installation_id": 12345678,
    "repo_full_name": "owner/repo",
    "findings": [
      {
        "pattern_id": "REENTRANCY-001",
        "title": "Potential Reentrancy",
        "severity": "high",
        "location": "contracts/Token.sol:42",
        "description": "External call before state update"
      }
    ],
    "base_branch": "main"
  }'
```

### Via Python

```python
from integrations.auto_pr_fixer import create_fix_pr_for_findings

findings = [
    {
        "pattern_id": "REENTRANCY-001",
        "title": "Potential Reentrancy",
        "severity": "high",
        "location": "contracts/Token.sol:42",
        "description": "External call before state update",
        "confidence": 0.8,
    }
]

result = create_fix_pr_for_findings(
    installation_id=12345678,
    repo_full_name="owner/repo",
    findings=findings,
    scan_id="scan_abc123",
    base_branch="main",
    auto_merge=False,
)

if result["success"]:
    print(f"Created PR #{result['pr_number']}: {result['pr_url']}")
    print(f"Applied {result['fixes_applied']} fixes")
else:
    print(f"Failed: {result['errors']}")
```

## Response Format

### Success Response

```json
{
  "success": true,
  "pr_number": 123,
  "pr_url": "https://github.com/owner/repo/pull/123",
  "branch_name": "hound-fixes-20240101-120000",
  "fixes_applied": 3,
  "fixes_failed": 0,
  "errors": []
}
```

### Error Response

```json
{
  "success": false,
  "pr_number": null,
  "pr_url": null,
  "branch_name": "hound-fixes-20240101-120000",
  "fixes_applied": 1,
  "fixes_failed": 2,
  "errors": [
    "Fix failed: Missing access control - File not found: contracts/Admin.sol",
    "Fix failed: Unchecked call - Invalid location format"
  ]
}
```

## Generated PR Example

The auto-fix feature creates well-formatted PRs with:

### Title
```
🐕 Fix 3 high security issues
```

### Body

```markdown
# 🐕 Automated Security Fixes by Hound

This PR contains automated fixes for **3** security issue(s) detected by Hound.

## Fixed Issues

### 🟠 HIGH (3)

- **Potential Reentrancy**
  - Location: `contracts/Token.sol:42`
  - External call before state update...

- **Unchecked low-level call**
  - Location: `contracts/Vault.sol:15`
  - .call() without return check...

- **tx.origin usage**
  - Location: `contracts/Auth.sol:28`
  - Using tx.origin for authentication...

## Applied Fixes

The following fixes were automatically applied:

- ✅ Added `ReentrancyGuard` protection
- ✅ Added return value checks for low-level calls
- ✅ Replaced `tx.origin` with `msg.sender`

## ⚠️ Important

**These are automated fixes.** Please:
1. Review all changes carefully
2. Run your test suite to ensure nothing broke
3. Consider a professional security audit for production code

## Next Steps

- [ ] Review the changes
- [ ] Run tests
- [ ] Update documentation if needed
- [ ] Consider additional security measures

---
_Scan ID: `scan_abc123`_
_🐕 [Hound](https://github.com/muellerberndt/hound) - Automated Security Analysis_
```

## Requirements

### Environment Variables

```bash
# GitHub App credentials (required)
export GITHUB_APP_ID=123456
export GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----..."

# Or use path to key file
export GITHUB_APP_PRIVATE_KEY_PATH=/path/to/private-key.pem
```

### GitHub App Permissions

The GitHub App needs these permissions:
- **Repository permissions**:
  - Contents: Read & Write (for creating branches and commits)
  - Pull requests: Read & Write (for creating PRs)
  - Metadata: Read (for repository access)

### Dependencies

The following need to be installed on the server:
- `git` command-line tool
- Python packages (already in requirements.txt):
  - `PyGithub`
  - `jwt`

## Limitations

### What Gets Fixed

Only patterns with defined fix generators can be automatically fixed:
- `REENTRANCY-001` ✅
- `UNCHECKED-CALL-001` ✅
- `ACCESS-001` ✅
- `TXORIGIN-001` ✅
- `OVERFLOW-001` ✅

Other patterns will be included in the report but not automatically fixed.

### Code Quality Assumptions

The auto-fix assumes:
- Code follows common Solidity patterns
- OpenZeppelin contracts are available
- Standard import paths are used
- Code compiles before fixes are applied

### Manual Review Required

⚠️ **Always review auto-generated fixes before merging!**

Automated fixes may:
- Not compile if dependencies are missing
- Break tests if they change function signatures
- Not address the root cause in complex scenarios
- Require additional configuration

## Best Practices

### 1. Test Before Merge

Always run your test suite after applying auto-fixes:

```bash
# After PR is created
git fetch origin
git checkout hound-fixes-20240101-120000
npm test  # or your test command
```

### 2. Review Each Change

Use GitHub's PR review interface to:
- Check each file change
- Verify fixes make sense in context
- Look for compilation errors
- Ensure no functionality is broken

### 3. Start with Low-Risk Repos

Test the auto-fix feature on:
- Non-production repositories
- Test branches
- Repositories with good test coverage

### 4. Monitor False Positives

The scanner may detect:
- False positive vulnerabilities
- Patterns that are safe in context
- Intentional design decisions

Review findings before creating fix PRs.

### 5. Gradual Adoption

Start with:
1. Review mode only (no auto-fix)
2. Auto-fix on test repositories
3. Auto-fix with manual review
4. Consider auto-merge only with comprehensive tests

## Troubleshooting

### "No fixable findings provided"

**Cause**: No findings match supported fix patterns.

**Solution**: Check that findings have valid `pattern_id` values matching supported patterns.

### "File not found"

**Cause**: The file path in the finding doesn't exist in the repository.

**Solution**: Verify the `location` field in findings uses correct relative paths from repository root.

### "Git operation failed"

**Cause**: Git commands failed during branch creation or push.

**Solutions**:
- Verify GitHub App has write permissions
- Check that base branch exists
- Ensure installation token is valid

### "Failed to clone repository"

**Cause**: Repository access issues.

**Solutions**:
- Verify installation ID is correct
- Check GitHub App is installed on the repository
- Ensure private key is properly configured

## Security Considerations

### Credentials

- GitHub App private keys are sensitive - never commit them
- Use environment variables or secure key storage
- Rotate keys if compromised

### PR Creation

- Auto-created PRs should require review before merge
- Don't enable auto-merge on production repositories
- Limit who can trigger auto-fix PRs

### Code Changes

- All changes are committed with Hound's name
- PRs clearly indicate they are automated
- Changes are transparent in commit history

## API Reference

See [API_REFERENCE.md](./API_REFERENCE.md) for complete API documentation of the auto-fix endpoints.

## Examples

See [examples/auto_fix_pr_example.py](../examples/auto_fix_pr_example.py) for working code examples.
