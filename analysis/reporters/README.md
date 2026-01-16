# GitHub PR Reporter

The GitHub PR Reporter allows you to post Hound security findings directly to GitHub Pull Requests as review comments.

## Features

- 📝 Posts security findings as PR review comments
- 🎯 Line-specific comments for findings with file/line information
- 🔴 Severity-based emojis (🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Low)
- 📊 Summary comment with all findings
- ⚠️ Automatic review event (REQUEST_CHANGES for critical/high, COMMENT for medium/low)

## Usage

### Basic Usage

```python
from analysis.report_generator import ReportGenerator
from analysis.reporters.github_pr import GitHubPRReporter

# 1. Get findings from report generator
generator = ReportGenerator(project_dir, config)
findings = generator._get_confirmed_findings()

# 2. Initialize PR reporter
reporter = GitHubPRReporter(
    repo_full_name="owner/repo",
    pr_number=42,
    token="ghp_your_token_here"  # or set GITHUB_TOKEN env var
)

# 3. Post findings to PR
result = reporter.report(findings)

# 4. Check result
if result["status"] == "success":
    print(f"Posted {result['comments_posted']} comments to PR")
else:
    print(f"Error: {result['error']}")
```

### Using the Example Script

The easiest way to use the reporter is with the provided example script:

```bash
# Set GitHub token
export GITHUB_TOKEN="ghp_your_token_here"

# Post findings to PR
python examples/github_pr_comment.py my-project owner/repo 42
```

### Integration with CI/CD

You can integrate the reporter into your CI/CD pipeline:

```yaml
# .github/workflows/security-audit.yml
name: Hound Security Audit

on:
  pull_request:
    types: [opened, synchronize]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Hound Analysis
        run: |
          hound project create pr-audit --source .
          hound graph build pr-audit
          hound agent run pr-audit
      
      - name: Post Findings to PR
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          python examples/github_pr_comment.py pr-audit ${{ github.repository }} ${{ github.event.pull_request.number }}
```

## Authentication

The reporter supports two methods of authentication:

### 1. Personal Access Token (PAT)

Generate a [personal access token](https://github.com/settings/tokens) with these scopes:
- `repo` (Full control of private repositories)
- `write:discussion` (Read and write team discussions)

```python
reporter = GitHubPRReporter(
    repo_full_name="owner/repo",
    pr_number=42,
    token="ghp_your_token_here"
)
```

### 2. Environment Variable

Set the `GITHUB_TOKEN` environment variable:

```bash
export GITHUB_TOKEN="ghp_your_token_here"
```

Then initialize without the token parameter:

```python
reporter = GitHubPRReporter(
    repo_full_name="owner/repo",
    pr_number=42
)
```

## Output Format

### Summary Comment

The reporter posts a summary comment at the PR level with:
- Overall count of findings
- Breakdown by severity
- Brief description of each finding

Example:
```markdown
# 🐕 Hound Security Analysis

Found **3** security finding(s) in this PR:

- 🔴 **Critical**: 1
- 🟠 **High**: 1
- 🟡 **Medium**: 1

---

## Findings

### 🔴 [CRITICAL] SQL Injection Vulnerability

A SQL injection vulnerability exists in the user authentication module...

**Affected:** the AuthModule and UserController components
```

### Line-Specific Comments

For findings with file and line information, the reporter creates inline code review comments:

```markdown
🔴 **[Hound] SQL Injection Vulnerability**

**Severity:** CRITICAL

A SQL injection vulnerability exists in the user authentication module where user input is directly concatenated into SQL queries without proper sanitization.

**Context:** User input directly concatenated into SQL query
```

## API Reference

### GitHubPRReporter

```python
class GitHubPRReporter(Reporter):
    def __init__(
        self,
        repo_full_name: str,
        pr_number: int,
        token: str | None = None,
        installation_id: int | None = None
    )
```

**Parameters:**
- `repo_full_name`: Full repository name (e.g., "owner/repo")
- `pr_number`: Pull request number
- `token`: GitHub access token (optional, uses GITHUB_TOKEN env var)
- `installation_id`: GitHub App installation ID (optional)

**Methods:**

#### `report(findings: list[dict]) -> dict`

Posts findings to the PR as a review.

**Returns:**
```python
{
    "status": "success",  # or "error"
    "review_id": 123,     # GitHub review ID
    "comments_posted": 2,  # Number of line comments
    "summary_posted": True,
    "review_event": "REQUEST_CHANGES"  # or "COMMENT"
}
```

## Finding Format

Findings should follow this structure (as returned by `ReportGenerator._get_confirmed_findings()`):

```python
{
    "id": "hyp_001",
    "title": "Vulnerability Title",
    "severity": "critical",  # critical, high, medium, low
    "type": "vulnerability_type",
    "description": "Raw description",
    "professional_description": "Polished description",
    "affected": ["Component1", "Component2"],
    "affected_description": "human readable affected components",
    "confidence": 0.95,
    "code_samples": [
        {
            "file": "src/auth/controller.py",
            "start_line": 45,
            "end_line": 50,
            "code": "vulnerable code here",
            "language": "python",
            "explanation": "Why this code is relevant"
        }
    ]
}
```

## Testing

Run the unit tests:

```bash
pytest tests/test_github_pr_reporter.py -v
```

## Troubleshooting

### Error: "GitHub token not provided"

Set the `GITHUB_TOKEN` environment variable or pass the `token` parameter.

### Error: "Failed to access repository or PR"

Check that:
- The repository name is correct (format: "owner/repo")
- The PR number exists
- Your token has the required permissions

### Error: "API rate limit exceeded"

GitHub API has rate limits:
- Authenticated requests: 5,000 per hour
- Unauthenticated: 60 per hour

Wait for the limit to reset or use a different token.

### No line comments posted

Line comments require:
- Findings with `code_samples` containing `file` and `start_line`
- The file must be part of the PR diff
- The line number must be in the diff context

## License

This component is part of the Hound security analysis platform.
