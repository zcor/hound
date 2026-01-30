# Firepan Surface Scan

A lightweight, cost-effective security scanner for preliminary assessment of Solidity/Vyper smart contract repositories.

## Overview

Surface Scan is designed for **lead generation** - quickly scanning hundreds of repos to identify potential prospects who might benefit from a full Firepan audit. It's NOT a replacement for deep auditing.

**Key Characteristics:**
- Fast: ~2 seconds per repo (static analysis only)
- Cheap: ~$0.05 per repo with LLM verification (5 calls)
- Scalable: Batch processing with checkpointing for 1000+ repos

## Usage

### Basic Commands

```bash
# Scan a GitHub repository
hound scan https://github.com/uniswap/v4-core

# Scan a local directory
hound scan /path/to/contracts

# Generate HTML report (sales-ready)
hound scan https://github.com/org/repo --format html --output report.html

# Batch scan from CSV
hound scan --batch repos.csv --output results.csv

# Quick scan without LLM (faster, more false positives)
hound scan /path/to/contracts --no-llm
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--format` | Output format: json, html, md, csv | json |
| `--output` | Output file path | stdout |
| `--budget` | Max LLM calls per repo | 5 |
| `--model` | Override LLM model | gpt-4o-mini |
| `--no-llm` | Skip LLM verification | false |
| `--quiet` | Suppress progress output | false |
| `--batch` | CSV file for batch scanning | - |
| `--max-concurrent` | Concurrent scans (batch mode) | 10 |

### Environment Variables

The scanner auto-detects available LLM providers:

```bash
# Preferred (cheapest)
export DEEPSEEK_API_KEY=sk-xxx

# Alternatives
export OPENAI_API_KEY=sk-xxx
export ANTHROPIC_API_KEY=sk-xxx
```

## Output Formats

### JSON (default)
```json
{
  "repo_name": "example",
  "risk_score": 74,
  "risk_level": "critical",
  "findings": [...],
  "quality_metrics": {...},
  "summary": "Critical security issues detected..."
}
```

### HTML
Professional report suitable for sales outreach with:
- Visual risk score dashboard
- Color-coded findings by severity
- Code snippets with line numbers
- Quality indicators
- Call-to-action section

### CSV (batch mode)
```csv
repo_url,repo_name,risk_score,risk_level,critical_count,high_count,...
https://github.com/org/repo,repo-name,74,critical,1,3,...
```

## Vulnerability Patterns Detected

### Critical Severity
| Pattern ID | Name | Description |
|------------|------|-------------|
| SELFDESTRUCT-001 | Unprotected selfdestruct | selfdestruct without access control |
| DELEGATECALL-001 | Unprotected delegatecall | delegatecall to untrusted targets |

### High Severity
| Pattern ID | Name | Description |
|------------|------|-------------|
| REENTRANCY-001 | Potential Reentrancy | External call before state update |
| TXORIGIN-001 | tx.origin auth | Using tx.origin for authorization |
| UNCHECKED-CALL-001 | Unchecked low-level call | .call() without return check |
| OVERFLOW-001 | Integer Overflow | Solidity < 0.8.0 without SafeMath |

### Medium Severity
| Pattern ID | Name | Description |
|------------|------|-------------|
| ACCESS-001 | Missing access control | Public state-changing functions |
| FRONTRUN-001 | Frontrunning risk | Approval patterns |
| ORACLE-001 | Price oracle dependency | External price feeds |
| FLASHLOAN-001 | Flash loan callback | Flash loan patterns |

### Low Severity
| Pattern ID | Name | Description |
|------------|------|-------------|
| DEPRECATED-001 | Deprecated patterns | throw, sha3, suicide, etc. |
| VISIBILITY-001 | Default visibility | Missing explicit visibility |

## Risk Score Calculation

The risk score (0-100) combines:

**Vulnerability Score (0-70 points)**
- Critical findings: 25 points × confidence
- High findings: 15 points × confidence
- Medium findings: 8 points × confidence
- Low findings: 3 points × confidence

**Quality Deductions (0-30 points)**
- No tests: +10 points
- Solidity < 0.8.0: +10 points
- No NatSpec: +3 points
- No access control patterns: +5 points
- No events: +2 points

**Risk Levels**
- 70-100: Critical
- 50-69: High
- 25-49: Medium
- 0-24: Low

## Known Limitations & False Positives

### High False Positive Rate Without LLM

Static regex patterns are intentionally sensitive. Without LLM verification, expect:

1. **approve() flagged as frontrunning** - Standard ERC20 pattern, not a vulnerability
2. **Access control false positives** - Functions may have modifiers the regex doesn't see
3. **Reentrancy in safe contexts** - CEI pattern may be followed but not detected

**Recommendation:** Always use LLM verification (`--budget 5`) for any results you plan to share externally.

### Battle-Tested Repos Show Vulnerabilities

Running against OpenZeppelin, Uniswap, etc. will produce findings. These are almost always:
- Design patterns that look like vulnerabilities but aren't
- Intentional trade-offs in well-audited code
- False positives from regex limitations

**Do NOT send surface scan reports to major DeFi protocols without manual review.**

### What Surface Scan is Good For

1. **Identifying unaudited repos** - New projects with real issues
2. **Lead qualification** - Finding repos that might need help
3. **Initial triage** - Prioritizing which repos to look at first
4. **Code quality signals** - No tests, old Solidity, missing events

### What Surface Scan is NOT Good For

1. **Replacing deep audits** - It's a 2-second scan, not a week-long audit
2. **Auditing production code** - False positives will embarrass you
3. **Finding complex vulnerabilities** - Logic bugs, economic attacks, etc.

## Architecture

```
hound scan <target>
       │
       ▼
┌─────────────────┐
│ SurfaceScanner  │
└────────┬────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌────────┐ ┌──────────────┐
│ GitHub │ │ Local Path   │
│ Tarball│ │              │
└────┬───┘ └──────┬───────┘
     │            │
     └─────┬──────┘
           ▼
┌─────────────────────┐
│ Pattern Detection   │  ← Regex-based, 0 LLM calls
│ (15+ patterns)      │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ LLM Verification    │  ← Up to 5 calls, filters FPs
│ (DeepSeek/OpenAI)   │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ Risk Calculation    │
│ + Report Generation │
└─────────────────────┘
```

## Files

| File | Purpose |
|------|---------|
| `analysis/surface/__init__.py` | Module exports |
| `analysis/surface/models.py` | Pydantic data models |
| `analysis/surface/patterns.py` | Vulnerability regex patterns |
| `analysis/surface/scanner.py` | Core scanning engine |
| `analysis/surface/report.py` | HTML/MD/CSV generation |
| `commands/scan.py` | CLI command |

## Batch Processing

### Input CSV Format

The scanner looks for these columns (case-insensitive):
- `GitHub URL`, `github_url`, `url`, `repo_url`, `URL`
- `Name`, `name`, `Login`, `login`, `repo`

Example:
```csv
Name,GitHub URL
Uniswap,https://github.com/Uniswap/v4-core
Aave,https://github.com/aave/aave-v3-core
```

### Checkpointing

For large batches, the scanner:
1. Saves progress every 50 repos
2. Creates `{output}.checkpoint.json`
3. Resumes from checkpoint on restart

### Example Batch Run

```bash
# Scan 1000 repos with checkpointing
hound scan --batch all_repos.csv --output results.csv --no-llm

# Resume after interruption (automatic)
hound scan --batch all_repos.csv --output results.csv --no-llm
```

## Sample Results

Scanning 5 major DeFi protocols (no LLM):

| Repo | Risk Score | Critical | High | Medium | Time |
|------|------------|----------|------|--------|------|
| Uniswap v4 | 50 | 0 | 0 | 9 | 2.2s |
| OpenZeppelin | 70 | 0 | 51 | 46 | 2.8s |
| Aave v3 | 80 | 5 | 0 | 74 | 2.0s |
| Compound | 70 | 3 | 3 | 58 | 1.7s |
| Curve | 73 | 0 | 34 | 0 | 1.4s |

**Note:** These scores reflect false positives from static analysis. Battle-tested protocols don't actually have these vulnerabilities.

## Future Improvements

1. **Tighter patterns** - Reduce false positives in standard patterns
2. **Confidence thresholds** - Filter low-confidence findings
3. **Strict mode** - Only show high-confidence findings
4. **Org scanning** - Auto-discover repos in GitHub organizations
5. **Slither integration** - Use Slither for more accurate detection
6. **Gas analysis** - Flag expensive patterns
