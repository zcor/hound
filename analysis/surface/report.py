"""Report generation for surface scan results."""

import csv
from io import StringIO
from typing import Literal

from .models import BatchResult, ScanResult


class ScanReportGenerator:
    """Generate professional reports from scan results."""

    def generate(
        self,
        result: ScanResult,
        format: Literal["html", "md", "json", "csv"] = "json",
    ) -> str:
        """Generate report in specified format."""
        if format == "html":
            return self.generate_html(result)
        elif format == "md":
            return self.generate_markdown(result)
        elif format == "csv":
            return self.generate_csv(result)
        else:
            return self.generate_json(result)

    def generate_html(self, result: ScanResult) -> str:
        """Generate a professional HTML report for sales outreach."""
        counts = result.finding_counts

        # Risk level styling
        risk_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#28a745",
        }
        risk_color = risk_colors.get(result.risk_level, "#6c757d")

        # Risk bar width
        bar_width = min(100, result.risk_score)

        # Generate findings HTML
        findings_html = ""
        for f in sorted(result.findings, key=lambda x: ["critical", "high", "medium", "low"].index(x.severity)):
            severity_color = risk_colors.get(f.severity, "#6c757d")
            findings_html += f"""
            <div class="finding-card" style="border-left-color: {severity_color};">
                <div class="finding-header">
                    <span class="severity-badge" style="background: {severity_color};">{f.severity.upper()}</span>
                    <span class="finding-title">{f.title}</span>
                </div>
                <div class="finding-location">{f.location}</div>
                <p class="finding-description">{f.description}</p>
                <pre class="code-snippet"><code>{self._escape_html(f.code_snippet[:300])}</code></pre>
                {f'<div class="llm-notes">LLM Analysis: {f.llm_notes}</div>' if f.llm_notes else ''}
            </div>
            """

        # Quality metrics HTML
        quality = result.quality_metrics
        quality_items = [
            ("Tests", "present" if quality.has_tests else "not found", quality.has_tests),
            ("Solidity Version", quality.solidity_version or "Unknown",
             quality.solidity_version and quality.solidity_version >= "0.8" if quality.solidity_version else False),
            ("Access Control", "detected" if quality.has_access_control else "not detected", quality.has_access_control),
            ("Events", "present" if quality.has_events else "missing", quality.has_events),
            ("Documentation", "present" if quality.has_natspec else "missing", quality.has_natspec),
        ]

        quality_html = ""
        for label, value, is_good in quality_items:
            color = "#28a745" if is_good else "#dc3545"
            quality_html += f"""
            <div class="quality-item">
                <span class="quality-icon" style="color: {color};">{'✓' if is_good else '✗'}</span>
                <span class="quality-label">{label}:</span>
                <span class="quality-value">{value}</span>
            </div>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Surface Scan: {result.repo_name}</title>
    <style>
        :root {{
            --primary: #1a1a2e;
            --secondary: #16213e;
            --accent: #0f3460;
            --text: #eaeaea;
            --text-dim: #888;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            color: var(--text);
            min-height: 100vh;
            padding: 2rem;
        }}

        .container {{
            max-width: 900px;
            margin: 0 auto;
        }}

        header {{
            text-align: center;
            margin-bottom: 2rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--accent);
        }}

        .logo {{
            font-size: 2rem;
            font-weight: bold;
            color: #fff;
            margin-bottom: 0.5rem;
        }}

        .subtitle {{
            color: var(--text-dim);
            font-size: 1rem;
        }}

        .repo-name {{
            font-size: 1.5rem;
            margin-top: 1rem;
            color: #4dabf7;
        }}

        .risk-dashboard {{
            background: var(--secondary);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            text-align: center;
        }}

        .risk-score {{
            font-size: 4rem;
            font-weight: bold;
            color: {risk_color};
            margin-bottom: 0.5rem;
        }}

        .risk-bar {{
            height: 12px;
            background: #333;
            border-radius: 6px;
            overflow: hidden;
            margin: 1rem auto;
            max-width: 400px;
        }}

        .risk-bar-fill {{
            height: 100%;
            width: {bar_width}%;
            background: {risk_color};
            border-radius: 6px;
            transition: width 0.5s ease;
        }}

        .risk-level {{
            font-size: 1.2rem;
            color: {risk_color};
            text-transform: uppercase;
            font-weight: bold;
            margin-bottom: 1rem;
        }}

        .summary {{
            color: var(--text-dim);
            font-size: 1rem;
            line-height: 1.5;
            max-width: 600px;
            margin: 0 auto;
        }}

        .section {{
            background: var(--secondary);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }}

        .section-title {{
            font-size: 1.3rem;
            margin-bottom: 1rem;
            color: #fff;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}

        .finding-card {{
            background: rgba(255,255,255,0.05);
            border-left: 4px solid;
            border-radius: 0 8px 8px 0;
            padding: 1rem;
            margin-bottom: 1rem;
        }}

        .finding-header {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 0.5rem;
        }}

        .severity-badge {{
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: bold;
            color: #fff;
        }}

        .finding-title {{
            font-weight: bold;
            color: #fff;
        }}

        .finding-location {{
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.85rem;
            color: #4dabf7;
            margin-bottom: 0.5rem;
        }}

        .finding-description {{
            color: var(--text-dim);
            font-size: 0.9rem;
            margin-bottom: 0.75rem;
        }}

        .code-snippet {{
            background: #0d1117;
            border-radius: 6px;
            padding: 0.75rem;
            overflow-x: auto;
            font-size: 0.8rem;
        }}

        .code-snippet code {{
            font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
            color: #c9d1d9;
        }}

        .llm-notes {{
            margin-top: 0.5rem;
            padding: 0.5rem;
            background: rgba(77, 171, 247, 0.1);
            border-radius: 4px;
            font-size: 0.85rem;
            color: #4dabf7;
        }}

        .quality-item {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 0;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }}

        .quality-item:last-child {{
            border-bottom: none;
        }}

        .quality-icon {{
            font-size: 1.2rem;
            width: 24px;
        }}

        .quality-label {{
            color: var(--text-dim);
            min-width: 120px;
        }}

        .quality-value {{
            color: var(--text);
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1rem;
            margin-top: 1rem;
        }}

        .stat-card {{
            background: rgba(255,255,255,0.05);
            border-radius: 8px;
            padding: 1rem;
            text-align: center;
        }}

        .stat-value {{
            font-size: 1.5rem;
            font-weight: bold;
            color: #fff;
        }}

        .stat-label {{
            font-size: 0.8rem;
            color: var(--text-dim);
            margin-top: 0.25rem;
        }}

        .cta {{
            background: linear-gradient(135deg, #0f3460 0%, #1a1a2e 100%);
            border: 1px solid #4dabf7;
            border-radius: 12px;
            padding: 2rem;
            text-align: center;
            margin-top: 2rem;
        }}

        .cta h2 {{
            color: #4dabf7;
            margin-bottom: 1rem;
        }}

        .cta p {{
            color: var(--text-dim);
            margin-bottom: 1.5rem;
            max-width: 500px;
            margin-left: auto;
            margin-right: auto;
        }}

        .cta-button {{
            display: inline-block;
            background: #4dabf7;
            color: #000;
            padding: 0.75rem 2rem;
            border-radius: 6px;
            text-decoration: none;
            font-weight: bold;
            margin: 0 0.5rem;
        }}

        .cta-button:hover {{
            background: #74c0fc;
        }}

        .cta-button.secondary {{
            background: transparent;
            border: 1px solid #4dabf7;
            color: #4dabf7;
        }}

        footer {{
            text-align: center;
            margin-top: 2rem;
            padding-top: 1rem;
            border-top: 1px solid var(--accent);
            color: var(--text-dim);
            font-size: 0.85rem;
        }}

        @media (max-width: 600px) {{
            .stats-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">HOUND</div>
            <div class="subtitle">Security Surface Scan Report</div>
            <div class="repo-name">{result.repo_name}</div>
        </header>

        <section class="risk-dashboard">
            <div class="risk-score">{result.risk_score}</div>
            <div class="risk-bar"><div class="risk-bar-fill"></div></div>
            <div class="risk-level">{result.risk_level.upper()} RISK</div>
            <p class="summary">{result.summary}</p>

            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value" style="color: #dc3545;">{counts['critical']}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #fd7e14;">{counts['high']}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #ffc107;">{counts['medium']}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #28a745;">{counts['low']}</div>
                    <div class="stat-label">Low</div>
                </div>
            </div>
        </section>

        <section class="section">
            <h2 class="section-title">Potential Issues ({len(result.findings)})</h2>
            {findings_html if findings_html else '<p style="color: var(--text-dim);">No issues detected in static analysis.</p>'}
        </section>

        <section class="section">
            <h2 class="section-title">Code Quality Indicators</h2>
            {quality_html}
        </section>

        <section class="section">
            <h2 class="section-title">Scan Details</h2>
            <div class="quality-item">
                <span class="quality-label">Contracts Scanned:</span>
                <span class="quality-value">{result.contracts_scanned}</span>
            </div>
            <div class="quality-item">
                <span class="quality-label">Lines of Code:</span>
                <span class="quality-value">{result.quality_metrics.total_loc:,}</span>
            </div>
            <div class="quality-item">
                <span class="quality-label">Scan Duration:</span>
                <span class="quality-value">{result.scan_duration_seconds:.1f}s</span>
            </div>
            <div class="quality-item">
                <span class="quality-label">LLM Calls Used:</span>
                <span class="quality-value">{result.llm_calls_used}</span>
            </div>
        </section>

        <section class="cta">
            <h2>Next Steps</h2>
            <p>This automated surface scan identified areas that may warrant deeper investigation.
            A comprehensive security audit can uncover complex vulnerabilities that automated tools may miss.</p>
            <a href="mailto:security@yourcompany.com?subject=Audit Request: {result.repo_name}" class="cta-button">Request Full Audit</a>
            <a href="#" class="cta-button secondary">Learn More</a>
        </section>

        <footer>
            <p>Generated by Hound Security Scanner</p>
            <p>{result.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </footer>
    </div>
</body>
</html>"""

        return html

    def generate_markdown(self, result: ScanResult) -> str:
        """Generate Markdown report."""
        counts = result.finding_counts

        md = f"""# Security Surface Scan: {result.repo_name}

## Risk Assessment

| Metric | Value |
|--------|-------|
| **Risk Score** | {result.risk_score}/100 |
| **Risk Level** | {result.risk_level.upper()} |
| **Critical Issues** | {counts['critical']} |
| **High Issues** | {counts['high']} |
| **Medium Issues** | {counts['medium']} |
| **Low Issues** | {counts['low']} |

### Summary

{result.summary}

---

## Findings

"""

        for f in sorted(result.findings, key=lambda x: ["critical", "high", "medium", "low"].index(x.severity)):
            md += f"""### [{f.severity.upper()}] {f.title}

**Location:** `{f.location}`

{f.description}

```solidity
{f.code_snippet[:300]}
```

"""
            if f.llm_notes:
                md += f"> **LLM Analysis:** {f.llm_notes}\n\n"

        md += """---

## Code Quality

"""
        quality = result.quality_metrics
        md += f"""| Indicator | Status |
|-----------|--------|
| Tests | {'Present' if quality.has_tests else 'Not Found'} |
| Solidity Version | {quality.solidity_version or 'Unknown'} |
| Access Control | {'Detected' if quality.has_access_control else 'Not Detected'} |
| Events | {'Present' if quality.has_events else 'Missing'} |
| Documentation | {'Present' if quality.has_natspec else 'Missing'} |

---

## Scan Details

- **Contracts Scanned:** {result.contracts_scanned}
- **Lines of Code:** {result.quality_metrics.total_loc:,}
- **Scan Duration:** {result.scan_duration_seconds:.1f}s
- **LLM Calls:** {result.llm_calls_used}
- **Timestamp:** {result.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}

---

*Generated by Hound Security Scanner*
"""

        return md

    def generate_json(self, result: ScanResult) -> str:
        """Generate JSON output."""
        return result.model_dump_json(indent=2)

    def generate_csv(self, result: ScanResult) -> str:
        """Generate CSV output for single result."""
        output = StringIO()
        row = result.to_csv_row()
        writer = csv.DictWriter(output, fieldnames=row.keys())
        writer.writeheader()
        writer.writerow(row)
        return output.getvalue()

    def generate_batch_csv(self, batch_result: BatchResult) -> str:
        """Generate CSV output for batch results."""
        if not batch_result.results:
            return ""

        output = StringIO()
        fieldnames = list(batch_result.results[0].to_csv_row().keys())
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for result in batch_result.results:
            writer.writerow(result.to_csv_row())

        return output.getvalue()

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        return (
            text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )
