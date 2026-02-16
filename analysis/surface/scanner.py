"""Core surface scanning engine."""

import csv
import json
import os
import re
import shutil
import tarfile
import tempfile
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import httpx
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn

from .models import BatchResult, Finding, QualityMetrics, ScanResult
from .patterns import PatternDetector, PatternMatch

console = Console()


class SurfaceScanner:
    """Lightweight security scanner for smart contract repositories."""

    def __init__(
        self,
        config: dict | None = None,
        llm_budget: int = 5,
        model: str | None = None,
        quiet: bool = False,
    ):
        """Initialize the surface scanner.

        Args:
            config: Configuration dictionary (optional)
            llm_budget: Maximum LLM calls per scan (default: 5)
            model: Override model for LLM calls
            quiet: Suppress progress output
        """
        self.config = config or {}
        self.llm_budget = llm_budget
        self.model = model or "gpt-4o-mini"
        self.quiet = quiet
        self.llm_calls_made = 0
        self.pattern_detector = PatternDetector()

        # GitHub API settings
        self.github_token = os.environ.get("GITHUB_TOKEN")

    def scan(self, target: str) -> ScanResult:
        """Scan a repository for vulnerabilities.

        Args:
            target: GitHub URL or local path

        Returns:
            ScanResult with findings and risk score
        """
        start_time = time.time()
        self.llm_calls_made = 0

        try:
            # Resolve target to local path
            repo_path, repo_url, cleanup_fn = self._resolve_target(target)

            if not self.quiet:
                console.print(f"[cyan]Scanning:[/cyan] {repo_path.name}")

            # Find smart contracts
            contracts = self._find_contracts(repo_path)
            if not contracts:
                return ScanResult(
                    repo_url=repo_url,
                    repo_path=str(repo_path),
                    repo_name=repo_path.name,
                    risk_score=0,
                    risk_level="low",
                    summary="No Solidity or Vyper contracts found in repository.",
                    error="No smart contracts found",
                )

            # Run static pattern detection
            all_matches: list[PatternMatch] = []
            quality_data: dict = {
                "has_events": False,
                "has_natspec": False,
                "has_access_control": False,
                "uses_safemath": False,
                "solidity_version": None,
                "vyper_version": None,
                "total_loc": 0,
            }

            for contract_path in contracts:
                content = contract_path.read_text(errors='ignore')
                quality_data["total_loc"] += content.count('\n')

                # Detect patterns
                matches = self.pattern_detector.detect(content, contract_path)
                all_matches.extend(matches)

                # Extract quality metrics
                file_metrics = self.pattern_detector.detect_quality_metrics(content, contract_path)
                quality_data["has_events"] = quality_data["has_events"] or file_metrics["has_events"]
                quality_data["has_natspec"] = quality_data["has_natspec"] or file_metrics["has_natspec"]
                quality_data["has_access_control"] = quality_data["has_access_control"] or file_metrics["has_access_control"]
                quality_data["uses_safemath"] = quality_data["uses_safemath"] or file_metrics["uses_safemath"]
                if file_metrics["solidity_version"]:
                    quality_data["solidity_version"] = file_metrics["solidity_version"]
                if file_metrics["vyper_version"]:
                    quality_data["vyper_version"] = file_metrics["vyper_version"]

            # Check for tests
            test_files = self._find_test_files(repo_path)

            # Build quality metrics
            quality_metrics = QualityMetrics(
                solidity_version=quality_data["solidity_version"],
                vyper_version=quality_data["vyper_version"],
                has_tests=len(test_files) > 0,
                test_count=len(test_files),
                has_natspec=quality_data["has_natspec"],
                contract_count=len(contracts),
                total_loc=quality_data["total_loc"],
                has_events=quality_data["has_events"],
                uses_safemath=quality_data["uses_safemath"],
                has_access_control=quality_data["has_access_control"],
            )

            # Convert matches to findings
            findings = self._matches_to_findings(all_matches, repo_path)

            # LLM verification (if budget allows)
            if self.llm_budget > 0 and findings:
                findings, summary = self._llm_verify(findings, contracts, quality_metrics, repo_path)
            else:
                summary = self._generate_basic_summary(findings, quality_metrics)

            # Calculate risk score
            risk_score = self._calculate_risk_score(findings, quality_metrics)
            risk_level = self._score_to_level(risk_score)

            # Cleanup temp directory if needed
            if cleanup_fn:
                cleanup_fn()

            duration = time.time() - start_time

            return ScanResult(
                repo_url=repo_url,
                repo_path=str(repo_path),
                repo_name=repo_path.name,
                risk_score=risk_score,
                risk_level=risk_level,
                findings=findings,
                quality_metrics=quality_metrics,
                contracts_scanned=len(contracts),
                contracts_total=len(contracts),
                llm_calls_used=self.llm_calls_made,
                scan_duration_seconds=duration,
                summary=summary,
            )

        except Exception as e:
            duration = time.time() - start_time
            return ScanResult(
                repo_url=target if target.startswith("http") else None,
                repo_path=target,
                repo_name=Path(target).name if not target.startswith("http") else target.split("/")[-1],
                risk_score=0,
                risk_level="low",
                scan_duration_seconds=duration,
                error=str(e),
            )

    def scan_batch(
        self,
        csv_path: Path,
        output_path: Path | None = None,
        max_concurrent: int = 10,
        checkpoint_interval: int = 50,
    ) -> BatchResult:
        """Scan multiple repositories from a CSV file.

        Args:
            csv_path: Path to CSV file with repo URLs
            output_path: Optional path for output CSV
            max_concurrent: Maximum concurrent scans
            checkpoint_interval: Save checkpoint every N repos

        Returns:
            BatchResult with all scan results
        """
        start_time = time.time()

        # Read CSV and extract repo URLs
        repos = self._parse_input_csv(csv_path)
        if not repos:
            console.print("[red]No valid repositories found in CSV[/red]")
            return BatchResult(total_repos=0)

        console.print(f"[cyan]Found {len(repos)} repositories to scan[/cyan]")

        # Check for existing checkpoint
        checkpoint_path = output_path.with_suffix('.checkpoint.json') if output_path else Path('scan_checkpoint.json')
        completed_urls = set()
        if checkpoint_path.exists():
            with open(checkpoint_path) as f:
                checkpoint_data = json.load(f)
                completed_urls = set(checkpoint_data.get('completed', []))
            console.print(f"[yellow]Resuming from checkpoint: {len(completed_urls)} already completed[/yellow]")

        # Filter out already completed
        pending_repos = [(url, name) for url, name in repos if url not in completed_urls]
        console.print(f"[cyan]{len(pending_repos)} repositories remaining[/cyan]")

        batch_result = BatchResult(
            total_repos=len(repos),
            checkpoint_path=str(checkpoint_path),
        )

        # Run scans with progress bar
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(f"Scanning {len(pending_repos)} repos...", total=len(pending_repos))

            for i, (repo_url, repo_name) in enumerate(pending_repos):
                try:
                    result = self.scan(repo_url)
                    batch_result.add_result(result)
                    completed_urls.add(repo_url)

                    # Update progress
                    status = "[green]✓[/green]" if not result.error else "[red]✗[/red]"
                    progress.update(task, advance=1, description=f"{status} {repo_name[:30]}")

                except Exception as e:
                    error_result = ScanResult(
                        repo_url=repo_url,
                        repo_path=repo_url,
                        repo_name=repo_name,
                        risk_score=0,
                        risk_level="low",
                        error=str(e),
                    )
                    batch_result.add_result(error_result)
                    completed_urls.add(repo_url)
                    progress.update(task, advance=1, description=f"[red]✗[/red] {repo_name[:30]}")

                # Checkpoint
                if (i + 1) % checkpoint_interval == 0:
                    self._save_checkpoint(checkpoint_path, list(completed_urls), batch_result)

        # Save final results
        batch_result.total_duration_seconds = time.time() - start_time
        self._save_checkpoint(checkpoint_path, list(completed_urls), batch_result)

        # Write output CSV if specified
        if output_path:
            self._write_batch_csv(batch_result, output_path)

        console.print("\n[green]Scan complete![/green]")
        console.print(f"  Successful: {batch_result.successful}")
        console.print(f"  Failed: {batch_result.failed}")
        console.print(f"  Duration: {batch_result.total_duration_seconds:.1f}s")

        return batch_result

    def _resolve_target(self, target: str) -> tuple[Path, str | None, callable | None]:
        """Resolve target to local path, downloading if needed.

        Returns:
            (local_path, original_url_or_none, cleanup_function_or_none)
        """
        # Check if it's a URL
        if target.startswith("http://") or target.startswith("https://"):
            # GitHub URL
            if "github.com" in target:
                return self._fetch_github_repo(target)
            else:
                raise ValueError(f"Unsupported URL: {target}")

        # Local path
        local_path = Path(target).resolve()
        if not local_path.exists():
            raise ValueError(f"Path does not exist: {target}")

        return local_path, None, None

    def _fetch_github_repo(self, url: str) -> tuple[Path, str, callable]:
        """Fetch a GitHub repository as a tarball.

        Returns:
            (temp_dir_path, original_url, cleanup_function)
        """
        # Parse URL to get owner/repo
        parsed = urlparse(url)
        parts = parsed.path.strip('/').split('/')
        if len(parts) < 2:
            raise ValueError(f"Invalid GitHub URL: {url}")

        owner, repo = parts[0], parts[1].replace('.git', '')
        api_url = f"https://api.github.com/repos/{owner}/{repo}/tarball"

        # Create temp directory
        temp_dir = tempfile.mkdtemp(prefix=f"hound_scan_{repo}_")

        def cleanup():
            shutil.rmtree(temp_dir, ignore_errors=True)

        try:
            # Download tarball
            headers = {}
            if self.github_token:
                headers["Authorization"] = f"token {self.github_token}"

            if not self.quiet:
                console.print(f"[dim]Downloading {owner}/{repo}...[/dim]")

            with httpx.Client(follow_redirects=True, timeout=60.0) as client:
                response = client.get(api_url, headers=headers)
                response.raise_for_status()

                # Save and extract tarball
                tarball_path = Path(temp_dir) / "repo.tar.gz"
                tarball_path.write_bytes(response.content)

                with tarfile.open(tarball_path, "r:gz") as tar:
                    tar.extractall(temp_dir)

                # Find extracted directory (GitHub adds a hash suffix)
                extracted_dirs = [d for d in Path(temp_dir).iterdir() if d.is_dir()]
                if not extracted_dirs:
                    raise ValueError("Failed to extract repository")

                return extracted_dirs[0], url, cleanup

        except Exception as e:
            cleanup()
            raise ValueError(f"Failed to fetch {url}: {e}")

    def _find_contracts(self, repo_path: Path) -> list[Path]:
        """Find all Solidity and Vyper contracts in repository."""
        contracts = []

        # First, try to find contracts in the root directory
        contracts.extend(repo_path.glob("*.sol"))
        contracts.extend(repo_path.glob("*.vy"))

        # Common contract directories
        search_dirs = [
            repo_path / "contracts",
            repo_path / "src",
            repo_path / "lib",
            repo_path,
        ]

        for search_dir in search_dirs:
            if search_dir.exists():
                contracts.extend(search_dir.rglob("*.sol"))
                contracts.extend(search_dir.rglob("*.vy"))

        # Deduplicate and filter out test/mock files
        seen = set()
        filtered = []
        for c in contracts:
            if c not in seen:
                seen.add(c)
                # Skip test and mock files based on filename only (not full path)
                filename = c.name.lower()
                parent_name = c.parent.name.lower()
                # Skip if the file or its immediate parent is clearly a test/mock
                skip_file = any(skip in filename for skip in ['.t.sol', 'test', 'mock', 'script'])
                skip_dir = parent_name in ['test', 'tests', 'mocks', 'scripts', 'forge-std', 'node_modules']
                if not skip_file and not skip_dir:
                    filtered.append(c)

        return filtered

    def _find_test_files(self, repo_path: Path) -> list[Path]:
        """Find test files in repository."""
        test_files = []

        # Look for test directories
        test_dirs = [
            repo_path / "test",
            repo_path / "tests",
            repo_path / "spec",
        ]

        for test_dir in test_dirs:
            if test_dir.exists():
                test_files.extend(test_dir.rglob("*.sol"))
                test_files.extend(test_dir.rglob("*.t.sol"))
                test_files.extend(test_dir.rglob("*.js"))
                test_files.extend(test_dir.rglob("*.ts"))
                test_files.extend(test_dir.rglob("*.py"))

        # Also check for foundry test files in src
        test_files.extend(repo_path.rglob("*.t.sol"))

        return list(set(test_files))

    def _matches_to_findings(self, matches: list[PatternMatch], repo_path: Path) -> list[Finding]:
        """Convert pattern matches to findings."""
        findings = []

        for match in matches:
            # Calculate relative path
            try:
                rel_path = Path(match.file_path).relative_to(repo_path)
            except ValueError:
                rel_path = Path(match.file_path)

            # Extract a cleaner code snippet (just the matched line + context)
            snippet_lines = match.code_context.split('\n')
            if len(snippet_lines) > 10:
                # Trim to 10 lines around the match
                snippet_lines = snippet_lines[:10]
            snippet = '\n'.join(snippet_lines)

            finding = Finding(
                pattern_id=match.pattern.id,
                title=match.pattern.name,
                severity=match.pattern.severity,
                category=match.pattern.category,
                confidence=0.7,  # Base confidence, LLM can adjust
                location=f"{rel_path}:{match.line_number}",
                code_snippet=snippet[:500],  # Limit snippet size
                description=match.pattern.description,
                llm_verified=False,
            )
            findings.append(finding)

        # Deduplicate findings (same pattern in same file)
        seen = set()
        unique_findings = []
        for f in findings:
            key = (f.pattern_id, f.location.split(':')[0])  # Same pattern, same file
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        return unique_findings

    def _llm_verify(
        self,
        findings: list[Finding],
        contracts: list[Path],
        quality: QualityMetrics,
        repo_path: Path,
    ) -> tuple[list[Finding], str]:
        """Use LLM to verify findings and generate summary.

        Returns:
            (verified_findings, summary)
        """
        try:
            from llm.unified_client import UnifiedLLMClient
        except ImportError:
            # Fallback if LLM not available
            return findings, self._generate_basic_summary(findings, quality)

        # Prepare config for LLM
        llm_config = self.config.copy() if self.config else {}
        if "models" not in llm_config:
            llm_config["models"] = {}

        # Determine provider based on available API keys
        if os.environ.get("OPENAI_API_KEY"):
            provider = "openai"
            model = self.model or "gpt-4o-mini"
        elif os.environ.get("DEEPSEEK_API_KEY"):
            provider = "deepseek"
            model = "deepseek-chat"
        elif os.environ.get("ANTHROPIC_API_KEY"):
            provider = "anthropic"
            model = "claude-3-haiku-20240307"
        else:
            # No API key available, skip LLM
            return findings, self._generate_basic_summary(findings, quality)

        llm_config["models"]["scan"] = {
            "provider": provider,
            "model": model,
        }

        # Also set deepseek config if needed
        if provider == "deepseek" and "deepseek" not in llm_config:
            llm_config["deepseek"] = {
                "api_key_env": "DEEPSEEK_API_KEY",
                "base_url": "https://api.deepseek.com",
            }

        try:
            client = UnifiedLLMClient(llm_config, profile="scan")
        except Exception:
            return findings, self._generate_basic_summary(findings, quality)

        # Call 1: Verify critical/high findings
        critical_high = [f for f in findings if f.severity in ("critical", "high")]
        if critical_high and self.llm_calls_made < self.llm_budget:
            findings = self._verify_findings_batch(client, critical_high, findings)
            self.llm_calls_made += 1

        # Call 2: Verify medium findings
        medium = [f for f in findings if f.severity == "medium" and not f.llm_verified]
        if medium and self.llm_calls_made < self.llm_budget:
            findings = self._verify_findings_batch(client, medium, findings)
            self.llm_calls_made += 1

        # Call 3: Generate summary
        summary = self._generate_basic_summary(findings, quality)
        if self.llm_calls_made < self.llm_budget:
            summary = self._generate_llm_summary(client, findings, quality, repo_path)
            self.llm_calls_made += 1

        return findings, summary

    def _verify_findings_batch(
        self,
        client,
        to_verify: list[Finding],
        all_findings: list[Finding],
    ) -> list[Finding]:
        """Verify a batch of findings with LLM."""
        if not to_verify:
            return all_findings

        # Build prompt
        findings_text = "\n\n".join([
            f"### {f.pattern_id}: {f.title}\n"
            f"Location: {f.location}\n"
            f"Severity: {f.severity}\n"
            f"Description: {f.description}\n"
            f"Code:\n```\n{f.code_snippet}\n```"
            for f in to_verify[:5]  # Limit to 5 per call
        ])

        prompt = f"""Analyze these potential smart contract vulnerabilities.
For each finding, determine if it's a TRUE positive or FALSE positive.
Consider common patterns that would mitigate the issue (like ReentrancyGuard, access control modifiers).

Findings to verify:
{findings_text}

Respond in JSON format:
{{
  "findings": [
    {{
      "pattern_id": "...",
      "is_valid": true/false,
      "confidence": 0.0-1.0,
      "notes": "brief explanation"
    }}
  ]
}}"""

        try:
            response = client.generate(prompt, max_tokens=1000)
            # Parse response and update findings
            # This is simplified - in production, use proper JSON parsing
            result_text = response if isinstance(response, str) else str(response)
            if '"findings"' in result_text:
                # Extract JSON from response
                json_match = re.search(r'\{[\s\S]*"findings"[\s\S]*\}', result_text)
                if json_match:
                    result = json.loads(json_match.group())
                    for item in result.get("findings", []):
                        pattern_id = item.get("pattern_id")
                        for f in all_findings:
                            if f.pattern_id == pattern_id:
                                f.llm_verified = True
                                f.confidence = item.get("confidence", f.confidence)
                                f.llm_notes = item.get("notes")
                                if not item.get("is_valid", True):
                                    f.confidence = 0.1  # Mark as likely false positive
        except Exception:
            pass  # Continue without LLM verification

        return all_findings

    def _generate_llm_summary(
        self,
        client,
        findings: list[Finding],
        quality: QualityMetrics,
        repo_path: Path,
    ) -> str:
        """Generate LLM summary of scan results."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            counts[f.severity] += 1

        prompt = f"""Generate a brief (2-3 sentence) security summary for this smart contract repository:

Repository: {repo_path.name}
Contracts: {quality.contract_count}
Lines of Code: {quality.total_loc}

Findings:
- Critical: {counts['critical']}
- High: {counts['high']}
- Medium: {counts['medium']}
- Low: {counts['low']}

Code Quality:
- Has Tests: {quality.has_tests}
- Solidity Version: {quality.solidity_version or 'Unknown'}
- Has Access Control: {quality.has_access_control}
- Has Events: {quality.has_events}

Write a professional, concise summary suitable for a security report. Focus on the key risks."""

        try:
            response = client.generate(prompt, max_tokens=200)
            return response if isinstance(response, str) else str(response)
        except Exception:
            return self._generate_basic_summary(findings, quality)

    def _generate_basic_summary(self, findings: list[Finding], quality: QualityMetrics) -> str:
        """Generate a basic summary without LLM."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            counts[f.severity] += 1

        if counts["critical"] > 0:
            return f"Critical security issues detected. Found {counts['critical']} critical and {counts['high']} high severity issues requiring immediate attention."
        elif counts["high"] > 0:
            return f"Significant security concerns identified. Found {counts['high']} high and {counts['medium']} medium severity issues that should be addressed."
        elif counts["medium"] > 0:
            return f"Moderate security issues found. {counts['medium']} medium severity findings warrant review."
        elif counts["low"] > 0:
            return f"Minor issues detected. {counts['low']} low severity findings related to code quality."
        else:
            return "No significant security issues detected in static analysis. A deeper audit is recommended for production contracts."

    def _calculate_risk_score(self, findings: list[Finding], quality: QualityMetrics) -> int:
        """Calculate composite risk score 0-100."""
        # Vulnerability points (capped at 70)
        severity_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3}
        vuln_score = sum(
            severity_weights.get(f.severity, 0) * f.confidence
            for f in findings
        )
        vuln_score = min(70, vuln_score)

        # Quality deductions (up to 30 points)
        quality_score = 0
        if not quality.has_tests:
            quality_score += 10
        if quality.solidity_version:
            try:
                major, minor = quality.solidity_version.split('.')[:2]
                if int(major) == 0 and int(minor) < 8:
                    quality_score += 10  # Pre-0.8.0
            except ValueError:
                pass
        if not quality.has_natspec:
            quality_score += 3
        if not quality.has_access_control:
            quality_score += 5
        if not quality.has_events:
            quality_score += 2

        return min(100, int(vuln_score + quality_score))

    def _score_to_level(self, score: int) -> str:
        """Convert risk score to level."""
        if score >= 70:
            return "critical"
        elif score >= 50:
            return "high"
        elif score >= 25:
            return "medium"
        else:
            return "low"

    def _parse_input_csv(self, csv_path: Path) -> list[tuple[str, str]]:
        """Parse input CSV to extract repo URLs and names."""
        repos = []

        with open(csv_path, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Try common column names for GitHub URL
                url = (
                    row.get('GitHub URL') or
                    row.get('github_url') or
                    row.get('url') or
                    row.get('repo_url') or
                    row.get('URL') or
                    ""
                )
                # Try common column names for name
                name = (
                    row.get('Name') or
                    row.get('name') or
                    row.get('Login') or
                    row.get('login') or
                    row.get('repo') or
                    ""
                )

                if url and url.startswith("http"):
                    repos.append((url, name or url.split('/')[-1]))

        return repos

    def _save_checkpoint(self, path: Path, completed: list[str], batch_result: BatchResult) -> None:
        """Save checkpoint to disk."""
        checkpoint_data = {
            "completed": completed,
            "successful": batch_result.successful,
            "failed": batch_result.failed,
            "timestamp": datetime.now().isoformat(),
        }
        with open(path, 'w') as f:
            json.dump(checkpoint_data, f, indent=2)

    def _write_batch_csv(self, batch_result: BatchResult, output_path: Path) -> None:
        """Write batch results to CSV."""
        if not batch_result.results:
            return

        fieldnames = list(batch_result.results[0].to_csv_row().keys())

        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for result in batch_result.results:
                writer.writerow(result.to_csv_row())

        console.print(f"[green]Results written to {output_path}[/green]")
