"""Core surface scanning engine."""

import csv
import json
import os
import re
import shutil
import tarfile
import tempfile
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import httpx
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn

from .models import BatchResult, Finding, QualityMetrics, ScanResult
from .patterns import PatternDetector, PatternMatch

console = Console()

# Max scan log size in bytes (64KB)
_MAX_LOG_BYTES = 65536

# Patterns for secret redaction
_SECRET_PATTERNS = [
    # Stripe keys
    re.compile(r'sk_live_[A-Za-z0-9]+'),
    re.compile(r'sk_test_[A-Za-z0-9]+'),
    # GitHub tokens
    re.compile(r'ghp_[A-Za-z0-9]+'),
    re.compile(r'ghu_[A-Za-z0-9]+'),
    re.compile(r'ghs_[A-Za-z0-9]+'),
    # PEM blocks
    re.compile(r'-----BEGIN[A-Z ]*KEY-----[\s\S]*?-----END[A-Z ]*KEY-----'),
    # High-entropy token-like strings (>40 chars)
    re.compile(r'[A-Za-z0-9+/=_-]{40,}'),
    # URL query param secrets
    re.compile(r'([?&](?:token|key|secret|password|api_key|apikey)=)[^\s&]+', re.IGNORECASE),
]

# The URL param pattern replaces only the value portion
_URL_SECRET_PATTERN = re.compile(r'([?&](?:token|key|secret|password|api_key|apikey)=)[^\s&]+', re.IGNORECASE)


def _redact_log(text: str) -> str:
    """Redact secrets from log text before storage."""
    if not text:
        return text
    # URL params: keep the param name, redact the value
    text = _URL_SECRET_PATTERN.sub(r'\1[REDACTED]', text)
    # PEM blocks
    text = re.sub(r'-----BEGIN[A-Z ]*KEY-----[\s\S]*?-----END[A-Z ]*KEY-----', '[REDACTED]', text)
    # Token patterns
    for pattern in _SECRET_PATTERNS:
        if pattern is _URL_SECRET_PATTERN:
            continue
        if pattern.pattern.startswith('-----BEGIN'):
            continue
        text = pattern.sub('[REDACTED]', text)
    return text


def _truncate_log(text: str, max_bytes: int = _MAX_LOG_BYTES) -> str:
    """Truncate log to max_bytes, appending a truncation notice."""
    if not text or len(text.encode('utf-8')) <= max_bytes:
        return text
    # Truncate by bytes, find last newline to avoid splitting a line
    truncated = text.encode('utf-8')[:max_bytes].decode('utf-8', errors='ignore')
    last_nl = truncated.rfind('\n')
    if last_nl > 0:
        truncated = truncated[:last_nl]
    return truncated + '\n[log truncated at 64KB]'


class SurfaceScanner:
    """Lightweight security scanner for smart contract repositories."""

    def __init__(
        self,
        config: dict | None = None,
        llm_budget: int = 5,
        model: str | None = None,
        quiet: bool = False,
        github_token: str | None = None,
    ):
        """Initialize the surface scanner.

        Args:
            config: Configuration dictionary (optional)
            llm_budget: Maximum LLM calls per scan (default: 5)
            model: Override model for LLM calls
            quiet: Suppress progress output
            github_token: Optional GitHub token for tarball downloads
        """
        self.config = config or {}
        self.llm_budget = llm_budget
        self.model = model or "gpt-4o-mini"
        self.quiet = quiet
        self.llm_calls_made = 0
        self.pattern_detector = PatternDetector()
        self._log_lines: list[str] = []
        self._start_time: float = 0.0

        # Prefer an explicit installation token, otherwise fall back to env.
        self.github_token = github_token or os.environ.get("GITHUB_TOKEN")

    def _log(self, msg: str) -> None:
        """Append a timestamped log line."""
        elapsed = time.time() - self._start_time if self._start_time else 0.0
        self._log_lines.append(f"[{elapsed:.1f}s] {msg}")

    def scan(self, target: str) -> ScanResult:
        """Scan a repository for vulnerabilities.

        Args:
            target: GitHub URL or local path

        Returns:
            ScanResult with findings and risk score
        """
        start_time = time.time()
        self._start_time = start_time
        self._log_lines = []
        self.llm_calls_made = 0

        try:
            # Resolve target to local path
            self._log(f"Resolving target: {target}")
            repo_path, repo_url, cleanup_fn = self._resolve_target(target)
            self._log(f"Cloned/resolved to: {repo_path.name}")

            if not self.quiet:
                console.print(f"[cyan]Scanning:[/cyan] {repo_path.name}")

            # Find smart contracts
            contracts = self._find_contracts(repo_path)
            if not contracts:
                self._log("No Solidity or Vyper contracts found")
                return ScanResult(
                    repo_url=repo_url,
                    repo_path=str(repo_path),
                    repo_name=repo_path.name,
                    risk_score=0,
                    risk_level="low",
                    summary="No Solidity or Vyper contracts found in repository.",
                    error="No smart contracts found",
                    scan_log="\n".join(self._log_lines),
                )

            total_loc = sum(c.read_text(errors='ignore').count('\n') for c in contracts)
            self._log(f"Found {len(contracts)} contract(s), {total_loc} LOC")

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
            self._log(f"Pattern detection: {len(all_matches)} raw matches, {len(findings)} unique findings")

            # Extract traits for summary (always, even without LLM)
            traits = self._extract_repo_traits(contracts, quality_metrics)

            # LLM verification (if budget allows)
            if self.llm_budget > 0 and findings:
                self._log(f"Starting LLM verification (budget: {self.llm_budget})")
                findings, summary = self._llm_verify(findings, contracts, quality_metrics, repo_path)
                self._log(f"LLM verification complete: {self.llm_calls_made} call(s) used")
            else:
                summary = self._generate_traits_summary(traits, findings, quality_metrics)

            # Calculate risk score
            risk_score = self._calculate_risk_score(findings, quality_metrics)
            risk_level = self._score_to_level(risk_score)

            # Cleanup temp directory if needed
            if cleanup_fn:
                cleanup_fn()

            duration = time.time() - start_time
            self._log(f"Scan complete: risk_score={risk_score} ({risk_level}), {len(findings)} finding(s), {duration:.1f}s")

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
                scan_log="\n".join(self._log_lines),
            )

        except Exception as e:
            duration = time.time() - start_time
            self._log(f"Scan failed: {e}")
            return ScanResult(
                repo_url=target if target.startswith("http") else None,
                repo_path=target,
                repo_name=Path(target).name if not target.startswith("http") else target.split("/")[-1],
                risk_score=0,
                risk_level="low",
                scan_duration_seconds=duration,
                error=str(e),
                scan_log="\n".join(self._log_lines),
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

    def _resolve_target(self, target: str) -> tuple[Path, str | None, Callable[[], None] | None]:
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

    def _fetch_github_repo(self, url: str) -> tuple[Path, str, Callable[[], None]]:
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
                try:
                    response.raise_for_status()
                except httpx.HTTPStatusError as e:
                    status = e.response.status_code
                    if status == 404 and not self.github_token:
                        raise ValueError("REPO_AUTH_REQUIRED: Repository not accessible — may be private or require authentication") from e
                    elif status == 404 and self.github_token:
                        raise ValueError("REPO_AUTH_REQUIRED: Repository not accessible with current permissions") from e
                    elif status in (401, 403) and self.github_token:
                        raise ValueError("REPO_TOKEN_INVALID: GitHub token was rejected — may be revoked or expired") from e
                    elif status in (401, 403):
                        raise ValueError("REPO_AUTH_REQUIRED: Repository requires authentication") from e
                    raise

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

        except ValueError as e:
            if "REPO_AUTH_REQUIRED" in str(e) or "REPO_TOKEN_INVALID" in str(e):
                cleanup()
                raise  # Preserve sentinel for worker-level handling
            cleanup()
            raise ValueError(f"Failed to fetch {url}: {e}")
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
                if not skip_file and not skip_dir and c.is_file():
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

    def _extract_repo_traits(self, contracts: list[Path], quality: QualityMetrics) -> dict:
        """Extract deterministic repo traits from contract source code.

        Returns a dict of boolean/string traits used to constrain LLM summary
        generation and build the deterministic fallback summary.
        """
        traits: dict = {
            "language": "unknown",
            "contract_style": "unknown",
            "has_stateful_accounting": False,
            "has_custody": False,
            "has_privileged_flows": False,
            "has_upgradeability": False,
            "has_oracle_dependency": False,
            "has_external_integrations": False,
            "has_signature_logic": False,
            "scope_complexity": "narrow",
        }

        all_source = ""
        sol_count = 0
        vy_count = 0
        for c in contracts:
            try:
                content = c.read_text(errors="ignore")
                all_source += content + "\n"
                if c.suffix == ".sol":
                    sol_count += 1
                elif c.suffix == ".vy":
                    vy_count += 1
            except Exception:
                continue

        # Language
        if sol_count > 0 and vy_count > 0:
            traits["language"] = "mixed"
        elif vy_count > 0:
            traits["language"] = "vyper"
        elif sol_count > 0:
            traits["language"] = "solidity"

        src = all_source.lower()

        # Contract style detection (best guess from keywords)
        style_signals = {
            "token": ["totalsupply", "balanceof", "transfer(", "erc20", "erc721", "erc1155", "mint("],
            "vault": ["deposit(", "withdraw(", "totalassets", "shares", "vault"],
            "amm": ["swap(", "addliquidity", "removeliquidity", "getreserves", "pair"],
            "oracle-consumer": ["latestround", "latestrounddata", "aggregatorv3", "pricefeed", "getprice"],
            "governance": ["propose(", "castVote", "execute(", "quorum", "governor", "timelock"],
            "payment-splitter": ["commission", "split", "transferfrom", "treasury", "pay("],
            "upgradeable-proxy": ["delegatecall", "implementation(", "upgradeto", "initialize(", "proxy"],
            "access-controlled-admin": ["onlyowner", "onlyadmin", "hasrole", "grantRole", "revokeRole"],
        }
        best_style = "utility/helper"
        best_score = 0
        for style, keywords in style_signals.items():
            score = sum(1 for kw in keywords if kw.lower() in src)
            if score > best_score:
                best_score = score
                best_style = style
        if best_score >= 2:
            traits["contract_style"] = best_style
        else:
            traits["contract_style"] = "utility/helper"

        # Boolean trait detection
        accounting_signals = ["balances[", "balanceof[", "totalsupply", "_balances", "mapping(address => uint"]
        traits["has_stateful_accounting"] = any(s in src for s in accounting_signals)

        custody_signals = ["withdraw(", "deposit(", "msg.value", "transfer(msg.sender", "payable("]
        traits["has_custody"] = any(s in src for s in custody_signals)

        privilege_signals = ["onlyowner", "onlyadmin", "hasrole(", "ownable", "accesscontrol", "msg.sender == owner"]
        traits["has_privileged_flows"] = any(s in src for s in privilege_signals)

        upgrade_signals = ["delegatecall", "upgradeto(", "initializer", "uupsupgradeable", "transparentproxy", "implementation()"]
        traits["has_upgradeability"] = any(s in src for s in upgrade_signals)

        oracle_signals = ["aggregatorv3", "latestrounddata", "chainlink", "pricefeed", "twap", "oracle"]
        traits["has_oracle_dependency"] = any(s in src for s in oracle_signals)

        # External integrations beyond standard ERC-20 transferFrom
        ext_signals = ["call(", "staticcall(", "delegatecall(", "interface ", "extcall ", "raw_call("]
        ext_count = sum(1 for s in ext_signals if s in src)
        # transferFrom/approve are standard ERC-20, don't count those alone
        traits["has_external_integrations"] = ext_count >= 2

        sig_signals = ["ecrecover", "eip712", "permit(", "signedmessage", "digest", "v, r, s"]
        traits["has_signature_logic"] = any(s in src for s in sig_signals)

        # Scope complexity
        loc = quality.total_loc or 0
        n_contracts = quality.contract_count or len(contracts)
        if loc > 2000 or n_contracts > 10:
            traits["scope_complexity"] = "broad"
        elif loc > 500 or n_contracts > 3:
            traits["scope_complexity"] = "moderate"
        else:
            traits["scope_complexity"] = "narrow"

        return traits

    def _prepare_source_context(self, contracts: list[Path], max_chars: int = 16000) -> str:
        """Prepare a bounded source code excerpt for LLM consumption.

        Sorts contracts smallest-first so simple contracts are shown in full.
        Hard budget of max_chars guarantees bounded prompt size.
        """
        # Sort by file size ascending, cap at 10 files
        sized = []
        for c in contracts:
            try:
                content = c.read_text(errors="ignore")
                sized.append((c, content))
            except Exception:
                continue
        sized.sort(key=lambda x: len(x[1]))
        sized = sized[:10]

        parts: list[str] = []
        remaining = max_chars
        for path, content in sized:
            header = f"// --- {path.name} ---\n"
            if remaining <= len(header) + 20:
                break
            remaining -= len(header)
            parts.append(header)
            if len(content) <= remaining:
                parts.append(content)
                remaining -= len(content)
            else:
                # Include as many lines as fit
                lines = content.split("\n")
                truncated: list[str] = []
                for line in lines:
                    if remaining < len(line) + 1:
                        break
                    truncated.append(line)
                    remaining -= len(line) + 1
                parts.append("\n".join(truncated))
                parts.append("\n[... truncated]")
                remaining = 0
            parts.append("\n\n")
            remaining -= 2
            if remaining <= 0:
                break

        return "".join(parts)

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
        # Extract traits for summary generation (cheap, deterministic)
        traits = self._extract_repo_traits(contracts, quality)

        try:
            from llm.unified_client import UnifiedLLMClient
        except ImportError:
            # Fallback if LLM not available
            return findings, self._generate_traits_summary(traits, findings, quality)

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
            return findings, self._generate_traits_summary(traits, findings, quality)

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
            return findings, self._generate_traits_summary(traits, findings, quality)

        # Call 1: Verify critical/high findings
        critical_high = [f for f in findings if f.severity in ("critical", "high")]
        if critical_high and self.llm_calls_made < self.llm_budget:
            self._log(f"LLM verifying {len(critical_high)} critical/high finding(s)")
            findings = self._verify_findings_batch(client, critical_high, findings)
            self.llm_calls_made += 1

        # Call 2: Verify medium findings
        medium = [f for f in findings if f.severity == "medium" and not f.llm_verified]
        if medium and self.llm_calls_made < self.llm_budget:
            self._log(f"LLM verifying {len(medium)} medium finding(s)")
            findings = self._verify_findings_batch(client, medium, findings)
            self.llm_calls_made += 1

        # Call 3: Generate context-aware summary
        summary = self._generate_traits_summary(traits, findings, quality)
        if self.llm_calls_made < self.llm_budget:
            self._log("LLM generating context-aware summary")
            summary = self._generate_llm_summary(client, findings, quality, repo_path, contracts, traits)
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
            response = client.generate(
                system="You are a smart contract security auditor. Analyze findings for false positives. Respond with JSON only.",
                user=prompt,
            )
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
        contracts: list[Path],
        traits: dict,
    ) -> str:
        """Generate a context-aware pre-audit posture paragraph using LLM."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            counts[f.severity] += 1

        # Top findings for context (up to 5 most severe)
        sorted_findings = sorted(findings, key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(f.severity, 4))
        top_findings_text = "\n".join(
            f"- [{f.severity}] {f.title}: {f.description[:120]}"
            for f in sorted_findings[:5]
        )

        source_excerpt = self._prepare_source_context(contracts)
        lang = traits.get("language", "unknown")
        version = quality.vyper_version or quality.solidity_version or "unknown"

        system_prompt = (
            "You are a senior smart contract security auditor writing a pre-audit posture assessment. "
            "Write a single paragraph (3-5 sentences) that:\n"
            "1. States what the repository appears to do\n"
            "2. Identifies what materially reduces or increases risk in this specific codebase\n"
            "3. Notes what a full audit would focus on next\n\n"
            "Rules:\n"
            "- Be specific to THIS code — no generic audit boilerplate\n"
            "- NEVER mention risk categories absent from the provided traits "
            "(no oracle talk if has_oracle_dependency is false, no admin risk if has_privileged_flows is false, etc.)\n"
            "- For simple repos, explicitly say the attack surface appears narrow when supported by traits\n"
            "- Auditor tone, not marketing language\n"
            "- Write prose only — no bullet points, no headers, no lists"
        )

        user_prompt = (
            f"Repository: {repo_path.name}\n"
            f"Language: {lang} ({version})\n"
            f"Contracts: {quality.contract_count} files, {quality.total_loc} LOC\n"
            f"Scope complexity: {traits.get('scope_complexity', 'unknown')}\n\n"
            f"Inferred traits:\n"
            f"  contract_style: {traits.get('contract_style', 'unknown')}\n"
            f"  has_stateful_accounting: {traits.get('has_stateful_accounting', False)}\n"
            f"  has_custody: {traits.get('has_custody', False)}\n"
            f"  has_privileged_flows: {traits.get('has_privileged_flows', False)}\n"
            f"  has_upgradeability: {traits.get('has_upgradeability', False)}\n"
            f"  has_oracle_dependency: {traits.get('has_oracle_dependency', False)}\n"
            f"  has_external_integrations: {traits.get('has_external_integrations', False)}\n"
            f"  has_signature_logic: {traits.get('has_signature_logic', False)}\n\n"
            f"Pattern scan results: {counts['critical']} critical, {counts['high']} high, "
            f"{counts['medium']} medium, {counts['low']} low\n"
        )
        if top_findings_text:
            user_prompt += f"\nTop findings:\n{top_findings_text}\n"

        user_prompt += (
            f"\nCode quality: tests={'yes' if quality.has_tests else 'no'}, "
            f"access_control={'yes' if quality.has_access_control else 'no'}, "
            f"events={'yes' if quality.has_events else 'no'}\n\n"
            f"Contract source code:\n{source_excerpt}"
        )

        try:
            response = client.generate(system=system_prompt, user=user_prompt)
            result = response if isinstance(response, str) else str(response)
            # Strip any markdown formatting the LLM might add
            result = result.strip().strip('"').strip("'")
            if result and len(result) > 50:
                return result
            return self._generate_traits_summary(traits, findings, quality)
        except Exception:
            return self._generate_traits_summary(traits, findings, quality)

    def _generate_traits_summary(self, traits: dict, findings: list[Finding], quality: QualityMetrics) -> str:
        """Generate a context-aware summary from traits without LLM."""
        lang = traits.get("language", "unknown").capitalize()
        style = traits.get("contract_style", "unknown").replace("-", " ")
        loc = quality.total_loc or 0
        n_contracts = quality.contract_count or 0
        complexity = traits.get("scope_complexity", "unknown")

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            counts[f.severity] += 1

        # Build the "what it is" part
        parts = [f"This {lang} {style} ({n_contracts} contract{'s' if n_contracts != 1 else ''}, {loc} LOC)"]

        # Build the "what's notable" part
        if complexity == "narrow":
            parts.append("has a narrow attack surface")
        elif complexity == "broad":
            parts.append("has a broad attack surface spanning multiple contracts")

        # Mention absent risk categories (only for narrow/moderate scope)
        absent = []
        if not traits.get("has_privileged_flows"):
            absent.append("admin roles")
        if not traits.get("has_oracle_dependency"):
            absent.append("oracle dependencies")
        if not traits.get("has_upgradeability"):
            absent.append("upgradeability")
        if not traits.get("has_custody"):
            absent.append("user fund custody")
        if absent and complexity != "broad":
            parts.append(f"with no {', '.join(absent)}")

        sentence1 = " ".join(parts) + "."

        # Build findings summary
        if counts["critical"] > 0:
            sentence2 = f"{counts['critical']} critical and {counts['high']} high-severity pattern matches require immediate attention."
        elif counts["high"] > 0:
            sentence2 = f"{counts['high']} high-severity pattern matches warrant review."
        elif counts["medium"] > 0:
            # Be specific about what the findings relate to using pattern IDs
            top_patterns = set()
            for f in findings[:5]:
                if f.pattern_id:
                    # Convert REENTRANCY-001 → "reentrancy" style
                    name = f.pattern_id.split("-")[0].lower() if "-" in f.pattern_id else f.title.lower()
                    top_patterns.add(name)
            pat_text = ", ".join(sorted(top_patterns)[:3]) if top_patterns else "security patterns"
            sentence2 = f"{counts['medium']} medium-severity pattern matches relate to {pat_text}."
        elif counts["low"] > 0:
            sentence2 = f"{counts['low']} low-severity informational findings were noted."
        else:
            sentence2 = "No security patterns were flagged during static analysis."

        # Build "what to audit next" part
        present = []
        if traits.get("has_external_integrations"):
            present.append("external contract interactions")
        if traits.get("has_stateful_accounting"):
            present.append("accounting state transitions")
        if traits.get("has_custody"):
            present.append("fund custody and withdrawal logic")
        if traits.get("has_signature_logic"):
            present.append("signature verification")
        if not present:
            # Infer from findings
            if any("transfer" in (f.title or "").lower() for f in findings):
                present.append("token transfer interaction patterns")
            else:
                present.append("edge cases in the core logic")
        sentence3 = f"A deeper review should validate {' and '.join(present[:2])}."

        return f"{sentence1} {sentence2} {sentence3}"

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
