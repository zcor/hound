"""
Single-auditor driver for the refactored audit pipeline.

Replaces the scout → strategist → finalize triangle with a linear flow:

    scope partition → Claude CLI session per chunk → fp-check per finding → emit gated findings

The auditor spawns **Claude Code CLI** sessions (``claude -p``) with full
tool access: file operations, bash execution, Slither, Foundry, Trail of
Bits plugins, and Pashov skills.  Claude reads files itself, runs static
analysis tools, explores call graphs, and produces findings autonomously.

Key design properties (from issue #38 + zcor's comments):
  * No self-declared "done" — the auditor declares coverage bounds and the
    pipeline decides whether to advance.
  * "What would prove this wrong" gate — before advancing to the next scope
    chunk the auditor must enumerate absent findings that would invalidate
    its coverage claim, and the pipeline verifies each is ruled out.
  * Wei-exact measurement gate — no finding is emitted without a numeric gap
    measurement in the candidate.
  * Instrumentation-order discipline — fp-check Phase 6 includes premise
    re-derivation so PoCs that accidentally measure setup deltas are caught.

Falls back to ``UnifiedLLMClient.parse()`` when the Claude CLI is not
available on ``$PATH``.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from analysis.cards import extract_card_content, load_card_index
from analysis.claude_cli import ClaudeResult, ClaudeSession
from analysis.concurrent_knowledge import Evidence, Hypothesis, HypothesisStore
from analysis.coverage_index import CoverageIndex
from analysis.fp_check import FPCheckPipeline
from analysis.scope_partitioner import ScopeChunk, partition
from llm.schemas import (
    CandidateFinding,
    CandidateFindingBatch,
    CoverageDeclaration,
    FPCheckVerdict,
)
from llm.unified_client import UnifiedLLMClient

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result containers
# ---------------------------------------------------------------------------

@dataclass
class GatedFinding:
    """A finding that passed all fp-check gates."""

    candidate: CandidateFinding
    verdict: FPCheckVerdict
    hypothesis_id: str = ""


@dataclass
class AuditResult:
    """Aggregate result from a full audit run."""

    findings: list[GatedFinding] = field(default_factory=list)
    rejected: list[tuple[CandidateFinding, FPCheckVerdict]] = field(default_factory=list)
    uncertain: list[tuple[CandidateFinding, FPCheckVerdict]] = field(default_factory=list)
    coverage_declarations: list[CoverageDeclaration] = field(default_factory=list)
    chunks_processed: int = 0
    chunks_total: int = 0
    elapsed_seconds: float = 0.0
    token_usage: dict[str, int] = field(default_factory=dict)
    # Counters bumped when ``rejected`` / ``uncertain`` lists hit the bound
    # configured via ``SingleAuditor.audit(max_secondary_results=...)``.  The
    # confirmed ``findings`` list is intentionally unbounded since it is the
    # product of the audit; rejected/uncertain are diagnostic and would
    # otherwise grow without limit on long runs.
    rejected_overflow: int = 0
    uncertain_overflow: int = 0
    # firepan-vff: per-chunk CLI failures that were skipped (not fatal). A
    # timed-out or errored chunk is left partially unaudited but the audit
    # continues; these counters surface that for the coverage report.
    chunk_timeouts: int = 0
    chunk_errors: int = 0


# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

_AUDITOR_SYSTEM = """\
You are a senior smart-contract / code security auditor with access to a
full toolbox: file operations, bash, Slither, semgrep, and (when available)
Foundry and the Trail of Bits plugin suite.

You are auditing a REAL codebase — not a hypothetical one.  USE YOUR TOOLS.

SCOPE DISCIPLINE — read this first:
- You are auditing ONE chunk: the specific files listed in the scope guidance.
  Stay focused on those files and their direct call partners.
- Run ``slither <file>`` on the scoped files individually. Do NOT run
  ``slither .`` on the whole repo — that floods your context with hundreds
  of unrelated detector hits and burns your turn budget.
- Do NOT run the full test suite (``forge test`` with no args). If you want
  to check a specific behavior, run a single targeted test:
  ``forge test --match-test <name>`` or ``forge test --match-contract <name>``.
  Pre-existing failing tests in OTHER parts of the repo are NOT your concern —
  do not try to fix or investigate them.
- When you have enough evidence for your findings, STOP and emit the JSON.
  Do not keep exploring — depth on the scoped files beats breadth.

Workflow:
1. Read the files listed in the scope guidance below.
2. Run ``slither <file>`` on each scoped file. Parse the output for real
   detector hits affecting THOSE files.
3. (Optional) Run a targeted ``forge test --match-*`` if you need to confirm
   a specific hypothesis. Skip if not needed.
4. Trace cross-references, call graphs, and state variables that touch the
   scoped surfaces.
5. For each real vulnerability, produce a CandidateFinding with:
   - title (max 120 chars)
   - description (root cause + attack scenario)
   - vulnerability_type
   - severity: critical / high / medium / low
   - confidence: 0.0-1.0
   - file_line_evidence: at least one {relpath, line_start, line_end, snippet}
   - reasoning: step-by-step chain based on code you ACTUALLY READ
   - numeric_gap_measurement: REQUIRED quantitative impact.
     If you cannot measure a gap, the candidate is NOT ready.
6. Prefer depth over breadth: one well-evidenced finding > five hand-wavy ones.
7. Do NOT rely on training-data priors — read the actual code at the actual
   lines.

Output format:
Emit your findings as a single JSON object inside a ```json fence matching
the CandidateFindingBatch schema:
{
  "candidates": [ ... CandidateFinding objects ... ],
  "scope_summary": "brief description of what you reviewed",
  "surfaces_examined": ["function or contract names you touched"]
}
"""

_CANDIDATE_EXTRACTION_PROMPT = """\
You are auditing the following scope chunk of a codebase.

=== SCOPE GUIDANCE ===
Chunk: {chunk_id}
Files / functions to examine:
{file_list}

Cross-component edges (callers/callees crossing component boundaries):
{cross_edges}

=== EXISTING FINDINGS (do not duplicate) ===
{existing_findings}

=== INSTRUCTIONS ===
1. Use your tools to READ each file listed above.
2. Run ``slither <file>`` on the scoped files individually (NOT ``slither .``).
   Optionally run ``semgrep --config auto <file>``. Parse output for hits
   affecting the scoped files only.
3. Trace data flows, check access control, look for precision loss,
   reentrancy, oracle manipulation, flash-loan attack surfaces, etc.
4. For each real vulnerability, include it in the CandidateFindingBatch.
5. Every candidate MUST have file:line evidence FROM THE ACTUAL CODE and
   a numeric gap measurement.
6. Once you have your findings, STOP and emit the JSON. Do not run the full
   test suite or explore beyond the scoped files.

Output a single ```json block with the CandidateFindingBatch.
If no vulnerabilities are found, return {{"candidates": [], "scope_summary": "...", "surfaces_examined": [...]}}.
"""

_COVERAGE_DECLARATION_PROMPT = """\
You have finished auditing the following scope.

=== SCOPE ===
Chunk: {chunk_id}
Files examined:
{file_list}

=== FINDINGS PRODUCED ===
{findings_summary}

=== INSTRUCTIONS ===
Using your tools, verify your coverage:
1. Name the surfaces/functions you claim to have covered.
2. For each, list a specific claim with measured bounds.
3. List findings that, IF THEY EXISTED, would invalidate your coverage
   claim — these are things you looked for and ruled out.
4. List surfaces you did NOT check (honestly).
5. Set status to "covered", "partial", or "needs_more_investigation".

Output a single ```json block matching the CoverageDeclaration schema:
{{
  "surface_name": "...",
  "claimed_bounds": ["..."],
  "expected_absent_findings": ["..."],
  "unchecked_surfaces": ["..."],
  "status": "covered" | "partial" | "needs_more_investigation"
}}
"""


# ---------------------------------------------------------------------------
# SingleAuditor
# ---------------------------------------------------------------------------

class SingleAuditor:
    """Single-auditor driver for the refactored pipeline.

    Spawns autonomous Claude CLI sessions where Claude reads files, runs
    Slither/Foundry/semgrep, and produces findings with real evidence.
    Hard-fails if the 'claude' CLI binary is unavailable (firepan-vff).
    Use mode=sweep or mode=intuition for legacy multi-agent behavior.

    Usage::

        auditor = SingleAuditor(config=cfg, ...)
        result = auditor.audit(time_limit_minutes=120)
    """

    # firepan-apn: regex constants — copied verbatim from
    # analysis/agent_core.py:2658-2750. Subject parity with AutonomousAgent so
    # SingleAuditor rejects the same hallucinated-symbol candidates.
    _SYMBOL_CONTRACT_DOT_FN_RE = re.compile(r"\b([A-Z][A-Za-z0-9_]+)\.([a-zA-Z_][a-zA-Z0-9_]*)\b")
    _SYMBOL_BACKTICK_RE = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*)`")
    _SYMBOL_CONSTANT_RE = re.compile(r"\b([A-Z][A-Z0-9_]{3,})\b")
    _SYMBOL_STOPWORDS = frozenset({
        "TODO", "FIXME", "XXX", "NOTE", "WARNING", "README",
        "TRUE", "FALSE", "NULL", "NONE",
        "API", "URL", "HTTP", "HTTPS", "JSON", "YAML", "SQL",
    })
    _SYMBOL_EXCLUDED_DIRS = (
        "node_modules", ".git", ".hound",
        "lib/forge-std", "lib/openzeppelin-contracts", "lib/solmate",
    )
    _SYMBOL_SCAN_EXTS = (".sol", ".vy", ".rs", ".ts", ".tsx", ".js", ".py", ".go")

    def __init__(
        self,
        config: dict[str, Any],
        graphs_dir: Path,
        manifest_dir: Path,
        repo_root: Path,
        session_id: str = "",
        agent_id: str = "auditor",
        hypothesis_store: HypothesisStore | None = None,
        coverage_index: CoverageIndex | None = None,
        redis_publisher: Any | None = None,
        debug_logger: Any | None = None,
        progress_callback: Any | None = None,
    ):
        self.config = config
        self.graphs_dir = Path(graphs_dir)
        self.manifest_dir = Path(manifest_dir)
        self.repo_root = Path(repo_root)
        self.session_id = session_id
        self.agent_id = agent_id
        self.hypothesis_store = hypothesis_store
        self.coverage_index = coverage_index
        self.redis_publisher = redis_publisher
        self.debug_logger = debug_logger
        self.progress_callback = progress_callback

        # Lazy-loaded infrastructure
        self._card_index: dict[str, dict] | None = None
        self._file_to_cards: dict[str, list[str]] | None = None

        # firepan-vff: SingleAuditor requires the 'claude' CLI binary. Silent
        # fallback to UnifiedLLMClient reproduces the YieldNest 0/13 TP failure
        # mode on access-control templates — that's exactly what the curation
        # gates downstream are built to prevent, but they can't fix raw
        # candidate output. If you need legacy behavior, use mode=sweep or
        # mode=intuition.
        if not ClaudeSession.available():
            raise RuntimeError(
                "SingleAuditor requires the 'claude' CLI binary on PATH. "
                "Install via scripts/setup-server.sh (dev) or via Dockerfile (prod). "
                "If you intended legacy behavior, use mode=sweep or mode=intuition."
            )
        self._use_cli = True
        logger.info("Claude Code CLI detected — using autonomous audit sessions")

        # firepan-apn: per-session counter of hypotheses rejected by the
        # symbol-exists gate. Read by worker/tasks.py via get_symbol_gate_stats()
        # for overview stamping (parity with AutonomousAgent._symbol_gate_rejections).
        self._symbol_gate_rejections: list[dict] = []

    # ---- public API -------------------------------------------------------

    def audit(
        self,
        time_limit_minutes: int = 120,
        max_chunk_tokens: int = 50_000,
        max_candidates_per_chunk: int = 10,
        max_coverage_retries: int = 2,
        max_secondary_results: int = 500,
    ) -> AuditResult:
        """Run a full audit across all scope chunks.

        Returns an ``AuditResult`` with gated findings, rejections, coverage
        declarations, and timing metadata.

        ``max_secondary_results`` caps the *rejected* and *uncertain* lists
        independently; once the cap is hit further entries are dropped and
        the corresponding ``*_overflow`` counter on the result is
        incremented so callers/UI can show "+N more".  Prevents long audits
        from growing the in-memory result without bound.
        """
        t0 = time.time()
        self._deadline = t0 + time_limit_minutes * 60
        self._max_secondary_results = max_secondary_results
        result = AuditResult()

        # Load card index
        card_index, file_to_cards = self._get_cards()

        # Load coverage data for partitioner
        coverage_data: dict[str, Any] = {}
        if self.coverage_index:
            coverage_data = self.coverage_index.snapshot()

        # Partition the graph into scope chunks
        chunks = partition(
            graphs_dir=self.graphs_dir,
            coverage_data=coverage_data,
            card_index=card_index,
            file_to_cards=file_to_cards,
            max_chunk_tokens=max_chunk_tokens,
        )
        result.chunks_total = len(chunks)

        if not chunks:
            logger.warning("No scope chunks produced — nothing to audit")
            result.elapsed_seconds = time.time() - t0
            return result

        self._publish_status("running", f"Partitioned into {len(chunks)} scope chunks")

        # Create fp-check pipeline
        fp_check = FPCheckPipeline(
            config=self.config,
            repo_root=self.repo_root,
            debug_logger=self.debug_logger,
        )

        # Process each chunk
        for chunk_idx, chunk in enumerate(chunks):
            elapsed = time.time() - t0
            if elapsed > time_limit_minutes * 60:
                self._publish_status("time_limit", f"Time limit reached after {chunk_idx} chunks")
                break

            logger.info(
                "Auditing chunk %s (%d/%d) — %d nodes, priority=%.1f",
                chunk.chunk_id, chunk_idx + 1, len(chunks),
                len(chunk.node_ids), chunk.priority,
            )
            self._publish_progress(chunk_idx, len(chunks), result)

            # ---- A. Build source context for this chunk ----
            source_context = self._build_source_context(chunk, card_index, file_to_cards)
            graph_context = self._build_graph_context(chunk)
            existing = self._existing_findings_summary(result)

            # ---- B. Extract candidate findings ----
            candidates = self._extract_candidates(
                chunk, source_context, graph_context, existing,
                max_candidates_per_chunk, result,
            )

            # ---- C. Run fp-check on each candidate ----
            for candidate in candidates:
                if time.time() - t0 > time_limit_minutes * 60:
                    break

                self._publish_thought(
                    f"Validating candidate: {candidate.title}",
                    chunk_idx,
                )

                # firepan-vff: strict fp-check (no silent per-phase fallback);
                # a CLI failure on this candidate → 'uncertain', audit continues.
                verdict = self._fp_check_safe(fp_check, candidate, source_context)

                if verdict.verdict == "confirmed":
                    hyp_id = self._persist_finding(candidate, verdict)
                    # firepan-apn: _persist_finding returns "" when the symbol-
                    # exists gate rejects the candidate before constructing the
                    # Hypothesis. Treat that as a rejection at the audit-loop
                    # level too — otherwise the candidate would still appear in
                    # result.findings + be published as a finding, breaking the
                    # gate's safety contract.
                    if not hyp_id:
                        self._append_bounded(
                            result.rejected, (candidate, verdict), result, "rejected"
                        )
                        logger.info(
                            "Rejected by symbol_exists_gate (firepan-apn): %s",
                            candidate.title,
                        )
                    else:
                        gf = GatedFinding(
                            candidate=candidate,
                            verdict=verdict,
                            hypothesis_id=hyp_id,
                        )
                        result.findings.append(gf)
                        self._publish_hypothesis(candidate, hyp_id, chunk_idx)
                elif verdict.verdict == "rejected":
                    self._append_bounded(result.rejected, (candidate, verdict), result, "rejected")
                    logger.info("Rejected: %s — %s", candidate.title, verdict.reasoning[:120])
                else:
                    # Uncertain: try to persist as "investigating" for human review,
                    # but if the symbol gate rejects (hyp_id=""), drop instead of
                    # leaving an orphaned uncertain row with no DB record.
                    uncertain_hyp_id = self._persist_finding(
                        candidate, verdict, status="investigating"
                    )
                    if not uncertain_hyp_id:
                        self._append_bounded(
                            result.rejected, (candidate, verdict), result, "rejected"
                        )
                        logger.info(
                            "Uncertain rejected by symbol_exists_gate (firepan-apn): %s",
                            candidate.title,
                        )
                    else:
                        self._append_bounded(result.uncertain, (candidate, verdict), result, "uncertain")
                        logger.info("Uncertain: %s — needs human review", candidate.title)

            # ---- D. Coverage declaration ----
            declaration = self._declare_coverage(chunk, result, source_context)
            if declaration:
                result.coverage_declarations.append(declaration)

                # If coverage is insufficient, retry the chunk (up to max_retries)
                if declaration.status == "needs_more_investigation":
                    for retry in range(max_coverage_retries):
                        if time.time() - t0 > time_limit_minutes * 60:
                            break
                        logger.info(
                            "Coverage insufficient for %s, retry %d/%d",
                            chunk.chunk_id, retry + 1, max_coverage_retries,
                        )
                        # Re-extract with the coverage gaps as guidance
                        gap_prompt = (
                            f"COVERAGE GAPS from previous pass:\n"
                            f"Unchecked: {', '.join(declaration.unchecked_surfaces)}\n"
                            f"Expected absent findings to verify: "
                            f"{', '.join(declaration.expected_absent_findings)}\n"
                        )
                        extra_candidates = self._extract_candidates(
                            chunk,
                            source_context,
                            graph_context + "\n\n" + gap_prompt,
                            self._existing_findings_summary(result),
                            max_candidates_per_chunk,
                            result,
                        )
                        if not extra_candidates:
                            # Coverage retry produced nothing new — escape the
                            # loop instead of re-running the same prompt and
                            # burning the budget on a stuck chunk.
                            logger.info(
                                "Coverage retry %d for %s returned 0 candidates; ending retries",
                                retry + 1, chunk.chunk_id,
                            )
                            break
                        for candidate in extra_candidates:
                            if time.time() - t0 > time_limit_minutes * 60:
                                break
                            # firepan-vff: strict fp-check; CLI failure → uncertain.
                            verdict = self._fp_check_safe(fp_check, candidate, source_context)
                            if verdict.verdict == "confirmed":
                                hyp_id = self._persist_finding(candidate, verdict)
                                # firepan-apn: see main-loop comment above; rejected
                                # candidates must not land in result.findings.
                                if not hyp_id:
                                    self._append_bounded(
                                        result.rejected, (candidate, verdict), result, "rejected"
                                    )
                                    logger.info(
                                        "Rejected by symbol_exists_gate (firepan-apn, retry): %s",
                                        candidate.title,
                                    )
                                else:
                                    gf = GatedFinding(
                                        candidate=candidate,
                                        verdict=verdict,
                                        hypothesis_id=hyp_id,
                                    )
                                    result.findings.append(gf)
                                    self._publish_hypothesis(candidate, hyp_id, chunk_idx)
                            elif verdict.verdict == "rejected":
                                self._append_bounded(result.rejected, (candidate, verdict), result, "rejected")
                            else:
                                self._append_bounded(result.uncertain, (candidate, verdict), result, "uncertain")

                        # Re-declare coverage
                        declaration = self._declare_coverage(chunk, result, source_context)
                        if declaration:
                            result.coverage_declarations[-1] = declaration
                            if declaration.status != "needs_more_investigation":
                                break

            # Mark nodes as visited in coverage index
            if self.coverage_index:
                for nid in chunk.node_ids:
                    self.coverage_index.touch_node(nid)
                self.coverage_index.record_investigation(
                    frame_id=self.session_id,
                    node_ids=chunk.node_ids,
                    status="done",
                )

            result.chunks_processed = chunk_idx + 1

        result.elapsed_seconds = time.time() - t0
        # Snapshot LLM/CLI usage onto the result for downstream reporting.
        self._record_llm_usage(result)
        self._publish_status(
            "completed",
            f"Audit complete: {len(result.findings)} confirmed, "
            f"{len(result.rejected)} rejected, {len(result.uncertain)} uncertain",
        )
        return result

    # ---- source context assembly ------------------------------------------

    def _get_cards(self) -> tuple[dict[str, dict], dict[str, list[str]]]:
        if self._card_index is None:
            graphs_meta = self.graphs_dir / "knowledge_graphs.json"
            self._card_index, self._file_to_cards = load_card_index(
                graphs_metadata_path=graphs_meta,
                manifest_path=self.manifest_dir,
            )
        return self._card_index, self._file_to_cards  # type: ignore[return-value]

    def _build_source_context(
        self,
        chunk: ScopeChunk,
        card_index: dict[str, dict],
        file_to_cards: dict[str, list[str]],
    ) -> str:
        """Assemble source code context for a chunk."""
        parts: list[str] = []
        seen_cards: set[str] = set()

        for cid in chunk.card_ids:
            if cid in seen_cards:
                continue
            seen_cards.add(cid)
            card = card_index.get(cid)
            if not card:
                continue
            content = extract_card_content(card, self.repo_root)
            if content:
                relpath = card.get("relpath", cid)
                parts.append(f"--- {relpath} ---\n{content}")

        if not parts:
            # Fallback: try loading files referenced by nodes directly
            graphs = []
            try:
                for gf in sorted(self.graphs_dir.glob("graph_*.json")):
                    graphs.append(json.loads(gf.read_text()))
            except Exception:
                pass
            seen_files: set[str] = set()
            for g in graphs:
                for n in g.get("nodes") or []:
                    if n.get("id") in chunk.node_ids:
                        for ref in n.get("refs") or n.get("source_files") or []:
                            if ref not in seen_files:
                                seen_files.add(ref)
                                fpath = self.repo_root / ref
                                if fpath.exists() and fpath.stat().st_size < 200_000:
                                    try:
                                        text = fpath.read_text(encoding="utf-8", errors="ignore")
                                        parts.append(f"--- {ref} ---\n{text}")
                                    except Exception:
                                        pass

        return "\n\n".join(parts) if parts else "(no source code available)"

    def _build_graph_context(self, chunk: ScopeChunk) -> str:
        """Build a compact graph context string for a chunk."""
        lines = [f"Nodes ({len(chunk.node_ids)}): {', '.join(chunk.node_ids[:30])}"]
        if len(chunk.node_ids) > 30:
            lines[0] += f" ... (+{len(chunk.node_ids) - 30} more)"

        if chunk.cross_edges:
            lines.append(f"\nCross-component edges ({len(chunk.cross_edges)}):")
            for e in chunk.cross_edges[:20]:
                lines.append(f"  {e['src']} --[{e['type']}]--> {e['dst']}")
            if len(chunk.cross_edges) > 20:
                lines.append(f"  ... (+{len(chunk.cross_edges) - 20} more)")

        return "\n".join(lines)

    def _existing_findings_summary(self, result: AuditResult) -> str:
        """Summary of existing findings to prevent duplicates."""
        if not result.findings:
            return "(none yet)"
        lines = []
        for gf in result.findings:
            lines.append(f"- [{gf.candidate.severity}] {gf.candidate.title}")
        return "\n".join(lines)

    def _fp_check_safe(
        self,
        fp_check: "FPCheckPipeline",
        candidate: "CandidateFinding",
        source_context: str,
    ) -> "FPCheckVerdict":
        """Run strict fp-check; convert a CLI failure into an 'uncertain' verdict.

        firepan-vff: a timeout / transient CLI error during fp-check on one
        candidate must NOT kill the whole audit. We still want strict mode
        (no silent UnifiedLLMClient fallback), but a strict-mode RuntimeError
        is downgraded to 'uncertain' so the candidate gets surfaced for human
        review rather than lost. A fatal error (binary missing) still raises.
        """
        try:
            if self.config.get("fp_check_cli_fallback"):
                return fp_check.run_with_cli_fallback(candidate, source_context, strict=True)
            return fp_check.run(candidate, source_context, strict=True)
        except RuntimeError as exc:
            msg = str(exc).lower()
            if "fatal" in msg or "not found" in msg:
                raise
            logger.warning(
                "fp-check CLI failed for '%s' (%s) — verdict=uncertain, audit continues",
                candidate.title,
                exc,
            )
            return FPCheckVerdict(
                verdict="uncertain",
                confidence=0.5,
                phase_results=[],
                reasoning=f"fp-check did not complete (CLI error: {exc}). Needs human review.",
            )

    # ---- LLM calls --------------------------------------------------------

    def _get_claude_session(self) -> ClaudeSession:
        """Create a new Claude CLI session pointed at the target repo."""
        return ClaudeSession(
            config=self.config,
            working_dir=self.repo_root,
            session_id=self.session_id,
        )

    def _get_llm(self) -> UnifiedLLMClient:
        """Fallback LLM client when Claude CLI is unavailable."""
        return UnifiedLLMClient(
            cfg=self.config,
            profile="auditor",
            debug_logger=self.debug_logger,
        )

    # ---- usage tracking ---------------------------------------------------

    def _append_bounded(
        self,
        target: list,
        item,
        result: AuditResult,
        kind: str,
    ) -> None:
        """Append to ``target`` but enforce ``self._max_secondary_results``.

        Bumps the appropriate ``*_overflow`` counter on ``result`` and drops
        the item once the cap is reached so very long audits cannot grow
        the in-memory result set without bound.
        """
        cap = getattr(self, "_max_secondary_results", 500)
        if len(target) >= cap:
            if kind == "rejected":
                result.rejected_overflow += 1
            else:
                result.uncertain_overflow += 1
            return
        target.append(item)

    def _remaining_budget(self, default: int) -> int:
        """Return min(remaining time, ``default``) in whole seconds.

        Used to clamp per-call subprocess timeouts so that a single Claude CLI
        invocation cannot blow past the audit's overall ``time_limit_minutes``
        deadline.  Returns at least 30s so we never pass 0 (which would be
        an immediate timeout).
        """
        deadline = getattr(self, "_deadline", None)
        if deadline is None:
            return default
        remaining = int(deadline - time.time())
        if remaining <= 0:
            return 30
        return max(30, min(default, remaining))

    def _record_cli_usage(self, result: AuditResult, cli_result: ClaudeResult) -> None:
        """Aggregate Claude CLI cost/turns into ``result.token_usage``.

        The Claude CLI emits cost (USD) and turn counts rather than raw
        token counts; we accumulate both so the final report exposes them.
        """
        usage = result.token_usage
        # cost_usd is float — store *1e6 as int micro-USD to keep dict[int]
        usage["cli_cost_micro_usd"] = int(usage.get("cli_cost_micro_usd", 0)) + int(
            round((cli_result.cost_usd or 0.0) * 1_000_000)
        )
        usage["cli_turns"] = int(usage.get("cli_turns", 0)) + int(cli_result.num_turns or 0)
        usage["cli_calls"] = int(usage.get("cli_calls", 0)) + 1

    def _record_llm_usage(self, result: AuditResult) -> None:
        """Pull token usage from the global token tracker (UnifiedLLMClient sink).

        UnifiedLLMClient already logs to the global token tracker; we mirror
        the input/output totals onto the AuditResult so callers (CLI,
        worker, server, benchmark) can report per-audit usage without
        going through the database.
        """
        try:
            from llm.token_tracker import get_token_tracker
            summary = get_token_tracker().get_summary()
        except Exception:
            return
        totals = (summary or {}).get("totals") or {}
        usage = result.token_usage
        usage["llm_input_tokens"] = int(totals.get("input_tokens", 0))
        usage["llm_output_tokens"] = int(totals.get("output_tokens", 0))
        usage["llm_total_tokens"] = int(totals.get("total_tokens", 0))
        usage["llm_call_count"] = int(totals.get("call_count", 0))

    def _build_file_list(self, chunk: ScopeChunk) -> str:
        """Build a human-readable file list for a scope chunk.

        Instead of dumping source code into the prompt, we list the files
        so Claude Code can read them itself with its file tools.
        """
        card_index, file_to_cards = self._get_cards()
        files: list[str] = []
        seen: set[str] = set()

        for cid in chunk.card_ids:
            card = card_index.get(cid)
            if not card:
                continue
            relpath = card.get("relpath", cid)
            if relpath not in seen:
                seen.add(relpath)
                files.append(relpath)

        # Also try node refs
        if not files:
            graphs = []
            try:
                for gf in sorted(self.graphs_dir.glob("graph_*.json")):
                    graphs.append(json.loads(gf.read_text()))
            except Exception:
                pass
            for g in graphs:
                for n in g.get("nodes") or []:
                    if n.get("id") in chunk.node_ids:
                        for ref in n.get("refs") or n.get("source_files") or []:
                            if ref not in seen:
                                seen.add(ref)
                                files.append(ref)

        if not files:
            return "(no specific files — explore the repository)"

        return "\n".join(f"  - {f}" for f in files)

    def _build_cross_edges_text(self, chunk: ScopeChunk) -> str:
        """Format cross-edges for the prompt."""
        if not chunk.cross_edges:
            return "(none)"
        lines = []
        for e in chunk.cross_edges[:30]:
            lines.append(f"  {e['src']} --[{e['type']}]--> {e['dst']}")
        if len(chunk.cross_edges) > 30:
            lines.append(f"  ... (+{len(chunk.cross_edges) - 30} more)")
        return "\n".join(lines)

    def _extract_candidates(
        self,
        chunk: ScopeChunk,
        source_context: str,
        graph_context: str,
        existing_findings: str,
        max_candidates: int,
        result: AuditResult | None = None,
    ) -> list[CandidateFinding]:
        """Extract candidate findings from a scope chunk.

        When the Claude CLI is available, spawns an autonomous session where
        Claude reads files/runs tools itself.  Falls back to
        ``UnifiedLLMClient.parse()`` with pre-assembled source context.
        """
        if self._use_cli:
            return self._extract_candidates_cli(
                chunk, existing_findings, max_candidates, result,
            )
        return self._extract_candidates_fallback(
            chunk, source_context, graph_context, existing_findings, max_candidates,
        )

    # CLI errors that mean "this run is misconfigured / broken" — keep raising
    # on these (no point continuing, and we must NOT silently fall back to
    # UnifiedLLMClient which would reproduce the YieldNest failure mode).
    _FATAL_CLI_ERRORS = frozenset({"not_found", "permission_denied", "os_error"})

    def _extract_candidates_cli(
        self,
        chunk: ScopeChunk,
        existing_findings: str,
        max_candidates: int,
        result: AuditResult | None = None,
    ) -> list[CandidateFinding]:
        """Claude CLI extraction — autonomous file reading + tool use.

        firepan-vff: distinguishes fatal CLI errors (auth/config broken — raise,
        no silent UnifiedLLMClient fallback) from a per-chunk *timeout* (skip
        this chunk, return [], let the audit continue and the coverage
        declaration note the gap). A slow chunk N must NOT lose chunks 1..N-1.
        """
        file_list = self._build_file_list(chunk)
        cross_edges = self._build_cross_edges_text(chunk)

        prompt = _CANDIDATE_EXTRACTION_PROMPT.format(
            chunk_id=chunk.chunk_id,
            file_list=file_list,
            cross_edges=cross_edges,
            existing_findings=existing_findings,
        )

        session = self._get_claude_session()
        cli_result = session.run(
            prompt,
            system_prompt=_AUDITOR_SYSTEM,
            timeout=self._remaining_budget(session.timeout),
        )
        if result is not None:
            self._record_cli_usage(result, cli_result)

        if cli_result.is_error:
            err = cli_result.raw_json.get("error", "<unknown>")
            if err == "timeout":
                logger.warning(
                    "Candidate extraction timed out for %s — skipping chunk, "
                    "continuing audit (chunk left partially unaudited)",
                    chunk.chunk_id,
                )
                if result is not None:
                    result.chunk_timeouts = getattr(result, "chunk_timeouts", 0) + 1
                return []
            if err in self._FATAL_CLI_ERRORS:
                raise RuntimeError(
                    "candidate extraction CLI fatal error for %s: %s"
                    % (chunk.chunk_id, err)
                )
            # Other errors (HTTP 4xx/5xx, malformed JSON, "<unknown>"):
            # treat as a chunk failure, not an audit failure — skip and continue.
            logger.warning(
                "Candidate extraction CLI error for %s (%s) — skipping chunk",
                chunk.chunk_id,
                err,
            )
            if result is not None:
                result.chunk_errors = getattr(result, "chunk_errors", 0) + 1
            return []

        return self._parse_candidates_from_result(cli_result, chunk, max_candidates)

    def _extract_candidates_fallback(
        self,
        chunk: ScopeChunk,
        source_context: str,
        graph_context: str,
        existing_findings: str,
        max_candidates: int,
    ) -> list[CandidateFinding]:
        """Fallback extraction via UnifiedLLMClient.parse()."""
        # Use the old-style prompt with pre-assembled source code
        prompt = (
            f"You are reviewing the following source code scope.\n\n"
            f"=== SCOPE ===\nChunk: {chunk.chunk_id}\n"
            f"Nodes: {len(chunk.node_ids)}\n"
            f"Cross-edges: {len(chunk.cross_edges)}\n\n"
            f"=== GRAPH CONTEXT ===\n{graph_context}\n\n"
            f"=== SOURCE CODE ===\n{source_context}\n\n"
            f"=== EXISTING FINDINGS ===\n{existing_findings}\n\n"
            f"Analyze for security vulnerabilities. Return JSON matching "
            f"CandidateFindingBatch schema."
        )
        llm = self._get_llm()
        try:
            batch = llm.parse(
                system=_AUDITOR_SYSTEM,
                user=prompt,
                schema=CandidateFindingBatch,
            )
            candidates = batch.candidates[:max_candidates]
            logger.info(
                "Extracted %d candidates from %s (fallback mode)",
                len(candidates), chunk.chunk_id,
            )
            return candidates
        except Exception:
            logger.warning("Candidate extraction failed for %s", chunk.chunk_id, exc_info=True)
            return []

    def _parse_candidates_from_result(
        self,
        result: ClaudeResult,
        chunk: ScopeChunk,
        max_candidates: int,
    ) -> list[CandidateFinding]:
        """Parse CandidateFinding objects from a Claude CLI result."""
        data = result.extract_json()
        if not data or not isinstance(data, dict):
            logger.warning(
                "Could not extract JSON from Claude CLI output for %s",
                chunk.chunk_id,
            )
            return []

        try:
            batch = CandidateFindingBatch.model_validate(data)
            candidates = batch.candidates[:max_candidates]
            logger.info(
                "Extracted %d candidates from %s via Claude CLI "
                "(cost=$%.4f, turns=%d)",
                len(candidates),
                chunk.chunk_id,
                result.cost_usd,
                result.num_turns,
            )
            return candidates
        except Exception:
            # Try parsing individual candidates from a list
            raw_candidates = data.get("candidates", [])
            if not raw_candidates:
                return []
            candidates = []
            for raw in raw_candidates[:max_candidates]:
                try:
                    candidates.append(CandidateFinding.model_validate(raw))
                except Exception:
                    logger.warning("Skipping malformed candidate: %s", str(raw)[:200])
            return candidates

    def _declare_coverage(
        self,
        chunk: ScopeChunk,
        result: AuditResult,
        source_context: str,
    ) -> CoverageDeclaration | None:
        """Ask the auditor to declare coverage for a chunk."""
        findings_in_chunk = [
            f"- [{gf.candidate.severity}] {gf.candidate.title} "
            f"(verdict: {gf.verdict.verdict}, confidence: {gf.verdict.confidence:.2f})"
            for gf in result.findings
        ]

        file_list = self._build_file_list(chunk)
        findings_summary = "\n".join(findings_in_chunk) if findings_in_chunk else "(no findings)"

        # firepan-vff: CLI-only path (no silent UnifiedLLMClient fallback —
        # that would reproduce the YieldNest failure mode). But a coverage
        # declaration is best-effort: on a CLI error, malformed JSON, or
        # schema mismatch, return None (== "no declaration for this chunk")
        # rather than killing the whole audit. A fatal CLI error (binary
        # missing etc.) still raises since the run is unrecoverable.
        prompt = _COVERAGE_DECLARATION_PROMPT.format(
            chunk_id=chunk.chunk_id,
            file_list=file_list,
            findings_summary=findings_summary,
        )
        session = self._get_claude_session()
        cov_result = session.run(
            prompt,
            system_prompt=_AUDITOR_SYSTEM,
            max_turns=15,
            timeout=self._remaining_budget(300),
        )
        self._record_cli_usage(result, cov_result)
        if cov_result.is_error:
            err = cov_result.raw_json.get("error", "<unknown>")
            if err in self._FATAL_CLI_ERRORS:
                raise RuntimeError(
                    "coverage declaration CLI fatal error for %s: %s"
                    % (chunk.chunk_id, err)
                )
            logger.warning(
                "Coverage declaration CLI error for %s (%s) — no declaration",
                chunk.chunk_id,
                err,
            )
            return None
        data = cov_result.extract_json()
        if not isinstance(data, dict):
            logger.warning(
                "Coverage declaration returned non-dict for %s — no declaration",
                chunk.chunk_id,
            )
            return None
        try:
            return CoverageDeclaration.model_validate(data)
        except Exception as exc:
            logger.warning(
                "Coverage declaration schema mismatch for %s (%s) — no declaration",
                chunk.chunk_id,
                exc,
            )
            return None

    # ---- persistence & publishing -----------------------------------------

    def _persist_finding(
        self,
        candidate: CandidateFinding,
        verdict: FPCheckVerdict,
        status: str = "confirmed",
    ) -> str:
        """Persist a gated finding to the HypothesisStore."""
        if not self.hypothesis_store:
            return ""

        # firepan-apn parity (hard blocker for auditor mode): reject candidates
        # whose cited symbols don't appear in the scanned commit. Kills
        # training-data drift hallucinations before they hit the hypothesis
        # store. Stats exposed via get_symbol_gate_stats() for overview stamping.
        if (self.config or {}).get('deep_audit_symbol_exists_gate', True):
            ok, unknown = self._validate_symbols_exist(candidate)
            if not ok:
                self._symbol_gate_rejections.append({
                    'title': candidate.title,
                    'unknown_symbols': unknown,
                    'source_files': [ev.relpath for ev in candidate.file_line_evidence],
                    'vulnerability_type': candidate.vulnerability_type,
                })
                logger.info(
                    "SingleAuditor rejected hypothesis (symbol_exists_gate): "
                    "cited symbols not in repo — %s",
                    unknown,
                )
                return ""

        # Build evidence list from fp-check phase results
        evidence_list = []
        for pr in verdict.phase_results:
            evidence_list.append(Evidence(
                description=f"[{pr.phase_name}] {pr.reasoning[:300]}",
                type="supports" if pr.passed else "refutes",
                confidence=pr.confidence,
                created_by=self.agent_id,
            ))

        # Map file_line_evidence to node_refs (best-effort)
        node_refs = []
        source_files = []
        for ev in candidate.file_line_evidence:
            node_refs.append(f"{ev.relpath}:{ev.line_start}-{ev.line_end}")
            if ev.relpath not in source_files:
                source_files.append(ev.relpath)

        # Determine model names from config
        auditor_cfg = self.config.get("models", {}).get("auditor", {})
        model_name = auditor_cfg.get("model", "unknown")

        hyp = Hypothesis(
            title=candidate.title,
            description=candidate.description,
            vulnerability_type=candidate.vulnerability_type,
            severity=candidate.severity,
            confidence=verdict.confidence,
            status=status,
            node_refs=node_refs,
            evidence=evidence_list,
            reasoning=candidate.reasoning,
            properties={
                "numeric_gap_measurement": candidate.numeric_gap_measurement,
                "fp_check_verdict": verdict.verdict,
                "fp_check_confidence": verdict.confidence,
                "numeric_gap_verified": verdict.numeric_gap_verified,
                "verified_gap_value": verdict.verified_gap_value,
                "poc_stub": verdict.poc_stub,
                "negative_poc": verdict.negative_poc,
                "devil_advocate_notes": verdict.devil_advocate_notes,
                "source_files": source_files,
                "pipeline": "single_auditor",
            },
            created_by=self.agent_id,
            reported_by_model=model_name,
            junior_model=model_name,
            # firepan-vff: single-auditor mode has no senior verifier by
            # definition. Setting senior_model=model_name would mask
            # firepan-281's "DeepSeek verifying DeepSeek" detection signal in
            # postmortem queries. Leave NULL so the audit trail is honest.
            senior_model=None,
            session_id=self.session_id,
        )

        success, hyp_id = self.hypothesis_store.propose(hyp)
        if success:
            # Add evidence records
            for ev in evidence_list:
                self.hypothesis_store.add_evidence(hyp_id, ev)
            # Track coverage at the card level (CoverageIndex keys by card/node id,
            # not file refs). Map each evidence relpath to its card ids via the
            # already-loaded file_to_cards index and bump those cards.
            if self.coverage_index:
                _, file_to_cards = self._get_cards()
                touched: set[str] = set()
                for ev in candidate.file_line_evidence:
                    for card_id in file_to_cards.get(ev.relpath, []) or []:
                        if card_id in touched:
                            continue
                        touched.add(card_id)
                        try:
                            self.coverage_index.touch_card(card_id)
                        except Exception:
                            logger.debug("coverage_index.touch_card failed for %s", card_id, exc_info=True)
            logger.info("Persisted finding %s: %s (%s)", hyp_id, candidate.title, status)
        else:
            logger.warning("Failed to persist finding: %s (reason: %s)", candidate.title, hyp_id)
        return hyp_id if success else ""

    def _publish_status(self, status: str, message: str = "") -> None:
        if self.redis_publisher:
            try:
                self.redis_publisher.publish_status(status, message)
            except Exception:
                logger.debug("redis publish_status failed", exc_info=True)
        if self.progress_callback:
            try:
                self.progress_callback({"status": status, "message": message})
            except Exception:
                logger.debug("progress_callback failed", exc_info=True)

    def _publish_progress(self, chunk_idx: int, total: int, result: AuditResult) -> None:
        if self.redis_publisher:
            try:
                self.redis_publisher.publish_progress(
                    iteration=chunk_idx,
                    max_iterations=total,
                    nodes_visited=sum(
                        len(d.claimed_bounds) for d in result.coverage_declarations
                    ),
                    hypotheses_count=len(result.findings),
                )
            except Exception:
                logger.debug("redis publish_progress failed", exc_info=True)

    def _publish_thought(self, thought: str, iteration: int = 0) -> None:
        if self.redis_publisher:
            try:
                self.redis_publisher.publish_thought(thought, iteration)
            except Exception:
                logger.debug("redis publish_thought failed", exc_info=True)

    def _publish_hypothesis(
        self,
        candidate: CandidateFinding,
        hyp_id: str,
        iteration: int = 0,
    ) -> None:
        if self.redis_publisher:
            try:
                self.redis_publisher.publish_hypothesis(
                    hypothesis_id=hyp_id,
                    title=candidate.title,
                    confidence=candidate.confidence,
                    severity=candidate.severity,
                    iteration=iteration,
                )
            except Exception:
                logger.debug("redis publish_hypothesis failed", exc_info=True)

    # ---- firepan-apn symbol-exists gate -----------------------------------
    # Parity port of analysis/agent_core.py:2666-2750 so SingleAuditor rejects
    # the same hallucinated-symbol candidates AutonomousAgent does.

    def _extract_cited_symbols(self, candidate: CandidateFinding) -> set[str]:
        """Pull candidate code symbols from candidate.title + candidate.description.

        Mirror of AutonomousAgent._extract_cited_symbols (agent_core.py:2666),
        parameterized on CandidateFinding instead of the legacy Hypothesis.
        Returns a set of tokens that look like code identifiers (not prose).
        """
        title = getattr(candidate, "title", "") or ""
        desc = getattr(candidate, "description", "") or ""
        text = f"{title}\n{desc[:2000]}"
        symbols: set[str] = set()

        # Contract.fn pairs — emit both halves so grep finds them individually.
        for m in self._SYMBOL_CONTRACT_DOT_FN_RE.finditer(text):
            contract, fn = m.group(1), m.group(2)
            if contract not in self._SYMBOL_STOPWORDS:
                symbols.add(contract)
            if len(fn) >= 3:
                symbols.add(fn)
        for m in self._SYMBOL_BACKTICK_RE.finditer(text):
            tok = m.group(1)
            if tok not in self._SYMBOL_STOPWORDS:
                symbols.add(tok)
        for m in self._SYMBOL_CONSTANT_RE.finditer(text):
            tok = m.group(1)
            if tok not in self._SYMBOL_STOPWORDS:
                symbols.add(tok)
        return symbols

    def _validate_symbols_exist(self, candidate: CandidateFinding) -> tuple[bool, list[str]]:
        """Return (True, []) if all cited symbols exist in the scanned repo.

        Strict parity port of AutonomousAgent._validate_symbols_exist
        (agent_core.py:2705). Differences from the earlier looser port that
        let candidates citing `Owner` slip through when only
        `OwnershipTransferred` was present:

        - Uses word-boundary regex (`\\bSYM\\b`) instead of bare substring `in`.
        - Excluded-dir check uses substring (`ex in rel`) not `rel.startswith(d)`,
          so `lib/forge-std/...` is excluded even when nested.
        - Walks paths once and builds a presence set (O(n) over files instead
          of O(n*m) for symbols × files). Capped at 400 files like the legacy.

        Soft-fails to (True, []) when self.repo_root is unavailable or no
        candidate symbols can be extracted.
        """
        repo_root = getattr(self, "repo_root", None)
        if repo_root is None or not repo_root.exists():
            return (True, [])
        symbols = self._extract_cited_symbols(candidate)
        if not symbols:
            return (True, [])

        present: set[str] = set()
        files_scanned = 0
        for path in repo_root.rglob("*"):
            if files_scanned >= 400:
                break
            if not path.is_file():
                continue
            rel = str(path.relative_to(repo_root))
            if any(ex in rel for ex in self._SYMBOL_EXCLUDED_DIRS):
                continue
            if path.suffix not in self._SYMBOL_SCAN_EXTS:
                continue
            files_scanned += 1
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for sym in symbols - present:
                if re.search(rf"\b{re.escape(sym)}\b", text):
                    present.add(sym)
            if len(present) == len(symbols):
                break

        unknown = sorted(symbols - present)
        if unknown:
            return (False, unknown)
        return (True, [])

    def get_symbol_gate_stats(self) -> dict:
        """Mirror of AutonomousAgent.get_symbol_gate_stats (agent_core.py:2752).

        Worker/tasks.py reads this via the `symbol_gate_provider` parameter to
        _stamp_overview_with_gate_stats() so the auditor branch stamps the same
        overview.symbol_exists_gate observability dict as the legacy branch.
        """
        return {
            "rejected_count": len(self._symbol_gate_rejections),
            "rejections": list(self._symbol_gate_rejections),
        }
