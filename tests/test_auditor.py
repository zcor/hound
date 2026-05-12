"""
Unit tests for the single-auditor pipeline (analysis/auditor.py).

NOTE (firepan-vff): The PR-39 tests in this module exercised the silent
UnifiedLLMClient fallback paths that we intentionally removed (those paths
reintroduced the YieldNest 0/13 TP failure mode by routing candidate
extraction through the same DeepSeek model that produced the original
hallucinations). The whole module is skipped pending a rewrite that mocks
the CLI session for both candidate-extraction AND coverage-declaration
calls instead of relying on the now-removed UnifiedLLMClient fallback.

Replacement coverage already lives in:
- tests/test_auditor_symbol_gate.py — firepan-apn parity port + constructor
  hard-fail when CLI is unavailable.
- tests/test_fp_check.py::TestRunStrictMode — strict=True kwarg semantics.

A follow-up under firepan-vff-2 will reauthor this module against the new
CLI-only contract.
"""

import pytest

pytest.skip(
    "Pending rewrite for CLI-only contract (firepan-vff). "
    "See module docstring; replacement tests in test_auditor_symbol_gate.py "
    "and test_fp_check.py::TestRunStrictMode.",
    allow_module_level=True,
)

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.auditor import AuditResult, GatedFinding, SingleAuditor
from analysis.claude_cli import ClaudeResult, ClaudeSession
from llm.schemas import (
    CandidateFinding,
    CandidateFindingBatch,
    CoverageDeclaration,
    FileLineEvidence,
    FPCheckPhaseResult,
    FPCheckVerdict,
)


def _mock_config():
    return {
        "models": {
            "auditor": {
                "provider": "mock",
                "model": "mock-auditor",
                "api_key": "test",
                "max_context": 200000,
                "temperature": 0.1,
            }
        }
    }


def _make_candidate(**overrides):
    defaults = dict(
        title="Test Reentrancy in withdraw()",
        description="External call before state update in withdraw()",
        vulnerability_type="reentrancy",
        severity="high",
        confidence=0.9,
        file_line_evidence=[FileLineEvidence(
            relpath="contracts/Vault.sol",
            line_start=42,
            line_end=55,
            snippet="msg.sender.call{value: amount}('');"
        )],
        reasoning="Step 1: external call. Step 2: state update after call.",
        numeric_gap_measurement="100% of deposited balance drainable",
    )
    defaults.update(overrides)
    return CandidateFinding(**defaults)


def _make_verdict(verdict="confirmed", confidence=0.92, **overrides):
    defaults = dict(
        verdict=verdict,
        confidence=confidence,
        phase_results=[
            FPCheckPhaseResult(
                phase_name="data_flow",
                passed=True,
                confidence=0.95,
                reasoning="Data flow confirmed",
                evidence="trace from input to call",
            ),
        ],
        devil_advocate_notes="No guards found",
        poc_stub="// PoC stub",
        negative_poc="// negative PoC",
        reasoning="All phases passed",
        numeric_gap_verified=True,
        verified_gap_value="100% drainable",
    )
    defaults.update(overrides)
    return FPCheckVerdict(**defaults)


class TestAuditResult(unittest.TestCase):
    """Test AuditResult dataclass."""

    def test_default_values(self):
        result = AuditResult()
        self.assertEqual(result.findings, [])
        self.assertEqual(result.rejected, [])
        self.assertEqual(result.uncertain, [])
        self.assertEqual(result.chunks_processed, 0)
        self.assertEqual(result.chunks_total, 0)

    def test_gated_finding(self):
        c = _make_candidate()
        v = _make_verdict()
        gf = GatedFinding(candidate=c, verdict=v, hypothesis_id="hyp_123")
        self.assertEqual(gf.hypothesis_id, "hyp_123")
        self.assertEqual(gf.candidate.severity, "high")


class TestSingleAuditorInit(unittest.TestCase):
    """Test SingleAuditor initialization."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.graphs_dir = Path(self.temp_dir) / "graphs"
        self.manifest_dir = Path(self.temp_dir) / "manifest"
        self.graphs_dir.mkdir()
        self.manifest_dir.mkdir()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("analysis.auditor.ClaudeSession.available", return_value=False)
    def test_init(self, _mock_cli):
        auditor = SingleAuditor(
            config=_mock_config(),
            graphs_dir=self.graphs_dir,
            manifest_dir=self.manifest_dir,
            repo_root=Path(self.temp_dir),
            session_id="test_session",
        )
        self.assertEqual(auditor.session_id, "test_session")
        self.assertEqual(auditor.agent_id, "auditor")
        self.assertIsNone(auditor._card_index)


class TestSingleAuditorAudit(unittest.TestCase):
    """Test the audit() method with mocked dependencies (fallback mode)."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.graphs_dir = Path(self.temp_dir) / "graphs"
        self.manifest_dir = Path(self.temp_dir) / "manifest"
        self.graphs_dir.mkdir()
        self.manifest_dir.mkdir()

        # Force fallback mode (no Claude CLI)
        self._cli_patch = patch("analysis.auditor.ClaudeSession.available", return_value=False)
        self._cli_patch.start()

        # Create minimal graph files
        graph_data = {
            "nodes": [
                {"id": "node_1", "label": "Vault", "type": "contract",
                 "source_files": ["contracts/Vault.sol"]},
                {"id": "node_2", "label": "Token", "type": "contract",
                 "source_files": ["contracts/Token.sol"]},
            ],
            "edges": [
                {"source": "node_1", "target": "node_2", "type": "calls"},
            ],
        }
        (self.graphs_dir / "graph_system.json").write_text(json.dumps(graph_data))
        (self.graphs_dir / "knowledge_graphs.json").write_text(
            json.dumps({"graphs": {"system": str(self.graphs_dir / "graph_system.json")}})
        )

        # Create minimal manifest
        (self.manifest_dir / "files.json").write_text(json.dumps([]))

        # Create a source file so the auditor can read it
        contracts_dir = Path(self.temp_dir) / "contracts"
        contracts_dir.mkdir()
        (contracts_dir / "Vault.sol").write_text("pragma solidity ^0.8.0;\ncontract Vault {}\n")

    def tearDown(self):
        self._cli_patch.stop()
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("analysis.auditor.SingleAuditor._get_llm")
    @patch("analysis.auditor.FPCheckPipeline")
    @patch("analysis.auditor.partition")
    @patch("analysis.auditor.load_card_index")
    def test_audit_empty_chunks(self, mock_cards, mock_partition, mock_fp, mock_llm):
        """Audit with no scope chunks returns empty result."""
        mock_cards.return_value = ({}, {})
        mock_partition.return_value = []

        auditor = SingleAuditor(
            config=_mock_config(),
            graphs_dir=self.graphs_dir,
            manifest_dir=self.manifest_dir,
            repo_root=Path(self.temp_dir),
        )
        result = auditor.audit(time_limit_minutes=5)

        self.assertEqual(result.chunks_total, 0)
        self.assertEqual(result.findings, [])
        self.assertGreater(result.elapsed_seconds, 0)

    @patch("analysis.auditor.SingleAuditor._get_llm")
    @patch("analysis.auditor.FPCheckPipeline")
    @patch("analysis.auditor.partition")
    @patch("analysis.auditor.load_card_index")
    def test_audit_confirmed_finding(self, mock_cards, mock_partition, mock_fp, mock_llm):
        """A confirmed finding passes through gating and into results."""
        from analysis.scope_partitioner import ScopeChunk

        mock_cards.return_value = ({}, {})

        chunk = ScopeChunk(
            chunk_id="chunk_0",
            node_ids=["node_1", "node_2"],
            card_ids=[],
            cross_edges=[],
            estimated_tokens=1000,
            priority=1.0,
        )
        mock_partition.return_value = [chunk]

        # Mock fp-check to confirm
        fp_instance = MagicMock()
        fp_instance.run.return_value = _make_verdict("confirmed", 0.92)
        mock_fp.return_value = fp_instance

        # Mock LLM to return candidates
        llm_instance = MagicMock()
        llm_instance.parse.side_effect = [
            # First call: candidate extraction
            CandidateFindingBatch(
                candidates=[_make_candidate()],
                scope_summary="Vault contract analysis",
                surfaces_examined=["withdraw()"],
            ),
            # Second call: coverage declaration
            CoverageDeclaration(
                surface_name="Vault",
                claimed_bounds=["checked reentrancy on withdraw()"],
                expected_absent_findings=["flash loan manipulation"],
                unchecked_surfaces=[],
                status="covered",
            ),
        ]
        mock_llm.return_value = llm_instance

        auditor = SingleAuditor(
            config=_mock_config(),
            graphs_dir=self.graphs_dir,
            manifest_dir=self.manifest_dir,
            repo_root=Path(self.temp_dir),
        )
        result = auditor.audit(time_limit_minutes=5)

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].candidate.title, "Test Reentrancy in withdraw()")
        self.assertEqual(result.findings[0].verdict.verdict, "confirmed")
        self.assertEqual(result.chunks_processed, 1)

    @patch("analysis.auditor.SingleAuditor._get_llm")
    @patch("analysis.auditor.FPCheckPipeline")
    @patch("analysis.auditor.partition")
    @patch("analysis.auditor.load_card_index")
    def test_audit_rejected_finding(self, mock_cards, mock_partition, mock_fp, mock_llm):
        """A rejected finding is tracked but not emitted."""
        from analysis.scope_partitioner import ScopeChunk

        mock_cards.return_value = ({}, {})
        chunk = ScopeChunk(
            chunk_id="chunk_0",
            node_ids=["node_1"],
            card_ids=[],
            cross_edges=[],
            estimated_tokens=500,
            priority=1.0,
        )
        mock_partition.return_value = [chunk]

        fp_instance = MagicMock()
        fp_instance.run.return_value = _make_verdict("rejected", 0.1)
        mock_fp.return_value = fp_instance

        llm_instance = MagicMock()
        llm_instance.parse.side_effect = [
            CandidateFindingBatch(
                candidates=[_make_candidate()],
                scope_summary="analysis",
                surfaces_examined=["withdraw()"],
            ),
            CoverageDeclaration(
                surface_name="Vault",
                claimed_bounds=["checked reentrancy"],
                expected_absent_findings=[],
                status="covered",
            ),
        ]
        mock_llm.return_value = llm_instance

        auditor = SingleAuditor(
            config=_mock_config(),
            graphs_dir=self.graphs_dir,
            manifest_dir=self.manifest_dir,
            repo_root=Path(self.temp_dir),
        )
        result = auditor.audit(time_limit_minutes=5)

        self.assertEqual(len(result.findings), 0)
        self.assertEqual(len(result.rejected), 1)

    @patch("analysis.auditor.SingleAuditor._get_llm")
    @patch("analysis.auditor.FPCheckPipeline")
    @patch("analysis.auditor.partition")
    @patch("analysis.auditor.load_card_index")
    def test_audit_uncertain_finding(self, mock_cards, mock_partition, mock_fp, mock_llm):
        """An uncertain verdict lands in the ``uncertain`` bucket, not findings."""
        from analysis.scope_partitioner import ScopeChunk

        mock_cards.return_value = ({}, {})
        chunk = ScopeChunk(
            chunk_id="chunk_0",
            node_ids=["node_1"],
            card_ids=[],
            cross_edges=[],
            estimated_tokens=500,
            priority=1.0,
        )
        mock_partition.return_value = [chunk]

        fp_instance = MagicMock()
        fp_instance.run.return_value = _make_verdict("uncertain", 0.5)
        mock_fp.return_value = fp_instance

        llm_instance = MagicMock()
        llm_instance.parse.side_effect = [
            CandidateFindingBatch(
                candidates=[_make_candidate()],
                scope_summary="analysis",
                surfaces_examined=["withdraw()"],
            ),
            CoverageDeclaration(
                surface_name="Vault",
                claimed_bounds=["checked"],
                expected_absent_findings=[],
                status="covered",
            ),
        ]
        mock_llm.return_value = llm_instance

        auditor = SingleAuditor(
            config=_mock_config(),
            graphs_dir=self.graphs_dir,
            manifest_dir=self.manifest_dir,
            repo_root=Path(self.temp_dir),
        )
        result = auditor.audit(time_limit_minutes=5)

        self.assertEqual(len(result.findings), 0)
        self.assertEqual(len(result.rejected), 0)
        self.assertEqual(len(result.uncertain), 1)

    @patch("analysis.auditor.SingleAuditor._get_llm")
    @patch("analysis.auditor.FPCheckPipeline")
    @patch("analysis.auditor.partition")
    @patch("analysis.auditor.load_card_index")
    def test_hypothesis_store_rejection_does_not_emit(
        self, mock_cards, mock_partition, mock_fp, mock_llm
    ):
        """When the hypothesis store rejects (e.g. duplicate), no finding is emitted."""
        from analysis.scope_partitioner import ScopeChunk

        mock_cards.return_value = ({}, {})
        chunk = ScopeChunk(
            chunk_id="chunk_0",
            node_ids=["node_1"],
            card_ids=[],
            cross_edges=[],
            estimated_tokens=500,
            priority=1.0,
        )
        mock_partition.return_value = [chunk]

        fp_instance = MagicMock()
        fp_instance.run.return_value = _make_verdict("confirmed", 0.95)
        mock_fp.return_value = fp_instance

        llm_instance = MagicMock()
        llm_instance.parse.side_effect = [
            CandidateFindingBatch(
                candidates=[_make_candidate()],
                scope_summary="analysis",
                surfaces_examined=["withdraw()"],
            ),
            CoverageDeclaration(
                surface_name="Vault",
                claimed_bounds=["checked"],
                expected_absent_findings=[],
                status="covered",
            ),
        ]
        mock_llm.return_value = llm_instance

        # Hypothesis store reports duplicate / rejection
        hyp_store = MagicMock()
        hyp_store.propose.return_value = (False, "Duplicate title: hyp_existing")

        auditor = SingleAuditor(
            config=_mock_config(),
            graphs_dir=self.graphs_dir,
            manifest_dir=self.manifest_dir,
            repo_root=Path(self.temp_dir),
            hypothesis_store=hyp_store,
        )
        result = auditor.audit(time_limit_minutes=5)

        # Confirmed by fp-check but not persisted -> still recorded but with empty hyp id
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].hypothesis_id, "")
        hyp_store.propose.assert_called_once()
        hyp_store.add_evidence.assert_not_called()

    @patch("analysis.auditor.SingleAuditor._get_llm")
    @patch("analysis.auditor.FPCheckPipeline")
    @patch("analysis.auditor.partition")
    @patch("analysis.auditor.load_card_index")
    def test_hypothesis_persistence(self, mock_cards, mock_partition, mock_fp, mock_llm):
        """Confirmed findings are persisted to the HypothesisStore."""
        from analysis.scope_partitioner import ScopeChunk

        mock_cards.return_value = ({}, {})
        chunk = ScopeChunk(
            chunk_id="chunk_0",
            node_ids=["node_1"],
            card_ids=[],
            cross_edges=[],
            estimated_tokens=500,
            priority=1.0,
        )
        mock_partition.return_value = [chunk]

        fp_instance = MagicMock()
        fp_instance.run.return_value = _make_verdict("confirmed", 0.95)
        mock_fp.return_value = fp_instance

        llm_instance = MagicMock()
        llm_instance.parse.side_effect = [
            CandidateFindingBatch(
                candidates=[_make_candidate()],
                scope_summary="analysis",
                surfaces_examined=["withdraw()"],
            ),
            CoverageDeclaration(
                surface_name="Vault",
                claimed_bounds=["checked"],
                expected_absent_findings=[],
                status="covered",
            ),
        ]
        mock_llm.return_value = llm_instance

        # Create a mock hypothesis store
        hyp_store = MagicMock()
        hyp_store.propose.return_value = (True, "hyp_test_123")

        auditor = SingleAuditor(
            config=_mock_config(),
            graphs_dir=self.graphs_dir,
            manifest_dir=self.manifest_dir,
            repo_root=Path(self.temp_dir),
            hypothesis_store=hyp_store,
        )
        result = auditor.audit(time_limit_minutes=5)

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].hypothesis_id, "hyp_test_123")
        hyp_store.propose.assert_called_once()

        # Verify the hypothesis object passed to propose
        hyp_arg = hyp_store.propose.call_args[0][0]
        self.assertEqual(hyp_arg.title, "Test Reentrancy in withdraw()")
        self.assertEqual(hyp_arg.severity, "high")
        self.assertIn("pipeline", hyp_arg.properties)
        self.assertEqual(hyp_arg.properties["pipeline"], "single_auditor")

    @patch("analysis.auditor.SingleAuditor._get_llm")
    @patch("analysis.auditor.FPCheckPipeline")
    @patch("analysis.auditor.partition")
    @patch("analysis.auditor.load_card_index")
    def test_redis_publisher_integration(self, mock_cards, mock_partition, mock_fp, mock_llm):
        """Progress and findings are published via RedisPublisher."""
        from analysis.scope_partitioner import ScopeChunk

        mock_cards.return_value = ({}, {})
        mock_partition.return_value = [ScopeChunk(
            chunk_id="c0", node_ids=["n1"], card_ids=[],
            cross_edges=[], estimated_tokens=500, priority=1.0,
        )]

        fp_instance = MagicMock()
        fp_instance.run.return_value = _make_verdict("confirmed", 0.9)
        mock_fp.return_value = fp_instance

        llm_instance = MagicMock()
        llm_instance.parse.side_effect = [
            CandidateFindingBatch(
                candidates=[_make_candidate()],
                scope_summary="s",
                surfaces_examined=["f"],
            ),
            CoverageDeclaration(
                surface_name="V", claimed_bounds=["x"],
                expected_absent_findings=[], status="covered",
            ),
        ]
        mock_llm.return_value = llm_instance

        publisher = MagicMock()

        auditor = SingleAuditor(
            config=_mock_config(),
            graphs_dir=self.graphs_dir,
            manifest_dir=self.manifest_dir,
            repo_root=Path(self.temp_dir),
            redis_publisher=publisher,
        )
        auditor.audit(time_limit_minutes=5)

        # Should publish status at least twice (running + completed)
        status_calls = [c for c in publisher.publish_status.call_args_list]
        self.assertGreaterEqual(len(status_calls), 2)

        # Should publish hypothesis once (one confirmed finding)
        publisher.publish_hypothesis.assert_called_once()


class TestCoverageRetry(unittest.TestCase):
    """Test that needs_more_investigation triggers a retry."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.graphs_dir = Path(self.temp_dir) / "graphs"
        self.manifest_dir = Path(self.temp_dir) / "manifest"
        self.graphs_dir.mkdir()
        self.manifest_dir.mkdir()
        (self.graphs_dir / "knowledge_graphs.json").write_text(
            json.dumps({"graphs": {}})
        )
        (self.manifest_dir / "files.json").write_text("[]")

        # Force fallback mode
        self._cli_patch = patch("analysis.auditor.ClaudeSession.available", return_value=False)
        self._cli_patch.start()

    def tearDown(self):
        self._cli_patch.stop()
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("analysis.auditor.SingleAuditor._get_llm")
    @patch("analysis.auditor.FPCheckPipeline")
    @patch("analysis.auditor.partition")
    @patch("analysis.auditor.load_card_index")
    def test_coverage_retry_on_needs_more(self, mock_cards, mock_partition, mock_fp, mock_llm):
        """When coverage says needs_more_investigation, the chunk is retried."""
        from analysis.scope_partitioner import ScopeChunk

        mock_cards.return_value = ({}, {})
        mock_partition.return_value = [ScopeChunk(
            chunk_id="c0", node_ids=["n1"], card_ids=[],
            cross_edges=[], estimated_tokens=500, priority=1.0,
        )]

        fp_instance = MagicMock()
        fp_instance.run.return_value = _make_verdict("rejected", 0.2)
        mock_fp.return_value = fp_instance

        # Coverage: first call needs_more, second call covered
        call_count = {"candidates": 0, "coverage": 0}

        def parse_side_effect(system, user, schema):
            if schema is CandidateFindingBatch:
                call_count["candidates"] += 1
                return CandidateFindingBatch(
                    candidates=[_make_candidate()] if call_count["candidates"] <= 2 else [],
                    scope_summary="s",
                    surfaces_examined=["f"],
                )
            elif schema is CoverageDeclaration:
                call_count["coverage"] += 1
                if call_count["coverage"] == 1:
                    return CoverageDeclaration(
                        surface_name="V",
                        claimed_bounds=["partial check"],
                        expected_absent_findings=["flash loan"],
                        unchecked_surfaces=["liquidation"],
                        status="needs_more_investigation",
                    )
                return CoverageDeclaration(
                    surface_name="V",
                    claimed_bounds=["full check"],
                    expected_absent_findings=[],
                    status="covered",
                )
            return MagicMock()

        llm_instance = MagicMock()
        llm_instance.parse.side_effect = parse_side_effect
        mock_llm.return_value = llm_instance

        auditor = SingleAuditor(
            config=_mock_config(),
            graphs_dir=self.graphs_dir,
            manifest_dir=self.manifest_dir,
            repo_root=Path(self.temp_dir),
        )
        result = auditor.audit(time_limit_minutes=5, max_coverage_retries=1)

        # Should have called candidates at least twice (first pass + retry)
        self.assertGreaterEqual(call_count["candidates"], 2)
        # Should have called coverage at least twice
        self.assertGreaterEqual(call_count["coverage"], 2)
        # Verify chunks were processed
        self.assertEqual(result.chunks_processed, 1)


class TestClaudeCliIntegration(unittest.TestCase):
    """Test Claude CLI path with mocked subprocess."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.graphs_dir = Path(self.temp_dir) / "graphs"
        self.manifest_dir = Path(self.temp_dir) / "manifest"
        self.graphs_dir.mkdir()
        self.manifest_dir.mkdir()

        graph_data = {
            "nodes": [
                {"id": "node_1", "label": "Vault", "type": "contract",
                 "source_files": ["contracts/Vault.sol"]},
            ],
            "edges": [],
        }
        (self.graphs_dir / "graph_system.json").write_text(json.dumps(graph_data))
        (self.graphs_dir / "knowledge_graphs.json").write_text(
            json.dumps({"graphs": {}})
        )
        (self.manifest_dir / "files.json").write_text("[]")

        # Force CLI mode
        self._cli_patch = patch("analysis.auditor.ClaudeSession.available", return_value=True)
        self._cli_patch.start()

    def tearDown(self):
        self._cli_patch.stop()
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("analysis.auditor.ClaudeSession.run")
    @patch("analysis.auditor.FPCheckPipeline")
    @patch("analysis.auditor.partition")
    @patch("analysis.auditor.load_card_index")
    def test_cli_extraction(self, mock_cards, mock_partition, mock_fp, mock_run):
        """Claude CLI extraction parses CandidateFindingBatch from JSON output."""
        from analysis.scope_partitioner import ScopeChunk

        mock_cards.return_value = ({}, {})
        chunk = ScopeChunk(
            chunk_id="c0", node_ids=["node_1"], card_ids=[],
            cross_edges=[], estimated_tokens=500, priority=1.0,
        )
        mock_partition.return_value = [chunk]

        # Mock CLI to return structured findings
        finding_batch = {
            "candidates": [{
                "title": "Reentrancy in withdraw()",
                "description": "External call before state update",
                "vulnerability_type": "reentrancy",
                "severity": "high",
                "confidence": 0.9,
                "file_line_evidence": [{
                    "relpath": "contracts/Vault.sol",
                    "line_start": 42,
                    "line_end": 55,
                    "snippet": "msg.sender.call{value: amount}('');"
                }],
                "reasoning": "External call precedes balance update",
                "numeric_gap_measurement": "100% drainable",
            }],
            "scope_summary": "Vault audit",
            "surfaces_examined": ["withdraw()"],
        }
        mock_run.return_value = ClaudeResult(
            text=f"```json\n{json.dumps(finding_batch)}\n```",
            cost_usd=0.05,
            num_turns=8,
        )

        # Mock fp-check
        fp_instance = MagicMock()
        fp_instance.run.return_value = _make_verdict("confirmed", 0.92)
        mock_fp.return_value = fp_instance

        auditor = SingleAuditor(
            config=_mock_config(),
            graphs_dir=self.graphs_dir,
            manifest_dir=self.manifest_dir,
            repo_root=Path(self.temp_dir),
        )
        result = auditor.audit(time_limit_minutes=5)

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].candidate.title, "Reentrancy in withdraw()")
        # Verify CLI was called (via the mock)
        mock_run.assert_called()

    @patch("analysis.auditor.ClaudeSession.run")
    @patch("analysis.auditor.FPCheckPipeline")
    @patch("analysis.auditor.partition")
    @patch("analysis.auditor.load_card_index")
    def test_cli_error_returns_empty(self, mock_cards, mock_partition, mock_fp, mock_run):
        """When Claude CLI returns an error, extraction produces no candidates."""
        from analysis.scope_partitioner import ScopeChunk

        mock_cards.return_value = ({}, {})
        mock_partition.return_value = [ScopeChunk(
            chunk_id="c0", node_ids=["node_1"], card_ids=[],
            cross_edges=[], estimated_tokens=500, priority=1.0,
        )]

        mock_run.return_value = ClaudeResult(text="", is_error=True)
        fp_instance = MagicMock()
        mock_fp.return_value = fp_instance

        auditor = SingleAuditor(
            config=_mock_config(),
            graphs_dir=self.graphs_dir,
            manifest_dir=self.manifest_dir,
            repo_root=Path(self.temp_dir),
        )
        result = auditor.audit(time_limit_minutes=5)

        self.assertEqual(len(result.findings), 0)
        self.assertEqual(len(result.rejected), 0)


class TestClaudeResult(unittest.TestCase):
    """Test ClaudeResult JSON extraction."""

    def test_extract_json_fenced(self):
        result = ClaudeResult(text='Some text\n```json\n{"key": "value"}\n```\nMore text')
        data = result.extract_json()
        self.assertEqual(data, {"key": "value"})

    def test_extract_json_bare(self):
        result = ClaudeResult(text='{"key": "value"}')
        data = result.extract_json()
        self.assertEqual(data, {"key": "value"})

    def test_extract_json_with_preamble(self):
        result = ClaudeResult(text='Here is the result:\n{"key": "value"}')
        data = result.extract_json()
        self.assertEqual(data, {"key": "value"})

    def test_extract_json_invalid(self):
        result = ClaudeResult(text="not json at all")
        data = result.extract_json()
        self.assertIsNone(data)

    def test_oversized_text_is_truncated(self):
        # 6 MiB of text exceeds the 4 MiB cap and should be truncated by
        # __post_init__ before any caller attempts to parse it.
        from analysis.claude_cli import _MAX_JSON_BYTES
        big = "x" * (_MAX_JSON_BYTES + 1024)
        result = ClaudeResult(text=big)
        self.assertEqual(len(result.text), _MAX_JSON_BYTES)


class TestClaudeCliScrub(unittest.TestCase):
    """Test secret scrubbing applied to logged stderr."""

    def test_scrub_strips_anthropic_key(self):
        from analysis.claude_cli import _scrub
        msg = "Error: invalid key sk-ant-api03-AAAAAAAAAAAAAAAAAAAA"
        out = _scrub(msg)
        self.assertNotIn("sk-ant-api03", out)
        self.assertIn("<redacted>", out)

    def test_scrub_strips_github_pat(self):
        from analysis.claude_cli import _scrub
        out = _scrub("auth failed: ghp_AAAAAAAAAAAAAAAAAAAAAAAA")
        self.assertNotIn("ghp_AAAA", out)
        self.assertIn("<redacted>", out)


class TestClaudeSession(unittest.TestCase):
    """Test ClaudeSession command building and output parsing."""

    def test_available_returns_false_when_no_cli(self):
        with patch("shutil.which", return_value=None):
            self.assertFalse(ClaudeSession.available())

    def test_available_returns_true_when_cli_exists(self):
        with patch("shutil.which", return_value="/usr/local/bin/claude"):
            self.assertTrue(ClaudeSession.available())

    def test_build_command_default(self):
        session = ClaudeSession(
            config={"models": {"auditor": {"model": "claude-sonnet-4-20250514"}}},
            working_dir=Path("/tmp/test"),
        )
        cmd = session._build_command(
            system_prompt="Test system",
            max_turns=10,
            output_json=True,
        )
        self.assertIn("-p", cmd)
        self.assertIn("--model", cmd)
        self.assertIn("claude-sonnet-4-20250514", cmd)
        self.assertIn("--max-turns", cmd)
        self.assertIn("10", cmd)
        self.assertIn("--output-format", cmd)
        self.assertIn("json", cmd)
        self.assertIn("--dangerously-skip-permissions", cmd)
        self.assertIn("--system-prompt", cmd)

    def test_parse_output_json(self):
        stdout = json.dumps({
            "result": "Found a reentrancy bug",
            "cost_usd": 0.05,
            "num_turns": 8,
            "duration_ms": 15000,
            "session_id": "abc123",
            "is_error": False,
        })
        result = ClaudeSession._parse_output(stdout, "", 0, output_json=True)
        self.assertEqual(result.text, "Found a reentrancy bug")
        self.assertEqual(result.cost_usd, 0.05)
        self.assertEqual(result.num_turns, 8)
        self.assertFalse(result.is_error)

    def test_parse_output_plain(self):
        result = ClaudeSession._parse_output("plain text", "", 0, output_json=False)
        self.assertEqual(result.text, "plain text")
        self.assertFalse(result.is_error)


class TestParseCandidates(unittest.TestCase):
    """Test _parse_candidates_from_result with various payloads."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.graphs_dir = Path(self.temp_dir) / "graphs"
        self.graphs_dir.mkdir()
        self.manifest_dir = Path(self.temp_dir) / "manifest"
        self.manifest_dir.mkdir()

    def _make_auditor(self):
        from analysis.scope_partitioner import ScopeChunk
        return SingleAuditor(
            config=_mock_config(),
            graphs_dir=self.graphs_dir,
            manifest_dir=self.manifest_dir,
            repo_root=Path(self.temp_dir),
        ), ScopeChunk(
            chunk_id="c0", node_ids=[], card_ids=[],
            cross_edges=[], estimated_tokens=500, priority=1.0,
        )

    def test_valid_batch_json(self):
        """A clean CandidateFindingBatch JSON returns candidates."""
        candidate = _make_candidate()
        batch_json = CandidateFindingBatch(
            candidates=[candidate], scope_summary="test"
        ).model_dump_json()
        result = ClaudeResult(text=f"```json\n{batch_json}\n```")
        auditor, chunk = self._make_auditor()
        candidates = auditor._parse_candidates_from_result(result, chunk, max_candidates=5)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].title, candidate.title)

    def test_no_json_returns_empty(self):
        """Plain text with no JSON returns empty list."""
        result = ClaudeResult(text="No vulnerabilities found in this chunk.")
        auditor, chunk = self._make_auditor()
        candidates = auditor._parse_candidates_from_result(result, chunk, max_candidates=5)
        self.assertEqual(candidates, [])

    def test_partial_candidates_skips_malformed(self):
        """When batch validation fails, individual candidates are tried."""
        good = _make_candidate().model_dump()
        bad = {"title": "missing fields"}
        data = {"candidates": [good, bad]}
        ClaudeResult(text=json.dumps(data))
        auditor, chunk = self._make_auditor()
        # Force batch validation to fail by corrupting a field
        data_corrupt = {"candidates": [good, bad], "extra_field_that_breaks_nothing": True}
        result2 = ClaudeResult(text=json.dumps(data_corrupt))
        candidates = auditor._parse_candidates_from_result(result2, chunk, max_candidates=5)
        # At least the good candidate should parse
        self.assertGreaterEqual(len(candidates), 1)

    def test_max_candidates_respected(self):
        """Only max_candidates are returned."""
        batch = CandidateFindingBatch(
            candidates=[_make_candidate(title=f"Finding {i}") for i in range(5)],
            scope_summary="test",
        )
        result = ClaudeResult(text=batch.model_dump_json())
        auditor, chunk = self._make_auditor()
        candidates = auditor._parse_candidates_from_result(result, chunk, max_candidates=2)
        self.assertEqual(len(candidates), 2)


class TestDeclareCoverageFallback(unittest.TestCase):
    """Test _declare_coverage API fallback paths."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.graphs_dir = Path(self.temp_dir) / "graphs"
        self.graphs_dir.mkdir()
        self.manifest_dir = Path(self.temp_dir) / "manifest"
        self.manifest_dir.mkdir()

    @patch("analysis.auditor.ClaudeSession.run")
    @patch("analysis.auditor.UnifiedLLMClient")
    def test_cli_error_falls_back_to_api(self, MockLLM, mock_run):
        """When CLI coverage fails, it falls through to API."""
        from analysis.scope_partitioner import ScopeChunk

        mock_run.return_value = ClaudeResult(text="", is_error=True)

        expected_cov = CoverageDeclaration(
            surface_name="c0",
            claimed_bounds=["95% of nodes touched"],
            expected_absent_findings=[],
            unchecked_surfaces=[],
            status="covered",
        )
        mock_llm = MockLLM.return_value
        mock_llm.parse.return_value = expected_cov

        auditor = SingleAuditor(
            config=_mock_config(),
            graphs_dir=self.graphs_dir,
            manifest_dir=self.manifest_dir,
            repo_root=Path(self.temp_dir),
        )
        chunk = ScopeChunk(
            chunk_id="c0", node_ids=["n1"], card_ids=[],
            cross_edges=[], estimated_tokens=500, priority=1.0,
        )
        audit_result = AuditResult()
        decl = auditor._declare_coverage(chunk, audit_result, "source code")
        # Should have fallen through to the LLM parse call
        if decl is not None:
            self.assertEqual(decl.surface_name, "c0")

    @patch("analysis.auditor.ClaudeSession.run")
    @patch("analysis.auditor.UnifiedLLMClient")
    def test_both_fail_returns_none(self, MockLLM, mock_run):
        """When both CLI and API fail, returns None."""
        mock_run.return_value = ClaudeResult(text="", is_error=True)
        mock_llm = MockLLM.return_value
        mock_llm.parse.side_effect = RuntimeError("API down")

        auditor = SingleAuditor(
            config=_mock_config(),
            graphs_dir=self.graphs_dir,
            manifest_dir=self.manifest_dir,
            repo_root=Path(self.temp_dir),
        )
        from analysis.scope_partitioner import ScopeChunk
        chunk = ScopeChunk(
            chunk_id="c0", node_ids=["n1"], card_ids=[],
            cross_edges=[], estimated_tokens=500, priority=1.0,
        )
        audit_result = AuditResult()
        decl = auditor._declare_coverage(chunk, audit_result, "source code")
        self.assertIsNone(decl)


if __name__ == "__main__":
    unittest.main()
