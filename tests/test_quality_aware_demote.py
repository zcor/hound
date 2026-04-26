"""
Tests for firepan-e5x — quality-aware dedup / template-spam demotion.

Covers:
- _quality_aware_demote: meta-pattern detection across survivors
- threshold semantics: >30% share + min sample 5
- demotion caps confidence at the documented ceiling, never raises
- stats dict shape matches what gets stamped into deep_audit_overview
"""

from __future__ import annotations

from worker.tasks import (
    _E5X_DEMOTED_CONFIDENCE_CEILING,
    _E5X_MIN_SAMPLE,
    _E5X_TEMPLATE_SHARE_THRESHOLD,
    _quality_aware_demote,
)


def _hyp(title: str, confidence: float = 0.9, hyp_id: str | None = None) -> dict:
    return {
        "id": hyp_id or title.replace(" ", "_").lower(),
        "title": title,
        "description": "",
        "confidence": confidence,
        "severity": "high",
    }


class TestBelowMinSample:
    def test_tiny_audit_skipped(self):
        """Audits with fewer than _E5X_MIN_SAMPLE survivors are not touched."""
        hyps = [_hyp(f"Missing access control on Foo.set{i}") for i in range(_E5X_MIN_SAMPLE - 1)]
        kept, stats = _quality_aware_demote(hyps)
        assert stats["skipped_reason"] == "below_min_sample"
        assert stats["demoted"] == []
        # Confidence untouched
        for h in kept:
            assert h["confidence"] == 0.9

    def test_empty_list(self):
        kept, stats = _quality_aware_demote([])
        assert kept == []
        assert stats["skipped_reason"] == "below_min_sample"


class TestThresholdBoundary:
    def test_exactly_at_threshold_not_demoted(self):
        """At exactly 30% share the demote MUST NOT fire (strict >)."""
        # 3 AC out of 10 = 30% — should NOT trigger.
        hyps = [_hyp(f"Missing access control on Foo.set{i}") for i in range(3)]
        hyps += [_hyp(f"Reentrancy in withdraw_{i}") for i in range(7)]
        kept, stats = _quality_aware_demote(hyps)
        assert stats["templates_triggered"] == []
        assert stats["demoted"] == []
        for h in kept:
            assert h["confidence"] == 0.9

    def test_just_above_threshold_demoted(self):
        """At 4/10 = 40% the demote fires."""
        hyps = [_hyp(f"Missing access control on Foo.set{i}") for i in range(4)]
        hyps += [_hyp(f"Reentrancy in withdraw_{i}") for i in range(6)]
        kept, stats = _quality_aware_demote(hyps)
        assert len(stats["templates_triggered"]) == 1
        triggered = stats["templates_triggered"][0]
        assert triggered["template"] == "access_control"
        assert triggered["matching"] == 4
        assert triggered["total"] == 10
        assert triggered["share"] > _E5X_TEMPLATE_SHARE_THRESHOLD

        # Only the 4 AC rows demoted; reentrancy untouched.
        ac_rows = [h for h in kept if "access control" in h["title"].lower()]
        re_rows = [h for h in kept if "reentrancy" in h["title"].lower()]
        assert all(h["confidence"] == _E5X_DEMOTED_CONFIDENCE_CEILING for h in ac_rows)
        assert all(h["confidence"] == 0.9 for h in re_rows)
        assert len(stats["demoted"]) == 4


class TestNeverRaiseConfidence:
    def test_low_confidence_rows_untouched(self):
        """Demote caps confidence — it never raises a low-confidence row UP
        to the ceiling. (Otherwise we'd promote spam, not demote it.)
        """
        # 6 AC rows, 5 already low-confidence (0.2). 6/10 = 60%, triggers.
        # The 5 low-confidence rows should stay low; only the 1 high-confidence
        # AC row gets capped at the ceiling.
        low_ac = [_hyp(f"Missing access control on A.s{i}", confidence=0.2,
                       hyp_id=f"low_ac_{i}") for i in range(5)]
        high_ac = [_hyp("Missing access control on B.set", confidence=0.95,
                        hyp_id="high_ac")]
        other = [_hyp(f"Overflow in calc_{i}") for i in range(4)]
        hyps = low_ac + high_ac + other

        kept, stats = _quality_aware_demote(hyps)
        # 6/10 = 60% AC > 30% → triggered
        assert len(stats["templates_triggered"]) == 1

        kept_by_id = {h["id"]: h for h in kept}
        # Low-confidence AC rows untouched
        for i in range(5):
            assert kept_by_id[f"low_ac_{i}"]["confidence"] == 0.2
        # High-confidence AC row capped at ceiling
        assert kept_by_id["high_ac"]["confidence"] == _E5X_DEMOTED_CONFIDENCE_CEILING
        # Only 1 demoted (the high-confidence one)
        assert len(stats["demoted"]) == 1
        assert stats["demoted"][0]["hypothesis_id"] == "high_ac"
        assert stats["demoted"][0]["original_confidence"] == 0.95


class TestNonAccessControlSpam:
    def test_only_known_templates_count(self):
        """A storm of non-template findings (e.g. 100% reentrancy) does NOT
        trigger demote — we only have a regex for access-control today.
        Documents the intentional scope: e5x mitigates known FP shapes; new
        shapes need a new template added to _E5X_TEMPLATES.
        """
        hyps = [_hyp(f"Reentrancy in withdraw_{i}") for i in range(10)]
        kept, stats = _quality_aware_demote(hyps)
        assert stats["templates_triggered"] == []
        assert stats["demoted"] == []
        for h in kept:
            assert h["confidence"] == 0.9


class TestStatsShape:
    def test_stats_shape_for_overview_stamp(self):
        """The stats dict shape must match what the worker stamps onto
        deep_audit_overview['template_demote'] — keys: checked, demoted (list),
        skipped_reason, templates_triggered (list).
        """
        hyps = [_hyp(f"Missing access control on Foo.set{i}") for i in range(6)]
        hyps += [_hyp(f"Other_{i}") for i in range(4)]
        _, stats = _quality_aware_demote(hyps)
        assert set(stats.keys()) == {
            "checked", "demoted", "skipped_reason", "templates_triggered"
        }
        assert isinstance(stats["demoted"], list)
        assert isinstance(stats["templates_triggered"], list)
        assert stats["checked"] == 10

    def test_demoted_entry_has_required_fields(self):
        hyps = [_hyp(f"Missing access control on Foo.set{i}") for i in range(6)]
        hyps += [_hyp(f"Other_{i}") for i in range(4)]
        _, stats = _quality_aware_demote(hyps)
        assert stats["demoted"], "expected demotions"
        for entry in stats["demoted"]:
            assert set(entry.keys()) == {
                "hypothesis_id", "title", "template",
                "original_confidence", "new_confidence",
            }
            assert entry["template"] == "access_control"
            assert entry["new_confidence"] == _E5X_DEMOTED_CONFIDENCE_CEILING
            assert entry["original_confidence"] >= entry["new_confidence"]


class TestYieldnestReplay:
    def test_yieldnest_shape_demotes_storm(self):
        """Replay the postmortem shape: 11 AC FPs + 2 real findings, all at
        confidence 0.9. e5x demotes the 11 to ceiling so they can't reach
        confirmed status (>=0.8) without per-row 8kv vouching them up — but
        the 2 real findings are untouched.
        """
        ac_storm = [
            _hyp(f"Missing access control on FeeHooks.setX{i}",
                 hyp_id=f"yn_{i}")
            for i in range(11)
        ]
        real = [
            _hyp("Reentrancy in withdraw", hyp_id="real_re"),
            _hyp("Integer overflow in calc", hyp_id="real_of"),
        ]
        hyps = ac_storm + real

        kept, stats = _quality_aware_demote(hyps)
        # 11/13 = 84.6% → triggered
        assert len(stats["templates_triggered"]) == 1
        assert stats["templates_triggered"][0]["matching"] == 11
        assert len(stats["demoted"]) == 11

        kept_by_id = {h["id"]: h for h in kept}
        # All 11 AC storm rows demoted to ceiling
        for i in range(11):
            assert kept_by_id[f"yn_{i}"]["confidence"] == _E5X_DEMOTED_CONFIDENCE_CEILING
        # Real findings untouched
        assert kept_by_id["real_re"]["confidence"] == 0.9
        assert kept_by_id["real_of"]["confidence"] == 0.9
