"""firepan-tw7: CurationReport dataclass + markdown summary.

This is the artifact users care about — it's the answer to "did our PRs
help?" expressed in numbers.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date


@dataclass
class StageResult:
    """One stage of the curation pipeline."""

    name: str
    input_count: int
    output_count: int
    fps_dropped_or_demoted: int  # of EXPECTED_FPs at this stage's input
    tps_dropped_or_demoted: int  # of non-FPs at this stage's input (oops counter)
    raw_stats: dict = field(default_factory=dict)


@dataclass
class CurationReport:
    """End-to-end replay summary for one corpus + one pipeline configuration."""

    corpus_name: str
    input_count: int
    expected_fp_count: int
    stages: list[StageResult] = field(default_factory=list)
    confabulation_flagged: bool = False
    confabulation_reason: str | None = None
    skipped_gates: list[str] = field(default_factory=list)

    @property
    def fps_correctly_filtered(self) -> int:
        """Total FPs caught by any stage. Dedupes by hypothesis_id implicitly:
        once a row is filtered, downstream stages can't catch it again, so
        the per-stage FP counts already partition cleanly.
        """
        return sum(s.fps_dropped_or_demoted for s in self.stages)

    @property
    def tps_incorrectly_filtered(self) -> int:
        """Total true-positives mistakenly dropped/demoted across all stages."""
        return sum(s.tps_dropped_or_demoted for s in self.stages)

    @property
    def fp_filter_rate(self) -> float:
        """Headline metric. `0.0` if there are no labeled FPs in the corpus."""
        if self.expected_fp_count == 0:
            return 0.0
        return self.fps_correctly_filtered / self.expected_fp_count

    def summary(self) -> str:
        """Render a markdown report. Stable shape — used both by the CLI and
        by the postmortem record archive.
        """
        lines: list[str] = [
            f"## Eval Replay — {self.corpus_name} — {date.today().isoformat()}",
            "",
            f"**Input**: {self.input_count} hypotheses "
            f"({self.expected_fp_count} expected FPs)",
            "",
            "| Stage | Input | Output | FPs caught | TPs lost | Skipped |",
            "|-------|------:|-------:|-----------:|---------:|---------|",
        ]
        for s in self.stages:
            skipped_note = s.raw_stats.get("skipped_reason") or ""
            lines.append(
                f"| `{s.name}` | {s.input_count} | {s.output_count} | "
                f"{s.fps_dropped_or_demoted} | {s.tps_dropped_or_demoted} | {skipped_note} |"
            )

        lines += [
            "",
            "### Headline",
            "",
            f"- **FPs correctly filtered**: {self.fps_correctly_filtered}/"
            f"{self.expected_fp_count}"
            + (
                f" ({self.fp_filter_rate * 100:.1f}%)"
                if self.expected_fp_count
                else ""
            ),
            f"- **TPs incorrectly filtered**: {self.tps_incorrectly_filtered}",
            f"- **Confabulation flag**: {self.confabulation_flagged}"
            + (f" — {self.confabulation_reason}" if self.confabulation_reason else ""),
        ]
        if self.skipped_gates:
            lines += [
                f"- **Skipped gates**: {', '.join(self.skipped_gates)}",
            ]
        lines.append("")
        return "\n".join(lines)
