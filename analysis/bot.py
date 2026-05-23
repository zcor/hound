"""Buffer-of-Thought — cross-session structured memory for audits.

Cherry-pick of LLM-SmartAudit (Wei et al, IEEE TSE Oct 2025) §III-B.
Their ablation showed −8.2% F1 when BoT was removed. We adopt it as a
*per-project* JSON file that audits read at start and append to at end,
so the next audit inherits accumulated knowledge instead of relearning.

Storage layout
==============

One file per project: ``<project_dir>/.bot.json``. Schema:

.. code-block:: json

    {
      "version": 1,
      "project_id": 5,
      "audit_sessions": [
        {
          "session_id": "audit_xxx",
          "started_at": "...",
          "completed_at": "...",
          "mode": "auditor",
          "model": "claude-opus-4-7",
          "coverage_ratio": 1.0,
          "summary": {"raw": 16, "in_scope_high": 0, "low": 4, "...": "..."}
        }
      ],
      "findings_history": {
        "hyp_e62d06f215ad": {
          "first_seen": "session_xxx",
          "title": "Division by zero in FxLowVolatilityMath...",
          "location": "contracts/f(x)/math/FxLowVolatilityMath.sol:75-76",
          "verdicts": [
            {"session_id": "audit_xxx", "method": "curator_rule4",
             "verdict": "potential_fail_safe", "evidence": "..."},
            {"session_id": "audit_yyy", "method": "mve_loop",
             "verdict": "mve_unverified",
             "evidence": "panic 0x12; attacker_delta=0"}
          ]
        }
      },
      "patterns_observed": {
        "fail_safe_revert": {
          "count": 4,
          "first_seen": "audit_xxx",
          "confirmed_by": ["reviewer:source_verification",
                           "curator:Rule_4", "mve_loop:0x12_panic"]
        }
      },
      "scope_decisions": {
        "in_scope": ["contracts/f(x)/v1/*", "..."],
        "out_of_scope": {"v2": "not deployed", "concentrator": "..."}
      },
      "trust_model": {
        "onlyOwner": "2-of-3 Fireblocks multisig",
        "onlyStrategy": "owner-set"
      }
    }

The BoT is queried on audit start (threaded into the investigation_prompt)
and on verify start (consulted for "what other methods have concluded
about this finding"). It's written by the curator + verify summary
hooks.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_SCHEMA_VERSION = 1


@dataclass
class FindingVerdict:
    """One verdict for a finding, tagged by method + session."""

    session_id: str
    method: str  # 'curator_rule3', 'curator_rule4', 'mve_loop', 'reviewer', ...
    verdict: str  # 'verified' | 'mve_unverified' | 'admin_trust' | 'fail_safe' | ...
    evidence: str = ""
    recorded_at: str = ""


@dataclass
class FindingHistory:
    """All verdicts ever recorded for a single hypothesis_id."""

    hypothesis_id: str
    first_seen: str  # session_id
    title: str
    location: str
    verdicts: list[FindingVerdict] = field(default_factory=list)

    def add_verdict(self, v: FindingVerdict) -> None:
        self.verdicts.append(v)

    @property
    def consensus(self) -> str:
        """Compute the consensus verdict across all recorded methods.

        Three or more agreeing methods → strong consensus; two → tentative;
        otherwise → unresolved. Returns the consensus string + count.
        """
        if not self.verdicts:
            return "unresolved (0 verdicts)"
        from collections import Counter
        tally = Counter(v.verdict for v in self.verdicts)
        top, top_count = tally.most_common(1)[0]
        if top_count >= 3:
            return f"strong:{top} ({top_count}/{len(self.verdicts)})"
        if top_count >= 2:
            return f"tentative:{top} ({top_count}/{len(self.verdicts)})"
        return f"unresolved (1/{len(self.verdicts)})"


@dataclass
class AuditSessionRecord:
    """One audit session — minimal summary for BoT."""

    session_id: str
    started_at: str
    completed_at: str = ""
    mode: str = ""  # 'auditor' | 'verify' | ...
    model: str = ""
    coverage_ratio: float | None = None
    summary: dict[str, Any] = field(default_factory=dict)


class BufferOfThought:
    """Per-project structured memory across audit sessions.

    Stored as JSON at ``project_dir / .bot.json``. Operations are
    append-mostly — sessions and verdicts accumulate, scope/trust
    state replaces the previous value.
    """

    def __init__(self, project_dir: Path):
        self.project_dir = Path(project_dir)
        self.path = self.project_dir / ".bot.json"
        self.data: dict[str, Any] = self._load()

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {
                "version": _SCHEMA_VERSION,
                "project_id": None,
                "audit_sessions": [],
                "findings_history": {},
                "patterns_observed": {},
                "scope_decisions": {},
                "trust_model": {},
            }
        try:
            return json.loads(self.path.read_text())
        except (OSError, json.JSONDecodeError):
            # Fail-open: never block an audit because of a corrupt BoT.
            return self._load_default()

    def _load_default(self) -> dict[str, Any]:
        return {
            "version": _SCHEMA_VERSION,
            "project_id": None,
            "audit_sessions": [],
            "findings_history": {},
            "patterns_observed": {},
            "scope_decisions": {},
            "trust_model": {},
        }

    def save(self) -> None:
        """Atomic-ish write. Best-effort — BoT corruption never blocks audits."""
        try:
            self.project_dir.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(self.data, indent=2, default=str))
            tmp.replace(self.path)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Read helpers — queried by audit / verify start hooks
    # ------------------------------------------------------------------

    def context_brief(self, max_chars: int = 3000) -> str:
        """Return a short markdown brief of the BoT for inclusion in the
        auditor's investigation_prompt. Prioritizes: scope decisions,
        trust model, known patterns, and the top-3 findings by verdict
        count."""
        lines: list[str] = []
        sd = self.data.get("scope_decisions") or {}
        if sd:
            lines.append("### Prior scope decisions")
            in_scope = sd.get("in_scope") or []
            if isinstance(in_scope, list) and in_scope:
                lines.append(f"- In scope: {', '.join(in_scope[:6])}")
            oos = sd.get("out_of_scope") or {}
            if isinstance(oos, dict) and oos:
                for k, v in list(oos.items())[:6]:
                    lines.append(f"- Out of scope: `{k}` — {v}")
            lines.append("")

        tm = self.data.get("trust_model") or {}
        if tm:
            lines.append("### Trust model (carried from prior audits)")
            for role, desc in list(tm.items())[:6]:
                lines.append(f"- `{role}`: {desc}")
            lines.append("")

        po = self.data.get("patterns_observed") or {}
        if po:
            lines.append("### Patterns observed in prior runs")
            for name, info in list(po.items())[:6]:
                count = info.get("count", 0)
                by = info.get("confirmed_by", [])
                lines.append(f"- **{name}**: seen {count}× "
                             f"(corroborated by {', '.join(by[:3])})")
            lines.append("")

        fh = self.data.get("findings_history") or {}
        if fh:
            lines.append("### Top-resolved findings (prior verdicts)")
            # Sort by number of verdicts (most-corroborated first)
            top = sorted(
                fh.items(),
                key=lambda kv: -len((kv[1].get("verdicts") or [])),
            )[:5]
            for hid, h in top:
                verdicts = h.get("verdicts") or []
                if not verdicts:
                    continue
                last = verdicts[-1]
                lines.append(
                    f"- `{hid}` ({h.get('location', '?')}): "
                    f"latest verdict = `{last.get('verdict')}` "
                    f"via {last.get('method')} "
                    f"(total methods: {len(verdicts)})"
                )
            lines.append("")

        brief = "\n".join(lines).strip()
        if len(brief) > max_chars:
            brief = brief[:max_chars] + "\n[... truncated ...]"
        return brief

    def lookup_finding(self, hypothesis_id: str) -> FindingHistory | None:
        raw = (self.data.get("findings_history") or {}).get(hypothesis_id)
        if not raw:
            return None
        verdicts = [
            FindingVerdict(**v) if isinstance(v, dict) else v
            for v in (raw.get("verdicts") or [])
        ]
        return FindingHistory(
            hypothesis_id=hypothesis_id,
            first_seen=raw.get("first_seen", ""),
            title=raw.get("title", ""),
            location=raw.get("location", ""),
            verdicts=verdicts,
        )

    # ------------------------------------------------------------------
    # Write helpers — called by curator / verify summary hooks
    # ------------------------------------------------------------------

    def record_session(self, record: AuditSessionRecord) -> None:
        sessions = self.data.setdefault("audit_sessions", [])
        # Upsert by session_id
        for i, s in enumerate(sessions):
            if s.get("session_id") == record.session_id:
                sessions[i] = asdict(record)
                self.save()
                return
        sessions.append(asdict(record))
        # Cap at 50 most-recent sessions — older audits are still
        # queryable via DB; BoT is for fast in-memory context.
        if len(sessions) > 50:
            self.data["audit_sessions"] = sessions[-50:]
        self.save()

    def record_verdict(
        self,
        hypothesis_id: str,
        title: str,
        location: str,
        session_id: str,
        method: str,
        verdict: str,
        evidence: str = "",
    ) -> None:
        """Append a verdict to a finding's history."""
        now = datetime.now(timezone.utc).isoformat()
        fh = self.data.setdefault("findings_history", {})
        if hypothesis_id not in fh:
            fh[hypothesis_id] = {
                "first_seen": session_id,
                "title": title,
                "location": location,
                "verdicts": [],
            }
        fh[hypothesis_id]["verdicts"].append({
            "session_id": session_id,
            "method": method,
            "verdict": verdict,
            "evidence": evidence,
            "recorded_at": now,
        })
        # Update title/location to the freshest values (auditors may
        # rephrase across runs).
        fh[hypothesis_id]["title"] = title or fh[hypothesis_id]["title"]
        fh[hypothesis_id]["location"] = location or fh[hypothesis_id]["location"]
        self.save()

    def increment_pattern(
        self,
        name: str,
        confirmed_by: str,
        session_id: str | None = None,
    ) -> None:
        """Record an observation of a known pattern."""
        po = self.data.setdefault("patterns_observed", {})
        if name not in po:
            po[name] = {
                "count": 0,
                "first_seen": session_id or "",
                "confirmed_by": [],
            }
        po[name]["count"] = int(po[name].get("count", 0)) + 1
        by = po[name].setdefault("confirmed_by", [])
        if confirmed_by not in by:
            by.append(confirmed_by)
        self.save()

    def set_scope_decisions(
        self,
        in_scope: list[str] | None = None,
        out_of_scope: dict[str, str] | None = None,
    ) -> None:
        sd = self.data.setdefault("scope_decisions", {})
        if in_scope is not None:
            sd["in_scope"] = list(in_scope)
        if out_of_scope:
            sd_oos = sd.setdefault("out_of_scope", {})
            sd_oos.update(out_of_scope)
        self.save()

    def set_trust_model(self, mapping: dict[str, str]) -> None:
        tm = self.data.setdefault("trust_model", {})
        tm.update(mapping)
        self.save()


__all__ = [
    "BufferOfThought",
    "FindingHistory",
    "FindingVerdict",
    "AuditSessionRecord",
]
