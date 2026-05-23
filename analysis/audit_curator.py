"""Audit curator — post-SingleAuditor pass that enforces scope, trust, and
design-constraint discipline on Claude's raw findings.

Without this, the auditor produces high-severity findings against:
  - files outside the declared scope (Claude follows cross-refs into v2/Aladdin/etc)
  - functions the client has confirmed are dead-by-design (e.g. fee subsystem
    on a fee-free permissioned CDP)
  - admin/owner trust surfaces (exploitation requires a privileged role that
    is in fact trusted by the engagement threat model)

These all need to be **either filtered or downgraded** before the report
is generated. The previous Round-1 engagement against the same client had
this happen manually as a human curation pass; this module bakes the
discipline into the pipeline so it can't be skipped silently.

Three rules, applied in order:

  1. SCOPE — finding's first node_ref file path must end with one of the
     declared scope_files. Otherwise: relabel as `out_of_scope`, severity
     floor `informational`.
  2. DEAD CODE — finding's file matches a `{file, function}` entry in
     dead_code_paths. Severity floor `informational`, labeled
     `design_constraint` with a "would be {orig} if active" note.
  3. TRUST BOUNDARY — evidence text matches a pattern showing exploitation
     requires only a trusted role (multisig owner, strategy contract).
     Severity capped at `low`, labeled `admin_trust_surface`.

Rules are non-cumulative: the first one that fires wins. Order matters:
out-of-scope findings short-circuit before we examine their content.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


@dataclass
class AuditContext:
    """Per-engagement audit context. Threaded in via Project.audit_context
    or the admin force-run payload's `audit_context` field.

    Attributes:
        scope_files: Repo-relative paths that are explicitly in scope. The
            curator does a *suffix* match against the finding's node_ref so
            relative/absolute confusion is forgiving.
        dead_code_paths: List of ``{"file": "...", "function": "..."}`` where
            ``function`` is optional (omit to mark the whole file as dead).
            Matched by suffix on file + case-insensitive substring on title.
        trusted_roles: Identifiers used in the contract's modifiers / docs
            that the engagement treats as trust assumptions. E.g.
            ``["onlyOwner", "onlyStrategy"]``. Used by the trust-boundary
            heuristic.
        deployed_contracts: Optional ``{name: address}`` mapping. Not used
            by the curator directly today; surfaced into the report for
            chain-of-custody.
        out_of_scope_action: "downgrade" (default — relabel + floor to
            informational) or "drop" (remove from the report entirely).
    """

    scope_files: list[str] = field(default_factory=list)
    dead_code_paths: list[dict[str, str]] = field(default_factory=list)
    trusted_roles: list[str] = field(default_factory=list)
    deployed_contracts: dict[str, str] = field(default_factory=dict)
    out_of_scope_action: str = "downgrade"
    # firepan-pr77 — Slither corroboration data + impact data for Rule 5.
    # slither_hits is a list of {"file": "...", "lines": [N, M], "check": "..."}
    # parsed from `slither <file> --json` output. When a curator finding's
    # location overlaps a slither hit, we get "corroborated" evidence.
    # finding_impacts maps hypothesis_id -> bounded USD impact (from
    # mode=verify Phase 5). Used by Rule 5 to override Rule 3 admin-trust
    # demotion when economic impact dominates the trust axis.
    slither_hits: list[dict[str, Any]] = field(default_factory=list)
    finding_impacts: dict[str, float] = field(default_factory=dict)
    # Threshold above which Rule 5 re-promotes admin-trust findings to
    # original severity. $1M default — admin-trust paths that can extract
    # >$1M warrant the original severity (e.g., assune-m35 H6c $99.5M).
    admin_trust_impact_threshold_usd: float = 1_000_000.0

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> "AuditContext":
        if not d:
            return cls()
        return cls(
            scope_files=list(d.get("scope_files") or []),
            dead_code_paths=list(d.get("dead_code_paths") or []),
            trusted_roles=list(d.get("trusted_roles") or []),
            deployed_contracts=dict(d.get("deployed_contracts") or {}),
            out_of_scope_action=str(d.get("out_of_scope_action") or "downgrade"),
            # firepan-pr77 — Slither corroboration + impact-bounded overrides
            slither_hits=list(d.get("slither_hits") or []),
            finding_impacts=dict(d.get("finding_impacts") or {}),
            admin_trust_impact_threshold_usd=float(
                d.get("admin_trust_impact_threshold_usd")
                or 1_000_000.0
            ),
        )


@dataclass
class CurationResult:
    """Outcome of curating a single finding."""

    hypothesis_id: str
    original_severity: str
    new_severity: str
    label: str | None = None  # 'out_of_scope' | 'design_constraint' | 'admin_trust_surface' | None
    reason: str | None = None
    drop: bool = False  # only set when out_of_scope_action='drop' and rule 1 fires

    @property
    def changed(self) -> bool:
        return self.new_severity != self.original_severity or self.label is not None or self.drop


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


_SEV_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _location_file(hypothesis: dict[str, Any]) -> str | None:
    """Best-effort extraction of the primary file path from a hypothesis."""
    nrefs = hypothesis.get("node_refs") or []
    if nrefs:
        # node_refs entries look like "contracts/foo/Bar.sol:123-145"
        first = nrefs[0]
        if isinstance(first, str):
            return first.split(":", 1)[0].strip()
    # Some pipelines stash it in properties.location_file
    props = hypothesis.get("properties") or {}
    return props.get("location_file") or props.get("file")


def _location_in_scope(path: str | None, scope_files: list[str]) -> bool:
    if not path or not scope_files:
        return False
    # Forgiving suffix match — handles abs vs rel, leading ./
    norm = path.lstrip("./")
    for s in scope_files:
        s_norm = s.lstrip("./")
        if norm == s_norm or norm.endswith("/" + s_norm) or s_norm.endswith("/" + norm):
            return True
        # Bare basename equivalence as a last resort
        if "/" not in s_norm and norm.endswith("/" + s_norm):
            return True
    return False


def _in_dead_code(
    path: str | None,
    title: str,
    description: str,
    dead_paths: list[dict[str, str]],
) -> dict[str, str] | None:
    if not path:
        return None
    text = (title or "") + " " + (description or "")
    for dp in dead_paths:
        dp_file = (dp.get("file") or "").lstrip("./")
        dp_func = (dp.get("function") or "").lower()
        if not dp_file:
            continue
        if not (path.endswith(dp_file) or path.endswith("/" + dp_file)):
            continue
        if not dp_func:
            return dp  # whole file marked dead
        if dp_func in text.lower():
            return dp
    return None


# Phrases that strongly suggest exploitation requires a privileged caller.
# We're conservative on purpose: better to leave a borderline finding alone
# than to silently downgrade real attacker-controlled bugs.
_TRUST_PATTERNS = [
    r"\bonly\s*owner\b",
    r"\bonly\s*strategy\b",
    r"\bonlyowner\b",
    r"\bonlystrategy\b",
    r"\b(compromised|malicious|rogue)\s+(owner|admin|strategy|multisig)\b",
    r"\bowner\s+can\b",
    r"\badmin\s+can\b",
    r"\bprivileged\s+(role|caller|account|address|setter)",
    r"\brequires?\s+owner\s+(access|privilege|action)",
    r"\b(only|requires?)\s+the\s+owner\b",
    r"\bset(?:s|table)?\s+by\s+(?:the\s+)?owner\b",
    # firepan-rule4 strategy-via-owner pattern — strategy contract is set by
    # onlyOwner so "malicious strategy" still requires owner action. The v4
    # RAAC audit's #3 (Strategy Balance Tracking) slipped past the trust rule
    # because the evidence said "strategy contract can …" without mentioning
    # onlyOwner; this catches that framing.
    r"\b(malicious|rogue|compromised)\s+strategy\s+(contract|address)\b",
    r"\bstrategy\s+contract\s+(can|could)\s+(manipulate|drain|transfer)\b",
    # firepan-rule4 function-name patterns — direct mention of an
    # onlyOwner/onlyStrategy-gated function is sufficient evidence of an
    # admin-trust surface. Any finding that says "the transferToStrategy
    # function does X" is implicitly about a function that requires the
    # strategy address, which is owner-set. v4's Strategy Balance Tracking
    # finding said exactly this and the curator missed it.
    r"\btransferToStrategy\b",
    r"\bnotifyStrategyProfit\b",
    r"\bupdateStrategy\b",
    r"\bupdatePriceOracle\b",
    r"\bupdateRateProvider\b",
    r"\bupdateBaseTokenCap\b",
    r"\bupdateEMASampleInterval\b",
]


# Rule 4 — fail-safe revert / unreachable-degenerate-state patterns. When a
# finding describes a math revert on a degenerate input (divide by zero,
# overflow on extreme value, etc.) without proving the degenerate state is
# reachable from a public entry point, the most likely truth is that an
# upstream guard short-circuits before the bad arithmetic line. Examples
# from RAAC v4 post-mortem:
#   - "div-by-zero when baseSupply==0" → Treasury.mint branches before calling
#     the math; the divisor is never zero on the reachable path
#   - "div-by-zero when NAV==0" → the math sits inside `if (_baseVal > _fVal)`
#     which proves the divisor is non-zero on that branch, AND the deployed
#     oracle reverts on degenerate readings, making the bad state unreachable
#     at runtime regardless
# These look like real bugs in isolation. They are not vulnerabilities. The
# curator conservatively flags this class for human review by floor-dropping
# severity two levels (Critical → Medium, High → Low, Medium → Informational).
_FAIL_SAFE_PATTERNS = [
    # explicit divide-by-zero phrasing
    r"\bdivision\s+by\s+zero\b",
    r"\bdiv(?:ide|ides|iding)?\s+by\s+zero\b",
    r"\bdiv(?:ides|iding)?\s+by\s+[a-z_]+\s+(?:when|if)\b.{0,40}\bzero\b",
    r"\b(?:zero|empty)\s+(?:supply|balance|value|nav)\s+(?:causes?|triggers?|allows?)\s+(?:dos|revert|panic|underflow|overflow)\b",
    # "X is zero" framing
    r"\bwhen\s+[a-z_]+\s+(?:is|==|equals|equal\s+to)\s+zero\b",
    r"\b(?:nav|supply|balance|value|amount|price)\s+(?:values?\s+)?(?:are|is)\s+zero\b",
    # generic DoS-via-revert phrasing
    r"\b(?:dos|denial[-\s]of[-\s]service)\s+(?:via|when|through)\s+(?:zero|empty|extreme|max|overflow|underflow)\b",
    # overflow/underflow on extreme value
    r"\b(?:arithmetic\s+)?overflow\s+(?:via|when)\s+extreme\s+(?:value|input)\b",
    r"\bunderflow\s+(?:via|when|due\s+to)\b",
    # explicit "reverts on" framings
    r"\breverts?\s+(?:on|when)\s+(?:zero|empty|degenerate)\b",
]


def _trust_boundary_match(
    evidence_text: str,
    trusted_roles: list[str],
) -> str | None:
    if not trusted_roles or not evidence_text:
        return None
    text = evidence_text.lower()
    for role in trusted_roles:
        if role.lower() in text:
            return role
    for pat in _TRUST_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            return "owner"
    return None


def _flatten_evidence(hypothesis: dict[str, Any]) -> str:
    """Build the text blob the trust-boundary heuristic scans."""
    parts: list[str] = [hypothesis.get("title", ""), hypothesis.get("description", "")]
    ev = hypothesis.get("evidence")
    if isinstance(ev, list):
        for item in ev:
            if isinstance(item, dict):
                parts.append(item.get("description", ""))
    elif isinstance(ev, dict):
        for item in ev.get("items", []) or []:
            if isinstance(item, dict):
                parts.append(item.get("description", ""))
    return " \n ".join(p for p in parts if p)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def curate_one(hypothesis: dict[str, Any], ctx: AuditContext) -> CurationResult:
    """Apply the three rules to a single hypothesis dict.

    The hypothesis dict is the structure persisted by HypothesisStore — see
    ``analysis.concurrent_knowledge.Hypothesis``. We accept dicts (not
    dataclasses) because the worker hands us already-serialized data after
    ``hyp_store.list_all()``.
    """
    hid = str(hypothesis.get("id") or "")
    orig_sev = str(hypothesis.get("severity") or "").lower() or "informational"
    title = hypothesis.get("title", "")
    desc = hypothesis.get("description", "")
    path = _location_file(hypothesis)

    # Rule 1 — scope. Short-circuits before content rules so OOS findings
    # never touch the dead-code / trust rules.
    if ctx.scope_files and not _location_in_scope(path, ctx.scope_files):
        if ctx.out_of_scope_action == "drop":
            return CurationResult(
                hid, orig_sev, orig_sev, label="out_of_scope",
                reason=f"location {path!r} not in scope_files; dropped per action='drop'",
                drop=True,
            )
        return CurationResult(
            hid, orig_sev, "informational", label="out_of_scope",
            reason=f"location {path!r} not in scope_files",
        )

    # Rule 2 — dead code by design.
    dead = _in_dead_code(path, title, desc, ctx.dead_code_paths)
    if dead:
        fn = dead.get("function") or "*"
        return CurationResult(
            hid, orig_sev, "informational", label="design_constraint",
            reason=f"function in client-confirmed inactive code path "
                   f"({dead.get('file')}::{fn}); would be {orig_sev.upper()} if active",
        )

    # Rule 3 — admin / owner trust boundary.
    role = _trust_boundary_match(_flatten_evidence(hypothesis), ctx.trusted_roles)
    if role and _SEV_RANK.get(orig_sev, 0) > _SEV_RANK["low"]:
        # firepan-pr77 Rule 5a — admin-trust-impact override. If the finding's
        # bounded USD impact exceeds the engagement threshold, admin-trust
        # demotion is overridden — the impact axis dominates the trust axis.
        # Closes assune-m35 (reviewer feedback: H6c at $99.5M was buried as Low).
        impact = ctx.finding_impacts.get(hid, 0.0) if ctx.finding_impacts else 0.0
        if impact >= ctx.admin_trust_impact_threshold_usd:
            return CurationResult(
                hid, orig_sev, orig_sev, label="admin_trust_high_impact",
                reason=(
                    f"requires {role!r} BUT bounded impact ${impact:,.0f} "
                    f">= ${ctx.admin_trust_impact_threshold_usd:,.0f} "
                    f"threshold; severity preserved (Rule 5a)"
                ),
            )
        return CurationResult(
            hid, orig_sev, "low", label="admin_trust_surface",
            reason=f"exploitation requires {role!r}; "
                   f"role is in trusted_roles per audit_context",
        )

    # Rule 4 — fail-safe revert / unreachable-degenerate-state. When a finding
    # describes a revert on a degenerate input (zero divisor, max overflow,
    # empty supply, etc.) the auditor often hasn't proved the bad state is
    # reachable from a public entry point. The most common truth is that an
    # upstream guard short-circuits before the bad math runs — see RAAC v4
    # post-mortem for three examples. Conservative response: floor-drop two
    # severity levels and require the verifier (mode='verify') or a human
    # reviewer to prove reachability before this can ship at original severity.
    if _fail_safe_revert_match(_flatten_evidence(hypothesis)):
        # Two-level floor: Critical → Medium, High → Low, Medium → Informational
        floor_map = {
            "critical": "medium",
            "high": "low",
            "medium": "informational",
            "low": "informational",
        }
        new_sev = floor_map.get(orig_sev, orig_sev)
        if _SEV_RANK.get(new_sev, 5) < _SEV_RANK.get(orig_sev, 5):
            return CurationResult(
                hid, orig_sev, new_sev, label="potential_fail_safe",
                reason=(
                    "auditor flagged a revert-on-degenerate-input without "
                    "proving the degenerate state is reachable from a public "
                    "entry point. Reachability must be demonstrated (caller "
                    "trace OR Phase-4 bump pass) before this can ship at "
                    f"{orig_sev.upper()}. See firepan-rule4."
                ),
            )

    # firepan-pr77 Rule 5b — Slither corroboration. When the auditor's
    # finding overlaps a Slither hit (same file + nearby lines + compatible
    # vulnerability_type), mark `slither_corroborated=True` in the
    # properties. When the auditor's finding has NO Slither overlap AND
    # severity is High/Critical, demote one level and mark
    # `unconfirmed_by_static` so the reviewer knows the LLM is the sole
    # source. Conservative: never PROMOTE; only demote unconfirmed
    # high-severity findings or annotate corroborated findings.
    corroborated, slither_check = _slither_overlap(hypothesis, ctx.slither_hits)
    if corroborated:
        # Annotate but don't change severity — let other rules continue.
        # Curator-applying caller will see the label addition and propagate.
        prop_label = "slither_corroborated"
        return CurationResult(
            hid, orig_sev, orig_sev, label=prop_label,
            reason=(
                f"Slither corroborated this finding (`{slither_check}`); "
                "stayed at original severity"
            ),
        )
    if (not corroborated
            and _SEV_RANK.get(orig_sev, 0) >= _SEV_RANK["high"]
            and ctx.slither_hits):  # only demote when we ran Slither at all
        floor = {"critical": "high", "high": "medium"}.get(orig_sev, orig_sev)
        return CurationResult(
            hid, orig_sev, floor, label="unconfirmed_by_static",
            reason=(
                f"High/Critical without Slither corroboration; demoted to "
                f"{floor.upper()} (Rule 5b). Reviewer to verify."
            ),
        )

    return CurationResult(hid, orig_sev, orig_sev)


# ---------------------------------------------------------------------------
# Rule 5b helpers — Slither overlap detection
# ---------------------------------------------------------------------------


def _slither_overlap(
    hypothesis: dict[str, Any],
    slither_hits: list[dict[str, Any]],
) -> tuple[bool, str]:
    """Return (matched, slither_check_name). True when the finding's file +
    line range overlaps with a Slither hit, AND the slither check's
    vulnerability type is compatible with the finding's vulnerability_type.
    Tolerant — we'd rather over-corroborate than under-corroborate."""
    if not slither_hits:
        return (False, "")
    loc_file = _location_file(hypothesis) or ""
    if not loc_file:
        return (False, "")
    nrefs = hypothesis.get("node_refs") or []
    if not nrefs:
        return (False, "")
    # Extract a line number range from the first node_ref (format: "path:N" or
    # "path:N-M"). Be forgiving with malformed inputs.
    line_start: int | None = None
    line_end: int | None = None
    if isinstance(nrefs[0], str) and ":" in nrefs[0]:
        try:
            tail = nrefs[0].rsplit(":", 1)[-1]
            if "-" in tail:
                a, b = tail.split("-", 1)
                line_start, line_end = int(a), int(b)
            else:
                line_start = line_end = int(tail)
        except (ValueError, IndexError):
            pass
    if line_start is None:
        return (False, "")

    vuln_type = (hypothesis.get("vulnerability_type") or "").lower()
    title = (hypothesis.get("title") or "").lower()

    for hit in slither_hits:
        hit_file = (hit.get("file") or "").strip()
        if not hit_file:
            continue
        # Match by suffix — slither paths may be absolute, finding paths
        # repo-relative, etc.
        if not (loc_file.endswith(hit_file) or hit_file.endswith(loc_file)):
            continue
        hit_lines = hit.get("lines") or []
        if not isinstance(hit_lines, list) or not hit_lines:
            # No line-level info — file-level match counts as overlap.
            return (True, str(hit.get("check") or "file-overlap"))
        # Line-range overlap with a ±5 tolerance
        hit_min = min(hit_lines) - 5
        hit_max = max(hit_lines) + 5
        if not (line_end < hit_min or line_start > hit_max):
            check = str(hit.get("check") or "line-overlap")
            # Optional vuln_type compatibility check — if both sides
            # declare types, they should be in the same family.
            if vuln_type and check:
                if not _vuln_type_compatible(vuln_type, check, title):
                    # Geographic overlap but type mismatch — still report
                    # as corroborated but flag the mismatch in the check
                    # name for the reviewer.
                    return (True, f"{check} (type mismatch w/ {vuln_type})")
            return (True, check)
    return (False, "")


_SLITHER_TYPE_FAMILIES: dict[str, list[str]] = {
    "reentrancy": ["reentrancy-eth", "reentrancy-no-eth",
                   "reentrancy-benign", "reentrancy-events",
                   "reentrancy-unlimited-gas"],
    "math": ["divide-before-multiply", "incorrect-equality",
             "weak-prng", "uninitialized-local"],
    "access-control": ["arbitrary-send", "controlled-array-length",
                       "controlled-delegatecall", "suicidal"],
    "oracle": ["timestamp", "block-other-parameters"],
    "dos": ["calls-loop", "costly-loop", "low-level-calls"],
    "uninitialized": ["uninitialized-state", "uninitialized-storage",
                      "uninitialized-local"],
}


def _vuln_type_compatible(vuln_type: str, slither_check: str, title: str) -> bool:
    """Return True if the slither check is in a family compatible with the
    auditor's vulnerability_type / title. Tolerant by design."""
    if not slither_check:
        return True
    check_lower = slither_check.lower()
    # Find which family the slither check belongs to
    family = None
    for fam, members in _SLITHER_TYPE_FAMILIES.items():
        if check_lower in members or fam in check_lower:
            family = fam
            break
    if not family:
        # Unknown slither check — accept (don't penalize for our incomplete map)
        return True
    text = (vuln_type + " " + title).lower()
    if family in text:
        return True
    # Family aliases for the auditor's terminology
    aliases = {
        "math": ["overflow", "underflow", "division", "div-by-zero",
                 "arithmetic", "precision"],
        "access-control": ["authorization", "permission", "missing-check",
                           "missing-modifier", "owner"],
        "reentrancy": ["reentrant", "external-call"],
    }
    for alias in aliases.get(family, []):
        if alias in text:
            return True
    return False


def _evidence_density(hypothesis: dict[str, Any]) -> int:
    """Return a numeric density score for tie-breaking dedup. Higher = more
    line-cite + tagged evidence + higher-confidence items. Used by
    curate_all() when two findings collide on the same code location."""
    items = hypothesis.get("evidence", [])
    if isinstance(items, dict):
        items = items.get("items", [])
    if not isinstance(items, list):
        return 0
    score = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        desc = item.get("description", "") or ""
        # Tagged evidence ([data_flow], [exploitability], [poc_construction], ...)
        if desc.lstrip().startswith("["):
            score += 3
        # Specific file:line citations
        for needle in [":", "#L", "@L"]:
            if needle in desc:
                score += 1
                break
        # Confidence
        try:
            score += int(float(item.get("confidence", 0.0) or 0) * 10)
        except (ValueError, TypeError):
            pass
    return score


def _fail_safe_revert_match(evidence_text: str) -> bool:
    """Return True if the finding's text matches a fail-safe-revert pattern."""
    if not evidence_text:
        return False
    for pat in _FAIL_SAFE_PATTERNS:
        if re.search(pat, evidence_text, re.IGNORECASE):
            return True
    return False


def curate_all(
    hypotheses: list[Any], ctx: AuditContext
) -> list[CurationResult]:
    """Curate a batch of hypotheses. Accepts either dicts or dataclass
    instances — we marshal to dict internally. firepan-pr77: before
    curating, resolve same-location conflicts via evidence-density."""
    # Marshal everything to dicts first so we can compute evidence density
    # consistently.
    marshalled: list[dict[str, Any]] = []
    for h in hypotheses:
        if hasattr(h, "__dict__") and not isinstance(h, dict):
            d = {
                "id": getattr(h, "id", ""),
                "title": getattr(h, "title", ""),
                "description": getattr(h, "description", ""),
                "severity": getattr(h, "severity", ""),
                "vulnerability_type": getattr(h, "vulnerability_type", ""),
                "node_refs": getattr(h, "node_refs", []) or [],
                "evidence": getattr(h, "evidence", []) or [],
                "properties": getattr(h, "properties", {}) or {},
            }
        else:
            d = dict(h)
        marshalled.append(d)

    # firepan-pr77 evidence-density dedup. When two findings share the same
    # location (file + nearest-line bucket), pick the one with the higher
    # evidence-density score. The losers are NOT dropped — they're marked
    # so the caller can still surface them as "subsumed by hyp_X". This
    # mirrors LLM-SmartAudit's Summarization Agent role.
    by_loc: dict[tuple[str, int], list[int]] = {}
    for i, d in enumerate(marshalled):
        loc = _location_file(d) or ""
        line = 0
        nrefs = d.get("node_refs") or []
        if nrefs and isinstance(nrefs[0], str) and ":" in nrefs[0]:
            try:
                tail = nrefs[0].rsplit(":", 1)[-1]
                line = int(tail.split("-", 1)[0])
            except (ValueError, IndexError):
                line = 0
        bucket = (line // 10) * 10  # ±5-line tolerance
        by_loc.setdefault((loc, bucket), []).append(i)

    subsumed: set[int] = set()
    for (loc, _bucket), idxs in by_loc.items():
        if len(idxs) < 2 or not loc:
            continue
        # Pick the densest evidence
        scored = sorted(
            idxs, key=lambda i: -_evidence_density(marshalled[i])
        )
        keeper = scored[0]
        for loser in scored[1:]:
            # Annotate the loser; the actual curate_one call still runs so the
            # caller has uniform results, but the label flags the subsumption.
            subsumed.add(loser)
            marshalled[loser].setdefault("properties", {})[
                "subsumed_by"
            ] = marshalled[keeper].get("id")

    results: list[CurationResult] = []
    for i, d in enumerate(marshalled):
        r = curate_one(d, ctx)
        if i in subsumed:
            # Override label with subsumption signal — visible in curator summary
            r = CurationResult(
                r.hypothesis_id, r.original_severity,
                "informational", label="subsumed_by_denser_evidence",
                reason=(f"same-location duplicate of "
                        f"{d['properties'].get('subsumed_by')}; "
                        f"floored to informational"),
            )
        results.append(r)
    return results


def apply_curation(
    hypothesis: Any, result: CurationResult
) -> None:
    """Mutate a hypothesis in place to reflect a CurationResult.

    Records the curation decision in ``properties["curation"]`` (a list, so
    re-runs can layer audits) and updates ``severity`` to the new value.
    Does NOT remove dropped hypotheses — callers must filter on
    ``result.drop`` themselves.
    """
    if not result.changed:
        return
    # Dataclass instance vs dict
    if hasattr(hypothesis, "severity"):
        hypothesis.severity = result.new_severity
        props = getattr(hypothesis, "properties", None)
        if props is None:
            hypothesis.properties = {}
            props = hypothesis.properties
    else:  # dict-like
        hypothesis["severity"] = result.new_severity
        props = hypothesis.setdefault("properties", {})
    audit_trail = props.setdefault("curation", [])
    audit_trail.append({
        "original_severity": result.original_severity,
        "new_severity": result.new_severity,
        "label": result.label,
        "reason": result.reason,
    })


__all__ = [
    "AuditContext",
    "CurationResult",
    "curate_one",
    "curate_all",
    "apply_curation",
]
