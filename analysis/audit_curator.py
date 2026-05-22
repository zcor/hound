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
        return CurationResult(
            hid, orig_sev, "low", label="admin_trust_surface",
            reason=f"exploitation requires {role!r}; "
                   f"role is in trusted_roles per audit_context",
        )

    return CurationResult(hid, orig_sev, orig_sev)


def curate_all(
    hypotheses: list[Any], ctx: AuditContext
) -> list[CurationResult]:
    """Curate a batch of hypotheses. Accepts either dicts or dataclass
    instances — we marshal to dict internally."""
    results: list[CurationResult] = []
    for h in hypotheses:
        if hasattr(h, "__dict__") and not isinstance(h, dict):
            # Dataclass-or-similar — best-effort conversion. We don't import
            # the Hypothesis class here to avoid a circular import; instead
            # we marshal the public attributes we care about.
            d = {
                "id": getattr(h, "id", ""),
                "title": getattr(h, "title", ""),
                "description": getattr(h, "description", ""),
                "severity": getattr(h, "severity", ""),
                "node_refs": getattr(h, "node_refs", []) or [],
                "evidence": getattr(h, "evidence", []) or [],
                "properties": getattr(h, "properties", {}) or {},
            }
        else:
            d = dict(h)
        results.append(curate_one(d, ctx))
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
