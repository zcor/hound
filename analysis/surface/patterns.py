"""Vulnerability pattern definitions for surface scanning."""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal


@dataclass
class VulnerabilityPattern:
    """Definition of a vulnerability pattern to detect."""

    id: str
    name: str
    severity: Literal["critical", "high", "medium", "low"]
    category: Literal["vulnerability", "quality"]
    patterns: list[re.Pattern]
    description: str
    false_positive_hints: list[str] = field(default_factory=list)

    def matches(self, content: str) -> list[re.Match]:
        """Find all matches of this pattern in content."""
        matches = []
        for pattern in self.patterns:
            matches.extend(pattern.finditer(content))
        return matches


@dataclass
class PatternMatch:
    """A match of a vulnerability pattern in code."""

    pattern: VulnerabilityPattern
    match: re.Match
    file_path: str
    line_number: int
    code_context: str  # Lines around the match


# Solidity vulnerability patterns
SOLIDITY_PATTERNS = [
    # Critical severity
    VulnerabilityPattern(
        id="SELFDESTRUCT-001",
        name="Unprotected selfdestruct",
        severity="critical",
        category="vulnerability",
        patterns=[
            re.compile(r'\bselfdestruct\s*\(', re.IGNORECASE),
        ],
        description="selfdestruct can destroy the contract and send funds. Ensure proper access control.",
        false_positive_hints=["onlyOwner", "require(msg.sender", "auth", "authorized"],
    ),
    VulnerabilityPattern(
        id="DELEGATECALL-001",
        name="Unprotected delegatecall",
        severity="critical",
        category="vulnerability",
        patterns=[
            re.compile(r'\.delegatecall\s*\(', re.IGNORECASE),
        ],
        description="delegatecall executes code in the caller's context. Can lead to storage corruption.",
        false_positive_hints=["onlyOwner", "require(msg.sender", "internal", "private"],
    ),

    # High severity
    VulnerabilityPattern(
        id="REENTRANCY-001",
        name="Potential Reentrancy",
        severity="high",
        category="vulnerability",
        patterns=[
            # External call followed by state change
            re.compile(r'\.call\{[^}]*value[^}]*\}\s*\([^)]*\)\s*;[^}]*\w+\s*[+\-=]', re.MULTILINE | re.DOTALL),
            re.compile(r'\.call\{[^}]*\}\s*\([^)]*\)\s*;[^}]*\w+\s*=\s*\w+', re.MULTILINE | re.DOTALL),
            # Transfer/send followed by state change
            re.compile(r'\.transfer\s*\([^)]+\)\s*;[^}]*\w+\s*[+\-=]', re.MULTILINE | re.DOTALL),
        ],
        description="External call before state update could allow reentrancy attack.",
        false_positive_hints=["nonReentrant", "ReentrancyGuard", "mutex", "locked"],
    ),
    VulnerabilityPattern(
        id="TXORIGIN-001",
        name="tx.origin for authorization",
        severity="high",
        category="vulnerability",
        patterns=[
            re.compile(r'require\s*\(\s*tx\.origin', re.IGNORECASE),
            re.compile(r'if\s*\(\s*tx\.origin', re.IGNORECASE),
            re.compile(r'==\s*tx\.origin', re.IGNORECASE),
        ],
        description="tx.origin can be manipulated in phishing attacks. Use msg.sender instead.",
        false_positive_hints=[],
    ),
    VulnerabilityPattern(
        id="UNCHECKED-CALL-001",
        name="Unchecked low-level call",
        severity="high",
        category="vulnerability",
        patterns=[
            # .call() without checking return value
            re.compile(r'\.call\s*\([^)]*\)\s*;(?!\s*\n\s*require)', re.MULTILINE),
            re.compile(r'\.call\{[^}]*\}\s*\([^)]*\)\s*;(?!\s*\n\s*require)', re.MULTILINE),
        ],
        description="Low-level call return value not checked. Could silently fail.",
        false_positive_hints=["(bool success", "bool result", "require(success"],
    ),
    VulnerabilityPattern(
        id="OVERFLOW-001",
        name="Potential Integer Overflow",
        severity="high",
        category="vulnerability",
        patterns=[
            # Solidity version < 0.8.0 without SafeMath
            re.compile(r'pragma\s+solidity\s+[\^~>=<]*\s*0\.[0-7]\.', re.IGNORECASE),
        ],
        description="Solidity < 0.8.0 does not have built-in overflow checks. Use SafeMath.",
        false_positive_hints=["SafeMath", "using SafeMath", "safe_"],
    ),

    # Medium severity
    VulnerabilityPattern(
        id="ACCESS-001",
        name="Missing access control",
        severity="medium",
        category="vulnerability",
        patterns=[
            # Public/external functions that modify state without modifiers
            re.compile(r'function\s+\w+\s*\([^)]*\)\s+(external|public)\s+(?!view|pure)[^{]*\{[^}]*\w+\s*=', re.MULTILINE | re.DOTALL),
        ],
        description="State-changing function may lack access control. Verify authorization.",
        false_positive_hints=["onlyOwner", "onlyRole", "require(msg.sender", "auth", "modifier"],
    ),
    VulnerabilityPattern(
        id="FRONTRUN-001",
        name="Potential frontrunning vulnerability",
        severity="medium",
        category="vulnerability",
        patterns=[
            # Approval patterns that could be frontrun
            re.compile(r'approve\s*\([^)]+,\s*[^)]+\)', re.IGNORECASE),
            re.compile(r'setApprovalForAll', re.IGNORECASE),
        ],
        description="Approval functions may be vulnerable to frontrunning attacks.",
        false_positive_hints=["increaseAllowance", "decreaseAllowance", "permit"],
    ),
    VulnerabilityPattern(
        id="ORACLE-001",
        name="Price oracle dependency",
        severity="medium",
        category="vulnerability",
        patterns=[
            re.compile(r'getPrice|latestAnswer|getRoundData|latestRoundData', re.IGNORECASE),
            re.compile(r'chainlink|oracle', re.IGNORECASE),
        ],
        description="External price oracle usage detected. Ensure manipulation resistance.",
        false_positive_hints=["TWAP", "timeWeighted", "staleness check"],
    ),
    VulnerabilityPattern(
        id="FLASHLOAN-001",
        name="Flash loan callback detected",
        severity="medium",
        category="vulnerability",
        patterns=[
            re.compile(r'flashLoan|executeOperation|onFlashLoan|uniswapV\dCall', re.IGNORECASE),
        ],
        description="Flash loan patterns detected. Ensure proper validation of callbacks.",
        false_positive_hints=["initiator check", "msg.sender =="],
    ),

    # Low severity
    VulnerabilityPattern(
        id="DEPRECATED-001",
        name="Deprecated pattern usage",
        severity="low",
        category="quality",
        patterns=[
            re.compile(r'\bthrow\s*;', re.IGNORECASE),
            re.compile(r'\bsha3\s*\(', re.IGNORECASE),
            re.compile(r'\bsuicide\s*\(', re.IGNORECASE),
            re.compile(r'\bconstant\s+function', re.IGNORECASE),
        ],
        description="Deprecated Solidity patterns detected. Consider updating.",
        false_positive_hints=[],
    ),
    VulnerabilityPattern(
        id="VISIBILITY-001",
        name="Default visibility",
        severity="low",
        category="quality",
        patterns=[
            # Function without explicit visibility (Solidity < 0.5)
            re.compile(r'function\s+\w+\s*\([^)]*\)\s*(?!public|private|internal|external)\s*{', re.MULTILINE),
        ],
        description="Function visibility not explicitly specified.",
        false_positive_hints=[],
    ),
]

# Vyper vulnerability patterns
VYPER_PATTERNS = [
    VulnerabilityPattern(
        id="VYPER-REENTRANCY-001",
        name="Potential Reentrancy (Vyper)",
        severity="high",
        category="vulnerability",
        patterns=[
            re.compile(r'raw_call\s*\([^)]*\)', re.IGNORECASE),
            re.compile(r'send\s*\([^)]*\)', re.IGNORECASE),
        ],
        description="External call detected. Verify reentrancy protection.",
        false_positive_hints=["@nonreentrant", "lock"],
    ),
    VulnerabilityPattern(
        id="VYPER-SELFDESTRUCT-001",
        name="Unprotected selfdestruct (Vyper)",
        severity="critical",
        category="vulnerability",
        patterns=[
            re.compile(r'\bselfdestruct\s*\(', re.IGNORECASE),
        ],
        description="selfdestruct can destroy the contract. Ensure proper access control.",
        false_positive_hints=["@internal", "assert msg.sender"],
    ),
]

# Quality patterns (applies to both)
QUALITY_PATTERNS = [
    # Note: Complex patterns that need lookahead/lookbehind are handled separately
    # to avoid regex compilation errors
]


class PatternDetector:
    """Detect vulnerability patterns in smart contract code."""

    def __init__(self):
        self.solidity_patterns = SOLIDITY_PATTERNS
        self.vyper_patterns = VYPER_PATTERNS
        self.quality_patterns = QUALITY_PATTERNS

    def detect_language(self, file_path: Path) -> str | None:
        """Detect smart contract language from file extension."""
        suffix = file_path.suffix.lower()
        if suffix == ".sol":
            return "solidity"
        elif suffix == ".vy":
            return "vyper"
        return None

    def get_patterns_for_language(self, language: str) -> list[VulnerabilityPattern]:
        """Get applicable patterns for a language."""
        patterns = self.quality_patterns.copy()
        if language == "solidity":
            patterns.extend(self.solidity_patterns)
        elif language == "vyper":
            patterns.extend(self.vyper_patterns)
        return patterns

    def detect(self, content: str, file_path: Path) -> list[PatternMatch]:
        """Detect all vulnerability patterns in file content."""
        language = self.detect_language(file_path)
        if not language:
            return []

        patterns = self.get_patterns_for_language(language)
        matches = []
        lines = content.split('\n')

        for pattern in patterns:
            for match in pattern.matches(content):
                # Calculate line number
                line_num = content[:match.start()].count('\n') + 1

                # Get context (5 lines before and after)
                start_line = max(0, line_num - 6)
                end_line = min(len(lines), line_num + 5)
                context = '\n'.join(lines[start_line:end_line])

                # Check for false positive hints in context
                has_fp_hint = any(
                    hint.lower() in context.lower()
                    for hint in pattern.false_positive_hints
                )

                # Only add if no false positive hints found
                if not has_fp_hint:
                    matches.append(PatternMatch(
                        pattern=pattern,
                        match=match,
                        file_path=str(file_path),
                        line_number=line_num,
                        code_context=context,
                    ))

        return matches

    def detect_quality_metrics(self, content: str, file_path: Path) -> dict:
        """Extract quality metrics from file content."""
        metrics = {
            "has_events": bool(re.search(r'\bevent\s+\w+', content)),
            "has_natspec": bool(re.search(r'(///|/\*\*)', content)),
            "has_access_control": bool(re.search(r'(onlyOwner|onlyRole|require\s*\(\s*msg\.sender|auth)', content, re.IGNORECASE)),
            "uses_safemath": bool(re.search(r'(using\s+SafeMath|\.add\(|\.sub\(|\.mul\()', content)),
            "solidity_version": None,
            "vyper_version": None,
        }

        # Extract Solidity version
        sol_match = re.search(r'pragma\s+solidity\s+[\^~>=<]*\s*(\d+\.\d+\.?\d*)', content)
        if sol_match:
            metrics["solidity_version"] = sol_match.group(1)

        # Extract Vyper version
        vy_match = re.search(r'#\s*@version\s+(\d+\.\d+\.?\d*)', content)
        if vy_match:
            metrics["vyper_version"] = vy_match.group(1)

        return metrics
