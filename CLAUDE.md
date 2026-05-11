# Hound — Smart-Contract Security Auditor

This repository contains the **Hound** audit pipeline.  When Claude Code
is invoked in autonomous auditor mode, the following tools and conventions
apply.

## Available tools

| Tool | Usage |
|------|-------|
| **Slither** | `slither .` or `slither <file>` — Solidity static analysis |
| **Foundry** | `forge build`, `forge test`, `cast` — compile, test, interact |
| **semgrep** | `semgrep --config auto .` — multi-language static analysis |
| **solc-select** | `solc-select install <ver> && solc-select use <ver>` |

### Trail of Bits Claude Code plugins

Installed via `claude plugin install <name>@trailofbits`.  Invoke with
`claude plugin run <name>`:

- `fp-check` — false-positive verification
- `audit-context-building` — build audit context from a codebase
- `static-analysis` — orchestrate static analysis tools
- `variant-analysis` — find variants of a known vulnerability
- `property-based-testing` — generate property-based tests
- `mutation-testing` — mutation testing for test suites
- `differential-review` — review diffs for security impacts
- `spec-to-code-compliance` — verify code matches specification
- `building-secure-contracts` — secure Solidity patterns
- `entry-point-analyzer` — find external entry points
- `second-opinion` — get a second opinion on a finding

### Pashov skills

Located in `~/.claude/skills/pashov-skills/`:
- `solidity-auditor` — comprehensive Solidity audit skill
- `x-ray` — deep code analysis skill

## Audit conventions

1. **Evidence first**: every finding must include `file:line` references
   from code you actually read.  Do not rely on training data.
2. **Numeric gap required**: every candidate finding must include a
   `numeric_gap_measurement` — a quantitative impact figure.
3. **Run tools**: use `slither`, `forge test`, `semgrep` on the actual
   codebase.  Parse their output for real detector hits.
4. **Depth over breadth**: one well-evidenced finding is better than five
   hand-wavy ones.
5. **CandidateFindingBatch schema**: output findings as a JSON object
   inside a ` ```json ` fence matching the schema.
