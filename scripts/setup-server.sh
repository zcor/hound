#!/usr/bin/env bash
# =============================================================================
# setup-server.sh — provision a Hound auditor server in one pass.
#
# A fresh clone followed by `./scripts/setup-server.sh` should produce a
# machine capable of running the single-auditor + fp-check pipeline described
# in the audit-pipeline refactor issue, including:
#   - Language/runtime prereqs (Python 3.13, Node 22 LTS, Rust stable, Solidity,
#     Vyper + titanoboa).
#   - CLI tooling (rg, fd, ast-grep, shellcheck, shfmt, actionlint, zizmor, prek).
#   - Security tooling (semgrep, slither-analyzer, crytic-compile).
#   - Claude Code CLI plus the Trail of Bits plugin marketplace
#     (fp-check, audit-context-building, static-analysis, ...).
#   - Pashov skills (solidity-auditor, x-ray) under ~/.claude/skills/.
#   - Giovani's claude-wiki skill.
#
# Design notes:
#   - Idempotent: every installer is guarded by a capability check.
#   - Best-effort: optional tooling that fails to install logs a warning but
#     does not abort the script; the server image should still come up.
#   - Root-or-sudo: uses sudo when available, runs apt-get directly when the
#     script is invoked as root (e.g. during Docker image build).
#   - No secrets: environment-variable requirements are *reported*, never
#     written. Operators must populate .env / container secrets themselves.
# =============================================================================

set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# --- logging helpers ---------------------------------------------------------
log()  { printf '\033[0;32m[setup]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m  %s\n' "$*" >&2; }
err()  { printf '\033[0;31m[err]\033[0m   %s\n' "$*" >&2; }

# Track non-fatal failures so we can summarise them at the end.
FAILED_STEPS=()
run_step() {
    local name="$1"; shift
    log "==> ${name}"
    if "$@"; then
        return 0
    else
        warn "${name} failed (continuing)"
        FAILED_STEPS+=("${name}")
        return 0
    fi
}

have() { command -v "$1" >/dev/null 2>&1; }

# --- privilege helper --------------------------------------------------------
if [[ "${EUID}" -eq 0 ]]; then
    SUDO=""
else
    if have sudo; then
        SUDO="sudo"
    else
        SUDO=""
        warn "running unprivileged and 'sudo' is not installed; apt steps will be skipped"
    fi
fi

apt_install() {
    # apt_install <pkg> [pkg...]
    if ! have apt-get; then
        warn "apt-get not available; skipping: $*"
        return 0
    fi
    if [[ -z "${SUDO}" && "${EUID}" -ne 0 ]]; then
        warn "no sudo and not root; skipping apt-get install: $*"
        return 0
    fi
    ${SUDO} DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@"
}

# =============================================================================
# 1. OS packages
# =============================================================================
install_os_packages() {
    if ! have apt-get; then
        warn "non-Debian system detected; skipping OS package bootstrap"
        return 0
    fi
    if [[ -z "${SUDO}" && "${EUID}" -ne 0 ]]; then
        warn "no sudo; skipping OS package bootstrap"
        return 0
    fi
    ${SUDO} DEBIAN_FRONTEND=noninteractive apt-get update
    apt_install \
        build-essential curl git ca-certificates pkg-config \
        libssl-dev libffi-dev libpq-dev \
        python3-venv python3-pip \
        ripgrep fd-find shellcheck jq unzip
    # fd is shipped as fdfind on Debian/Ubuntu; expose it as `fd` for skill scripts.
    if have fdfind && ! have fd; then
        if [[ -n "${SUDO}" || "${EUID}" -eq 0 ]]; then
            ${SUDO} ln -sf "$(command -v fdfind)" /usr/local/bin/fd
        fi
    fi
}

# =============================================================================
# 2. Python 3.13 + uv + ruff + ty + pytest
# =============================================================================
install_python_toolchain() {
    # uv bootstraps and manages a pinned Python 3.13 without touching the
    # system interpreter. Safe on Debian/Ubuntu images shipping 3.11/3.12.
    if ! have uv; then
        log "installing uv"
        curl -LsSf https://astral.sh/uv/install.sh | sh
        # uv installs to $HOME/.local/bin; expose for the rest of this script.
        export PATH="${HOME}/.local/bin:${PATH}"
    else
        log "uv already installed ($(uv --version))"
    fi

    log "pinning Python 3.13 via uv"
    uv python install 3.13

    # Install Python CLI tooling as isolated `uv tool` environments so they
    # don't collide with the repo's requirements.txt.
    for tool in ruff ty pytest semgrep slither-analyzer crytic-compile vyper titanoboa solc-select; do
        if uv tool list 2>/dev/null | grep -q "^${tool} "; then
            log "uv tool ${tool} already installed"
            continue
        fi
        log "uv tool install ${tool}"
        # slither depends on crytic-compile; install order doesn't matter for
        # uv (isolated venvs), but keep them on the list so both are present.
        if ! uv tool install "${tool}" >/dev/null 2>&1; then
            warn "uv tool install ${tool} failed; retrying with PyPI index refresh"
            uv tool install --no-cache "${tool}" || warn "skip ${tool}"
        fi
    done

    # Pin Vyper to 0.4.3 (required to execute the Curve-style PoCs).
    # `vyper --version` prints e.g. "0.4.3+commit.abcdef" on its first line, so
    # grab the leading semver with a regex rather than positional awk.
    if have vyper; then
        local vyper_version
        vyper_version="$(vyper --version 2>/dev/null | head -n1 \
            | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"
        if [[ "${vyper_version}" != "0.4.3" ]]; then
            log "pinning vyper to 0.4.3 (found: ${vyper_version:-unknown})"
            uv tool install --force 'vyper==0.4.3' || warn "could not pin vyper==0.4.3"
        fi
    fi

    # Pre-select recent solc versions so audits don't stall on first download.
    if have solc-select; then
        solc-select install 0.8.20 0.8.24 0.8.28 >/dev/null 2>&1 || \
            warn "solc-select: failed to pre-install solc versions"
        solc-select use 0.8.28 >/dev/null 2>&1 || true
    fi

    # prek (pre-commit-compatible) is distributed on PyPI.
    if ! have prek; then
        uv tool install prek >/dev/null 2>&1 || warn "prek install failed"
    fi
}

# =============================================================================
# 3. Node 22 LTS + pnpm (dashboard / frontend)
# =============================================================================
install_node_toolchain() {
    local want_major=22
    local have_major=""
    if have node; then
        have_major="$(node -v 2>/dev/null | sed -E 's/^v([0-9]+)\..*/\1/')"
    fi
    if [[ "${have_major}" != "${want_major}" ]]; then
        if have apt-get && { [[ -n "${SUDO}" ]] || [[ "${EUID}" -eq 0 ]]; }; then
            log "installing Node ${want_major} LTS via NodeSource"
            curl -fsSL "https://deb.nodesource.com/setup_${want_major}.x" | ${SUDO} -E bash -
            apt_install nodejs
        else
            warn "cannot install Node ${want_major}: need apt-get and root/sudo"
        fi
    else
        log "Node ${want_major} already installed ($(node -v))"
    fi

    if have npm && ! have pnpm; then
        log "installing pnpm via corepack"
        if [[ -n "${SUDO}" || "${EUID}" -eq 0 ]]; then
            ${SUDO} corepack enable >/dev/null 2>&1 || npm install -g pnpm
        else
            npm install -g pnpm >/dev/null 2>&1 || warn "pnpm install failed"
        fi
    fi
}

# =============================================================================
# 4. Rust stable + cargo-nextest + cargo-mutants
# =============================================================================
install_rust_toolchain() {
    if ! have rustup; then
        log "installing rustup (stable toolchain)"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
            sh -s -- -y --default-toolchain stable --profile minimal
        # shellcheck disable=SC1091
        [[ -f "${HOME}/.cargo/env" ]] && source "${HOME}/.cargo/env"
    else
        log "rustup already installed"
        rustup toolchain install stable --profile minimal >/dev/null 2>&1 || true
    fi

    export PATH="${HOME}/.cargo/bin:${PATH}"

    for crate in cargo-nextest cargo-mutants ast-grep; do
        local bin="${crate}"
        [[ "${crate}" == "ast-grep" ]] && bin="sg"
        if have "${bin}" || cargo install --list 2>/dev/null | grep -q "^${crate} "; then
            log "${crate} already installed"
            continue
        fi
        log "cargo install ${crate}"
        cargo install --locked "${crate}" >/dev/null 2>&1 || warn "${crate} install failed"
    done
}

# =============================================================================
# 5. Solidity — Foundry (forge/cast/anvil)
# =============================================================================
install_foundry() {
    if have forge && have cast && have anvil; then
        log "foundry already installed ($(forge --version | head -n1))"
        return 0
    fi
    log "installing Foundry via foundryup"
    curl -L https://foundry.paradigm.xyz | bash
    # foundryup drops itself at $HOME/.foundry/bin/foundryup.
    export PATH="${HOME}/.foundry/bin:${PATH}"
    if have foundryup; then
        foundryup
    else
        warn "foundryup not on PATH after install"
    fi
}

# =============================================================================
# 6. Go-based CLI tooling (shfmt, actionlint, zizmor)
# =============================================================================
install_go_tooling() {
    # shfmt / actionlint / zizmor have prebuilt binary releases — grab them via
    # the installer scripts published by each project. These are tiny and do
    # not require a Go toolchain on the server image.
    if ! have shfmt; then
        log "installing shfmt"
        if have curl; then
            local shfmt_url
            shfmt_url="$(curl -fsSL https://api.github.com/repos/mvdan/sh/releases/latest \
                | grep -oE 'https://[^"]*shfmt_[^"]*_linux_amd64' | head -n1)"
            if [[ -n "${shfmt_url}" ]]; then
                curl -fsSL "${shfmt_url}" -o /tmp/shfmt && chmod +x /tmp/shfmt
                ${SUDO} mv /tmp/shfmt /usr/local/bin/shfmt || \
                    mv /tmp/shfmt "${HOME}/.local/bin/shfmt"
            else
                warn "could not resolve shfmt release URL"
            fi
        fi
    fi

    if ! have actionlint; then
        log "installing actionlint"
        bash <(curl -fsSL https://raw.githubusercontent.com/rhysd/actionlint/main/scripts/download-actionlint.bash) \
            latest /tmp >/dev/null 2>&1 || warn "actionlint installer failed"
        if [[ -x /tmp/actionlint ]]; then
            ${SUDO} mv /tmp/actionlint /usr/local/bin/actionlint 2>/dev/null || \
                mv /tmp/actionlint "${HOME}/.local/bin/actionlint"
        fi
    fi

    if ! have zizmor; then
        # zizmor is published as a Python package; install with uv.
        if have uv; then
            uv tool install zizmor >/dev/null 2>&1 || warn "zizmor install failed"
        else
            warn "uv unavailable; skipping zizmor"
        fi
    fi
}

# =============================================================================
# 7. Claude Code CLI + Trail of Bits plugin marketplace + external skills
# =============================================================================
install_claude_cli_and_skills() {
    # Claude Code CLI ships as an npm package.
    if ! have claude; then
        if have npm; then
            log "installing Claude Code CLI"
            if [[ -n "${SUDO}" || "${EUID}" -eq 0 ]]; then
                ${SUDO} npm install -g @anthropic-ai/claude-code >/dev/null 2>&1 || \
                    warn "claude CLI install failed"
            else
                npm install -g @anthropic-ai/claude-code >/dev/null 2>&1 || \
                    warn "claude CLI install failed (no permission for global npm)"
            fi
        else
            warn "npm not available; skipping Claude Code CLI"
        fi
    else
        log "claude CLI already installed"
    fi

    # Trail of Bits plugin marketplace + plugins.
    if have claude; then
        log "registering Trail of Bits plugin marketplace"
        claude plugin marketplace add trailofbits/claude-code-plugins \
            >/dev/null 2>&1 || warn "marketplace add failed (may already be registered)"

        local tob_plugins=(
            fp-check
            audit-context-building
            spec-to-code-compliance
            building-secure-contracts
            variant-analysis
            differential-review
            semgrep-rule-creator
            semgrep-rule-variant-creator
            static-analysis
            dimensional-analysis
            constant-time-analysis
            supply-chain-risk-auditor
            mutation-testing
            property-based-testing
            second-opinion
            zeroize-audit
            entry-point-analyzer
            insecure-defaults
            sharp-edges
            fix-review
            workflow-skill-design
        )
        for plugin in "${tob_plugins[@]}"; do
            if claude plugin list 2>/dev/null | grep -q "^${plugin}\b"; then
                continue
            fi
            claude plugin install "${plugin}@trailofbits" >/dev/null 2>&1 || \
                warn "plugin install failed: ${plugin}"
        done
    fi

    # Pashov skills (solidity-auditor, x-ray) go under ~/.claude/skills/.
    local skills_dir="${HOME}/.claude/skills"
    mkdir -p "${skills_dir}"

    clone_or_update() {
        local repo_url="$1"
        local target="$2"
        if [[ -d "${target}/.git" ]]; then
            log "updating ${target}"
            git -C "${target}" pull --ff-only >/dev/null 2>&1 || \
                warn "git pull failed for ${target}"
        else
            log "cloning ${repo_url} -> ${target}"
            git clone --depth 1 "${repo_url}" "${target}" >/dev/null 2>&1 || \
                warn "git clone failed for ${repo_url}"
        fi
    }

    clone_or_update https://github.com/pashov/skills.git "${skills_dir}/pashov-skills"
    clone_or_update https://github.com/giovani-junior-dev/claude-wiki.git \
        "${skills_dir}/claude-wiki"

    # --- Claude Code project configuration ---
    # Ship a default .claude/settings.json in the Hound repo root so that
    # CLI sessions inherit sensible tool permissions automatically.
    local hound_claude_dir="${REPO_ROOT}/.claude"
    if [[ ! -f "${hound_claude_dir}/settings.json" ]]; then
        log "initialising .claude/settings.json in ${REPO_ROOT}"
        mkdir -p "${hound_claude_dir}"
        cat > "${hound_claude_dir}/settings.json" <<'SETTINGS'
{
  "permissions": {
    "allow": [
      "Read", "Write", "Edit",
      "Bash(slither *)", "Bash(forge *)", "Bash(cast *)",
      "Bash(semgrep *)", "Bash(solc-select *)", "Bash(solc *)",
      "Bash(cat *)", "Bash(find *)", "Bash(grep *)", "Bash(ls *)",
      "Bash(head *)", "Bash(tail *)", "Bash(wc *)", "Bash(diff *)",
      "Bash(sha256sum *)", "Bash(python3 *)", "Bash(node *)",
      "Glob", "Grep"
    ],
    "deny": [
      "Bash(rm -rf /)", "Bash(curl *)", "Bash(wget *)", "Bash(ssh *)"
    ]
  }
}
SETTINGS
    fi

    # Smoke-test: verify the Claude CLI is reachable.
    if have claude; then
        if claude --version >/dev/null 2>&1; then
            log "Claude CLI smoke-test passed: $(claude --version 2>&1 | head -1)"
        else
            warn "Claude CLI installed but --version failed"
        fi
    fi
}

# =============================================================================
# 8. Python project dependencies (the Hound repo itself)
# =============================================================================
install_hound_requirements() {
    cd "${REPO_ROOT}" || return 1
    if [[ ! -f requirements.txt ]]; then
        warn "requirements.txt missing; skipping Hound deps"
        return 0
    fi
    if have uv; then
        log "installing Hound Python requirements with uv"
        uv pip install --system -r requirements.txt >/dev/null 2>&1 \
            || uv pip install -r requirements.txt \
            || warn "uv pip install failed"
    else
        log "installing Hound Python requirements with pip"
        python3 -m pip install -r requirements.txt || warn "pip install failed"
    fi
}

# =============================================================================
# 9. Environment-variable sanity check
# =============================================================================
check_environment() {
    # Only *report* missing variables; never write them. Operators set these
    # via container secrets / .env.
    local required=(ANTHROPIC_API_KEY)
    local optional=(
        OPENAI_API_KEY GOOGLE_API_KEY
        XAI_API_KEY REI_API_KEY DEEPSEEK_API_KEY OPENROUTER_API_KEY
        ETH_RPC_URL ETHERSCAN_API_KEY
    )
    local missing_required=()
    local missing_optional=()

    for var in "${required[@]}"; do
        [[ -z "${!var-}" ]] && missing_required+=("${var}")
    done
    for var in "${optional[@]}"; do
        [[ -z "${!var-}" ]] && missing_optional+=("${var}")
    done

    if ((${#missing_required[@]})); then
        warn "missing REQUIRED env vars: ${missing_required[*]}"
        warn "the auditor pipeline will not run until these are populated"
    fi
    if ((${#missing_optional[@]})); then
        log "missing optional env vars (fallback providers / enrichment): ${missing_optional[*]}"
    fi
}

# =============================================================================
# main
# =============================================================================
check_only() {
    # Verify the toolchain a single-auditor server depends on is on $PATH.
    # Exits 0 iff every required tool resolves; otherwise exits 1 listing
    # the missing tools.  Intended for CI / readiness probes.
    local required=(python3 node claude git slither forge semgrep rg)
    local missing=()
    for tool in "${required[@]}"; do
        if ! command -v "${tool}" >/dev/null 2>&1; then
            missing+=("${tool}")
        fi
    done

    if ((${#missing[@]} == 0)); then
        log "✅ all required tools present: ${required[*]}"
        check_environment
        return 0
    fi

    err "missing required tools: ${missing[*]}"
    err "run ./scripts/setup-server.sh (without --check) to install them"
    return 1
}

main() {
    local mode="install"
    local force_prod=0
    while (( $# > 0 )); do
        case "$1" in
            --check|-c)        mode="check" ;;
            --force-prod)      force_prod=1 ;;
            -h|--help)
                cat <<USAGE
Usage: $0 [--check|-c] [--force-prod]

  --check, -c    Verify required tooling is on PATH (CI/readiness probe).
  --force-prod   Override the prod-droplet refusal. Use only for ops break-glass.
USAGE
                exit 0
                ;;
            *)
                err "unknown argument: $1"
                exit 64
                ;;
        esac
        shift
    done

    # Prod-droplet guard. setup-server.sh provisions developer machines.
    # It must NEVER run on the prod droplet (/opt/hound), where it would stomp
    # gerrit:firepan setgid perms and register Trail of Bits plugins org-wide.
    local hostname_raw
    hostname_raw="$(hostname 2>/dev/null || true)"
    if [[ "${PWD}" == "/opt/hound"* ]] \
       || [[ "${hostname_raw}" == *"firepan"* ]] \
       || [[ "${hostname_raw}" == *"hound-prod"* ]]; then
        if (( force_prod == 0 )); then
            err "setup-server.sh refuses to run on the prod droplet."
            err "  cwd=${PWD} hostname=${hostname_raw}"
            err "  pass --force-prod only if you know what you are doing."
            exit 2
        fi
        warn "--force-prod set; proceeding on apparent prod droplet."
    fi

    if [[ "${mode}" == "check" ]]; then
        check_only
        exit $?
    fi

    log "Hound auditor-server provisioner"
    log "repo root: ${REPO_ROOT}"

    run_step "OS packages"              install_os_packages
    run_step "Python toolchain"         install_python_toolchain
    run_step "Node toolchain"           install_node_toolchain
    run_step "Rust toolchain"           install_rust_toolchain
    run_step "Foundry (Solidity)"       install_foundry
    run_step "Go-based CLI tooling"     install_go_tooling
    run_step "Hound Python deps"        install_hound_requirements
    run_step "Claude CLI + skills"      install_claude_cli_and_skills

    check_environment

    if ((${#FAILED_STEPS[@]} == 0)); then
        log "✅ setup complete — all steps succeeded"
    else
        warn "setup finished with ${#FAILED_STEPS[@]} non-fatal failures:"
        for step in "${FAILED_STEPS[@]}"; do
            warn "  - ${step}"
        done
        warn "the server may still be usable; re-run this script after"
        warn "fixing network / permission issues to converge."
    fi
}

main "$@"
