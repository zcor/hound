# Hound SaaS Stack Dockerfile
FROM python:3.11-slim AS builder

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV PORT=8000

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    git \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies into a copyable prefix for the runtime image.
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Copy application code after dependencies for better caching.
COPY . .


FROM python:3.11-slim AS runner

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV PORT=8000
ENV PATH="/usr/local/bin:${PATH}"

# firepan-vff: OS-level audit toolchain. Mirrors scripts/setup-server.sh
# check_only requirements (python3, node, claude, git, slither, forge, semgrep,
# rg) so SingleAuditor in mode=auditor has the same tools available in prod as
# the dev provisioner installs. python3 already ships with the base image;
# slither/semgrep via pip; foundry + claude installed separately below.
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    libpq5 \
    curl \
    ca-certificates \
    ripgrep \
    build-essential \
 && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && pip install --no-cache-dir slither-analyzer semgrep \
 && rm -rf /var/lib/apt/lists/*

# Foundry (forge/cast/anvil) — install as root so binaries land in /usr/local/bin.
# Best-effort: foundryup network failures shouldn't break the image build.
RUN curl -L https://foundry.paradigm.xyz | bash || true \
 && /root/.foundry/bin/foundryup || true \
 && (cp /root/.foundry/bin/forge /usr/local/bin/ 2>/dev/null || true) \
 && (cp /root/.foundry/bin/cast /usr/local/bin/ 2>/dev/null || true) \
 && (cp /root/.foundry/bin/anvil /usr/local/bin/ 2>/dev/null || true)

# firepan-a1 — solc binaries for the verify-mode MVE generation loop.
# Forge uses its own ~/.svm cache (NOT solc-select's path), so we install
# via solc-select but then copy the binaries into the forge-expected
# location. Without this, every forge test invocation in the worker
# (which runs as user `hound`) failed at compile-time before the EVM ran.
# Verified live: forge's svm dir is /home/hound/.svm/<VERSION>/solc-<VERSION>.
RUN pip install --no-cache-dir solc-select \
 && solc-select install 0.7.6 0.8.20 \
 && solc-select use 0.8.20 \
 && ln -sf /root/.solc-select/artifacts/solc-0.8.20/solc-0.8.20 /usr/local/bin/solc \
 && mkdir -p /home/hound/.svm/0.8.20 /home/hound/.svm/0.7.6 \
 && cp /root/.solc-select/artifacts/solc-0.8.20/solc-0.8.20 /home/hound/.svm/0.8.20/solc-0.8.20 \
 && cp /root/.solc-select/artifacts/solc-0.7.6/solc-0.7.6 /home/hound/.svm/0.7.6/solc-0.7.6 \
 && chmod +x /home/hound/.svm/0.8.20/solc-0.8.20 /home/hound/.svm/0.7.6/solc-0.7.6
# NOTE: the in-stanza `chown -R hound:hound /home/hound/.svm` that used to
# live here ran BEFORE the `useradd hound` below — chown failed with
# "invalid user: hound:hound" and broke every CI image build from
# 2026-05-23 onward (5 consecutive Publish Docker Images runs).
# Ownership is set by the broader `chown -R hound:hound /app /home/hound`
# in the useradd block below, which recursively covers /home/hound/.svm.

# Claude Code CLI as root → ends up on /usr/local/bin, available to USER hound.
RUN npm install -g @anthropic-ai/claude-code

WORKDIR /app

COPY --from=builder /install /usr/local
COPY --from=builder /app /app

# hound user creation. Mirrors setup-server.sh: skills go under
# /home/hound/.claude/skills/; settings live in both /app/.claude (REPO_ROOT)
# and /home/hound/.claude (HOME) so CLI sessions inherit them whether invoked
# from /app or from the worker shell.
RUN useradd --create-home --shell /bin/bash hound \
 && mkdir -p /home/hound/.hound /home/hound/.claude/skills /app/.claude \
 && chown -R hound:hound /app /home/hound

# Mirror PR-A's .claude/settings.json into the home dir if it landed in the
# source tree (PR-A merged on feature/surface-scan). Soft-fail otherwise.
RUN if [ -f /app/.claude/settings.json ]; then \
        cp /app/.claude/settings.json /home/hound/.claude/settings.json && \
        chown hound:hound /home/hound/.claude/settings.json ; \
    else \
        echo "WARNING: /app/.claude/settings.json not present (PR-A not merged?)" ; \
    fi

USER hound

# Trail of Bits plugin marketplace + plugins. Best-effort (network failures
# don't break the image; SingleAuditor's fp-check runs natively, the ToB
# plugin is only a secondary cross-check).
# NOTE: must use the explicit HTTPS URL. `claude plugin marketplace add
# trailofbits/claude-code-plugins` (the short owner/repo form) resolves to an
# SSH git URL, which fails in-container (no SSH keys, ssh not installed).
RUN claude plugin marketplace add https://github.com/trailofbits/claude-code-plugins.git || true \
 && for p in fp-check audit-context-building spec-to-code-compliance \
             building-secure-contracts variant-analysis differential-review \
             semgrep-rule-creator semgrep-rule-variant-creator static-analysis \
             dimensional-analysis constant-time-analysis supply-chain-risk-auditor \
             mutation-testing property-based-testing second-opinion zeroize-audit \
             entry-point-analyzer insecure-defaults sharp-edges fix-review \
             workflow-skill-design ; do \
        claude plugin install "${p}@trailofbits" || true ; \
    done

# Pashov skills + claude-wiki under /home/hound/.claude/skills (mirrors
# setup-server.sh:347-376). Best-effort.
RUN git clone --depth 1 https://github.com/pashov/skills.git /home/hound/.claude/skills/pashov-skills || true
RUN git clone --depth 1 https://github.com/giovani-junior-dev/claude-wiki.git /home/hound/.claude/skills/claude-wiki || true

EXPOSE ${PORT}

CMD uvicorn server.api:app --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips='*'
