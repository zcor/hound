"""Claude Code CLI orchestration layer.

Spawns ``claude -p`` (print-mode) subprocesses to run autonomous audit
sessions where Claude Code has **full tool access** — file operations,
bash execution, Slither, Foundry, Trail of Bits plugins, and Pashov skills.

This is the core differentiator: instead of using Claude as a dumb
text-in/JSON-out API, we give it a real toolbox and let it *do* the audit.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Hard cap on stdout we'll attempt to JSON-parse (DoS guard).
_MAX_JSON_BYTES = 4 * 1024 * 1024  # 4 MiB

# Patterns scrubbed from any subprocess stderr/stdout we log.  The provider
# error paths frequently echo the offending API key verbatim; truncating
# stderr is not the same thing as redacting it.
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"sk-[A-Za-z0-9]{32,}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{20,}"),  # Google API keys
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),     # GitHub PATs
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
)


def _scrub(text: str) -> str:
    """Replace likely-secret substrings with ``<redacted>`` for logging."""
    if not text:
        return text
    for pat in _SECRET_PATTERNS:
        text = pat.sub("<redacted>", text)
    return text


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------

@dataclass
class ClaudeResult:
    """Parsed result from a Claude Code CLI session."""

    text: str = ""
    cost_usd: float = 0.0
    num_turns: int = 0
    duration_ms: int = 0
    session_id: str = ""
    is_error: bool = False
    raw_json: dict[str, Any] = field(default_factory=dict)

    # Convenience: extract a JSON object from the result text.
    def extract_json(self, *, fence: str = "```json") -> dict | list | None:
        """Pull the *first* fenced JSON block from ``self.text``.

        Falls back to parsing the entire text as JSON if no fence is found.
        """
        text = self.text
        if fence in text:
            start = text.index(fence) + len(fence)
            # Find the closing fence
            end = text.find("```", start)
            if end != -1:
                text = text[start:end].strip()
            else:
                text = text[start:].strip()
        else:
            # Try the whole thing as JSON (Claude sometimes omits fences)
            text = text.strip()
            # Strip leading prose before the JSON
            for marker in ("{", "["):
                idx = text.find(marker)
                if idx != -1:
                    text = text[idx:]
                    break

        try:
            return json.loads(text)
        except (json.JSONDecodeError, ValueError) as exc:
            logger.debug("extract_json: failed to parse Claude CLI output: %s", exc)
            return None

    def __post_init__(self) -> None:  # pragma: no cover - trivial
        # Defensive cap on the text payload we'll later parse as JSON.
        if self.text and len(self.text) > _MAX_JSON_BYTES:
            logger.warning(
                "Claude CLI text payload %.1f MiB exceeds %.1f MiB cap; truncating before parse",
                len(self.text) / 1_048_576,
                _MAX_JSON_BYTES / 1_048_576,
            )
            self.text = self.text[:_MAX_JSON_BYTES]


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

class ClaudeSession:
    """Manages a single Claude Code CLI session.

    Typical usage::

        session = ClaudeSession(
            config=cfg,
            working_dir=Path("/data/projects/abc/repo"),
        )
        result = session.run(
            prompt="Audit the following files for vulnerabilities ...",
            system_prompt=AUDITOR_SYSTEM,
        )
        findings = result.extract_json()
    """

    def __init__(
        self,
        config: dict[str, Any],
        working_dir: Path,
        *,
        session_id: str = "",
    ):
        self.config = config
        self.working_dir = Path(working_dir)
        self.session_id = session_id

        # Claude CLI settings — pulled from config['claude_cli'] if present
        cli_cfg = config.get("claude_cli", {})
        self.claude_path: str = cli_cfg.get("path", "claude")
        self.max_turns: int = cli_cfg.get("max_turns", 50)
        self.timeout: int = cli_cfg.get("timeout", 900)  # 15 min default
        self.skip_permissions: bool = cli_cfg.get("skip_permissions", True)

        # Model: prefer claude_cli.model → auditor profile model → None (let CLI default)
        self.model: str | None = (
            cli_cfg.get("model")
            or config.get("models", {}).get("auditor", {}).get("model")
        )

        # Allowed tools — None means "all"; list restricts to named tools
        self.allowed_tools: list[str] | None = cli_cfg.get("allowed_tools")

        # MCP server configuration file — passed via --mcp-config when set.
        # Validate the file exists and is regular before forwarding to the
        # CLI: a stale config path produces a confusing CLI error and a
        # missing file silently disables tool access for the whole audit.
        mcp_raw = cli_cfg.get("mcp_config")
        self.mcp_config: str | None = None
        if mcp_raw:
            mcp_path = Path(mcp_raw).expanduser()
            if mcp_path.is_file():
                self.mcp_config = str(mcp_path.resolve())
            else:
                logger.warning(
                    "claude_cli.mcp_config %r does not exist; ignoring",
                    str(mcp_raw),
                )

        # Extra environment variables to pass to the subprocess.
        #
        # firepan-vff: the claude CLI prefers ANTHROPIC_API_KEY over
        # CLAUDE_CODE_OAUTH_TOKEN when BOTH are set — even if the API key is
        # bogus (a placeholder, an expired key). The hound stack sets
        # ANTHROPIC_API_KEY for non-auditor curation paths, so when running
        # mode=auditor against a Claude subscription we must NOT forward
        # ANTHROPIC_API_KEY to the claude subprocess: if we do, claude 401s on
        # every call. When CLAUDE_CODE_OAUTH_TOKEN is present, forward that
        # (and the foundry RPC vars) but explicitly drop ANTHROPIC_API_KEY.
        self._extra_env: dict[str, str] = {}
        oauth_token = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN")
        self._drop_anthropic_api_key = bool(oauth_token)
        forward_keys = ["ETH_RPC_URL", "ETHERSCAN_API_KEY"]
        if oauth_token:
            self._extra_env["CLAUDE_CODE_OAUTH_TOKEN"] = oauth_token
        else:
            forward_keys.insert(0, "ANTHROPIC_API_KEY")
        for key in forward_keys:
            val = os.environ.get(key)
            if val:
                self._extra_env[key] = val

    # ---- capability check -------------------------------------------------

    @classmethod
    def available(cls) -> bool:
        """Return *True* if the ``claude`` CLI is on ``$PATH``."""
        return shutil.which("claude") is not None

    # ---- run a prompt -----------------------------------------------------

    def run(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
        max_turns: int | None = None,
        timeout: int | None = None,
        output_json: bool = True,
    ) -> ClaudeResult:
        """Execute a prompt through ``claude -p`` and return the parsed result.

        Parameters
        ----------
        prompt:
            The user prompt.  For large prompts this is piped via stdin.
        system_prompt:
            Optional system prompt prepended to the session.
        max_turns:
            Override the default max-turns for this invocation.
        timeout:
            Override the default timeout (seconds) for this invocation.
        output_json:
            If *True*, request ``--output-format json`` so we get structured
            metadata alongside the result text.
        """
        cmd = self._build_command(
            system_prompt=system_prompt,
            max_turns=max_turns or self.max_turns,
            output_json=output_json,
        )

        env = {**os.environ, **self._extra_env}
        if self._drop_anthropic_api_key:
            # See __init__ comment: claude prefers a (possibly bogus)
            # ANTHROPIC_API_KEY over the OAuth token. Strip it so the
            # subscription token wins.
            env.pop("ANTHROPIC_API_KEY", None)
        effective_timeout = timeout or self.timeout

        logger.info(
            "Claude CLI session: cwd=%s max_turns=%d timeout=%ds model=%s",
            self.working_dir,
            max_turns or self.max_turns,
            effective_timeout,
            self.model or "(default)",
        )

        try:
            proc = subprocess.run(
                cmd,
                input=prompt,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                cwd=str(self.working_dir),
                env=env,
            )
        except subprocess.TimeoutExpired:
            logger.error("Claude CLI session timed out after %ds", effective_timeout)
            return ClaudeResult(
                text="",
                is_error=True,
                raw_json={"error": "timeout", "timeout_seconds": effective_timeout},
            )
        except FileNotFoundError:
            logger.error("Claude CLI not found at '%s'", self.claude_path)
            return ClaudeResult(
                text="",
                is_error=True,
                raw_json={"error": "not_found", "path": self.claude_path},
            )
        except PermissionError as exc:
            logger.error("Claude CLI not executable at '%s': %s", self.claude_path, exc)
            return ClaudeResult(
                text="",
                is_error=True,
                raw_json={"error": "permission_denied", "path": self.claude_path},
            )
        except OSError as exc:
            # Covers BrokenPipeError, ChildProcessError, etc.
            logger.error("Claude CLI subprocess OS error: %s", exc)
            return ClaudeResult(
                text="",
                is_error=True,
                raw_json={"error": "os_error", "detail": str(exc)},
            )

        if proc.returncode != 0:
            # Some Claude CLI failure modes write the diagnostic to stdout
            # (e.g. JSON error envelopes) rather than stderr, so include both
            # streams in the warning to make these exits actionable.
            stderr_snippet = _scrub(proc.stderr[:500]) if proc.stderr else ""
            stdout_snippet = _scrub(proc.stdout[:500]) if proc.stdout else ""
            detail = stderr_snippet or stdout_snippet or "(no output)"
            source = "stderr" if stderr_snippet else ("stdout" if stdout_snippet else "none")
            logger.warning(
                "Claude CLI exited %d (%s): %s",
                proc.returncode,
                source,
                detail,
            )

        return self._parse_output(proc.stdout, proc.stderr, proc.returncode, output_json)

    # ---- internals --------------------------------------------------------

    def _build_command(
        self,
        *,
        system_prompt: str | None,
        max_turns: int,
        output_json: bool,
    ) -> list[str]:
        cmd = [self.claude_path, "-p"]

        if system_prompt:
            cmd.extend(["--system-prompt", system_prompt])

        if self.model:
            cmd.extend(["--model", self.model])

        cmd.extend(["--max-turns", str(max_turns)])

        if output_json:
            cmd.extend(["--output-format", "json"])

        if self.skip_permissions:
            cmd.append("--dangerously-skip-permissions")

        if self.allowed_tools:
            cmd.extend(["--allowedTools", ",".join(self.allowed_tools)])

        if self.mcp_config:
            cmd.extend(["--mcp-config", self.mcp_config])

        return cmd

    @staticmethod
    def _parse_output(
        stdout: str,
        stderr: str,
        returncode: int,
        output_json: bool,
    ) -> ClaudeResult:
        """Parse Claude CLI output into a ``ClaudeResult``."""
        if not stdout.strip():
            if stderr:
                logger.warning("Claude CLI produced no stdout; stderr: %s", _scrub(stderr[:500]))
            return ClaudeResult(
                text="",
                is_error=returncode != 0,
                raw_json={"stderr": stderr[:2000]} if stderr else {},
            )

        if output_json:
            try:
                data = json.loads(stdout)
                return ClaudeResult(
                    text=data.get("result", ""),
                    cost_usd=data.get("cost_usd", 0.0),
                    num_turns=data.get("num_turns", 0),
                    duration_ms=data.get("duration_ms", 0),
                    session_id=data.get("session_id", ""),
                    is_error=data.get("is_error", False),
                    raw_json=data,
                )
            except (json.JSONDecodeError, ValueError):
                # JSON parsing failed — treat stdout as plain text
                logger.warning("Claude CLI output was not valid JSON, treating as plain text")
                return ClaudeResult(
                    text=stdout,
                    is_error=returncode != 0,
                )

        return ClaudeResult(
            text=stdout,
            is_error=returncode != 0,
        )
