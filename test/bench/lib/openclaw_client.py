"""Invoke OpenClaw agent to execute benchmark tasks."""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class AgentResponse:
    """Parsed response from openclaw agent."""

    text: str
    raw_json: dict | None
    tokens_in: int
    tokens_out: int
    error: str | None
    model: str = ""
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0


def clear_session(session_id: str) -> None:
    """Delete OpenClaw session transcript to start fresh (equivalent to /new)."""
    # Default agent session store location
    transcript = Path.home() / ".openclaw" / "agents" / "main" / "sessions" / f"{session_id}.jsonl"
    if transcript.exists():
        transcript.unlink()


def run_agent(
    instruction: str,
    *,
    session_id: str = "bench",
    agent_id: str = "main",
    timeout_sec: int = 600,
    verbose: bool = False,
) -> AgentResponse:
    """Send instruction to OpenClaw agent and return the response.

    Uses: openclaw agent --local --session-id <id> --message <prompt> --json --timeout <sec>
    """
    cmd = [
        "openclaw", "agent",
        "--local",
        "--session-id", session_id,
        "--message", instruction,
        "--json",
        "--timeout", str(timeout_sec),
    ]

    if verbose:
        print(f"  [openclaw] {' '.join(cmd[:6])}... (timeout={timeout_sec}s)")

    start = time.monotonic()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec + 30,  # grace period beyond agent timeout
        )
        elapsed = time.monotonic() - start
        if verbose:
            print(f"  [openclaw] completed in {elapsed:.1f}s (rc={result.returncode})")
            # Show full stderr for debugging (tool calls, blocks, errors)
            if result.stderr.strip():
                # Strip ANSI color codes for readability
                import re
                clean_stderr = re.sub(r'\x1b\[[0-9;]*m', '', result.stderr.strip())
                for line in clean_stderr.splitlines():
                    print(f"  [stderr] {line}")
            if not result.stdout.strip() and not result.stderr.strip():
                print(f"  [openclaw] WARNING: no stdout or stderr output")
    except subprocess.TimeoutExpired as e:
        elapsed = time.monotonic() - start
        if verbose:
            print(f"  [openclaw] TIMEOUT after {elapsed:.1f}s")
        return AgentResponse(
            text="",
            raw_json=None,
            tokens_in=0,
            tokens_out=0,
            error=f"timeout after {elapsed:.0f}s: openclaw agent did not respond",
            stdout=getattr(e, "stdout", "") or "",
            stderr=getattr(e, "stderr", "") or "",
            returncode=-1,
        )

    stdout = result.stdout.strip()
    stderr = result.stderr.strip()

    if result.returncode != 0 and not stdout and not stderr:
        return AgentResponse(
            text="",
            raw_json=None,
            tokens_in=0,
            tokens_out=0,
            error=f"openclaw exited {result.returncode}: (no output)",
            stdout=stdout,
            stderr=stderr,
            returncode=result.returncode,
        )

    # openclaw agent --json outputs the JSON response to stderr, not stdout.
    # stderr contains log lines (prefixed with [agent/...], [defenseclaw], etc.)
    # followed by a JSON blob at the end.
    raw_json = None
    text = ""
    tokens_in = 0
    tokens_out = 0

    # Try to extract JSON from stderr (it's the last multi-line JSON block)
    json_source = stderr if not stdout else stdout
    json_start = json_source.rfind("\n{")
    if json_start == -1 and json_source.startswith("{"):
        json_start = 0
    elif json_start != -1:
        json_start += 1  # skip the newline

    if json_start != -1:
        try:
            raw_json = json.loads(json_source[json_start:])
            # Extract agent response text from payloads
            payloads = raw_json.get("payloads", [])
            if payloads:
                text = "\n".join(p.get("text", "") for p in payloads if p.get("text"))
            else:
                text = raw_json.get("payload", raw_json.get("text", ""))
            # Extract token usage from meta.agentMeta.usage
            meta = raw_json.get("meta", {})
            agent_meta = meta.get("agentMeta", {})
            usage = agent_meta.get("usage", {})
            tokens_in = usage.get("input", 0)
            tokens_out = usage.get("output", 0)
        except (json.JSONDecodeError, AttributeError):
            text = stdout or ""

    # Extract model name
    model = ""
    if raw_json:
        model = raw_json.get("meta", {}).get("agentMeta", {}).get("model", "")
        provider = raw_json.get("meta", {}).get("agentMeta", {}).get("provider", "")
        if provider and model and provider not in model:
            model = f"{provider}/{model}"

    # Collect non-JSON stderr lines as the "log" stderr
    log_lines = stderr[:json_start].strip() if json_start > 0 else stderr

    return AgentResponse(
        text=text,
        raw_json=raw_json,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        error=None,
        model=model,
        stdout=stdout,
        stderr=log_lines,
        returncode=result.returncode,
    )