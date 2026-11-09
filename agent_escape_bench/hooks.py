"""Discovering and calling shell-command hooks of coding agents.

Supported protocols:

* claude - Claude Code PreToolUse hooks. Exit code 2 blocks the call. Exit code 0 with
  JSON on stdout can return hookSpecificOutput.permissionDecision (allow, deny, ask)
  or the legacy "decision": "block" | "approve". Any other exit code is a
  non-blocking error in Claude Code, so the bench counts it as allow and reports it.
* cursor - Cursor beforeShellExecution hooks. JSON on stdout with
  "permission": "allow" | "deny" | "ask"; "continue": false stops the command.
  Only the JSON answer is honored; a non-zero exit without JSON is reported as an error.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

RANK = {"allow": 0, "ask": 1, "deny": 2}


@dataclass
class Hook:
    command: str
    protocol: str = "claude"  # claude | cursor
    source: str = "--hook"
    timeout: float = 30.0
    env: dict = field(default_factory=dict)
    cwd: str | None = None  # relative to the fixture root unless absolute
    fail_closed: bool = False  # Claude Code "onFailure": "block"
    matcher: str | None = None  # PreToolUse matcher; None means every tool (Cursor shell hooks: shell only)

    def applies(self, tool: str) -> bool:
        if self.protocol == "cursor":
            return tool == "Bash"
        return _matcher_hits(self.matcher, tool)


@dataclass
class Answer:
    decision: str  # allow | ask | deny
    error: str = ""
    reason: str = ""


def _matcher_hits(matcher: str | None, tool: str = "Bash") -> bool:
    if matcher in (None, "", "*"):
        return True
    try:
        return re.fullmatch(matcher, tool) is not None or re.search(rf"(^|\|){re.escape(tool)}($|\|)", matcher) is not None
    except re.error:
        return tool in matcher


def _claude_entries(hooks_obj: dict, source: str, env: dict | None = None, tool: str | None = "Bash") -> list[Hook]:
    """PreToolUse command hooks. tool="Bash" keeps the hooks that see shell commands; tool=None keeps all."""
    out = []
    for entry in (hooks_obj or {}).get("PreToolUse", []) or []:
        if tool is not None and not _matcher_hits(entry.get("matcher"), tool):
            continue
        for h in entry.get("hooks", []) or []:
            if h.get("type", "command") == "command" and h.get("command"):
                out.append(Hook(h["command"], "claude", source, float(h.get("timeout", 30)), dict(env or {}),
                                fail_closed=str(h.get("onFailure", "")).lower() == "block",
                                matcher=entry.get("matcher")))
    return out


def discover_claude(repo: Path, user_settings: bool = False, tool: str | None = "Bash") -> list[Hook]:
    files = [repo / ".claude" / "settings.json", repo / ".claude" / "settings.local.json"]
    if user_settings:
        files.append(Path.home() / ".claude" / "settings.json")
    hooks = []
    for f in files:
        if f.is_file():
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
            except ValueError as exc:
                raise SystemExit(f"cannot parse {f}: {exc}")
            hooks += _claude_entries(data.get("hooks") or {}, str(f), tool=tool)
    return hooks


def discover_plugin(plugin: Path, tool: str | None = "Bash") -> list[Hook]:
    f = plugin / "hooks" / "hooks.json"
    if not f.is_file():
        raise SystemExit(f"no hooks/hooks.json in {plugin}")
    data = json.loads(f.read_text(encoding="utf-8"))
    return _claude_entries(data.get("hooks") or {}, str(f), {"CLAUDE_PLUGIN_ROOT": str(plugin.resolve())}, tool)


def discover_cursor(repo: Path, user_settings: bool = False) -> list[Hook]:
    files = [repo / ".cursor" / "hooks.json"]
    if user_settings:
        files.append(Path.home() / ".cursor" / "hooks.json")
    hooks = []
    for f in files:
        if not f.is_file():
            continue
        data = json.loads(f.read_text(encoding="utf-8"))
        for h in (data.get("hooks") or {}).get("beforeShellExecution", []) or []:
            if h.get("command"):
                # Cursor resolves hook commands relative to the hooks.json that defines them.
                cwd = ".cursor" if f.parent == repo / ".cursor" else str(f.parent)
                hooks.append(Hook(h["command"], "cursor", str(f), float(h.get("timeout", 30)), cwd=cwd))
    return hooks


def payload(protocol: str, command: str, root: Path, session: str, n: int,
            tool: str = "Bash", tool_input: dict | None = None) -> dict:
    if protocol == "cursor":
        return {"conversation_id": session, "generation_id": f"{session}-{n}", "command": command,
                "cwd": str(root), "hook_event_name": "beforeShellExecution", "workspace_roots": [str(root)]}
    return {"session_id": session, "transcript_path": str(root / ".aeb-transcript.jsonl"), "cwd": str(root),
            "permission_mode": "default", "hook_event_name": "PreToolUse", "tool_name": tool,
            "tool_input": tool_input if tool_input is not None else {"command": command, "description": "agent-escape-bench case"}}


def parse(protocol: str, code: int, stdout: str, stderr: str) -> Answer:
    data = None
    text = stdout.strip()
    if text:
        try:
            data = json.loads(text)
        except ValueError:
            # Some hooks print logs before the JSON object: take the last JSON line.
            for line in reversed(text.splitlines()):
                try:
                    data = json.loads(line)
                    break
                except ValueError:
                    continue
    if protocol == "cursor":
        if isinstance(data, dict):
            if data.get("continue") is False:
                return Answer("deny", reason=str(data.get("userMessage") or data.get("agentMessage") or ""))
            perm = str(data.get("permission") or "").lower()
            if perm in RANK:
                return Answer(perm, reason=str(data.get("userMessage") or data.get("agentMessage") or ""))
        if code != 0:
            return Answer("allow", error=f"exit {code} without a permission answer: {stderr.strip()[:200]}")
        return Answer("allow")
    if code == 2:
        return Answer("deny", reason=stderr.strip()[:300])
    if code != 0:
        return Answer("allow", error=f"exit {code} is non-blocking in Claude Code: {stderr.strip()[:200]}")
    if isinstance(data, dict):
        spec = data.get("hookSpecificOutput") or {}
        dec = str(spec.get("permissionDecision") or "").lower()
        if dec in RANK:
            return Answer(dec, reason=str(spec.get("permissionDecisionReason") or ""))
        legacy = str(data.get("decision") or "").lower()
        if legacy == "block":
            return Answer("deny", reason=str(data.get("reason") or ""))
        if legacy == "approve":
            return Answer("allow")
        if data.get("continue") is False:
            return Answer("deny", reason=str(data.get("stopReason") or ""))
    return Answer("allow")


def call(hook: Hook, command: str, fixture, session: str, n: int,
         tool: str = "Bash", tool_input: dict | None = None) -> Answer:
    """Ask one hook about one tool call. For Bash, command is the shell command; other tools pass tool_input."""
    body = json.dumps(payload(hook.protocol, command, fixture.root, session, n, tool, tool_input))
    cwd = fixture.root if not hook.cwd else (Path(hook.cwd) if os.path.isabs(hook.cwd) else fixture.root / hook.cwd)
    try:
        proc = subprocess.run(hook.command, shell=True, input=body, capture_output=True, text=True,
                              cwd=cwd, env=fixture.env(hook.env), timeout=hook.timeout)
    except subprocess.TimeoutExpired:
        # A timed-out hook is a non-blocking error unless the hook is configured to fail closed.
        return Answer("deny" if hook.fail_closed else "allow", error=f"timeout after {hook.timeout:.0f}s")
    answer = parse(hook.protocol, proc.returncode, proc.stdout, proc.stderr)
    if answer.error and hook.fail_closed:
        return Answer("deny", error=answer.error + " (onFailure: block)")
    return answer


def combine(answers: list[Answer]) -> Answer:
    if not answers:
        return Answer("allow")
    best = max(answers, key=lambda a: RANK[a.decision])
    errors = "; ".join(a.error for a in answers if a.error)
    return Answer(best.decision, errors, best.reason)
