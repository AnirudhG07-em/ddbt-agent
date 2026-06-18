"""Claude Code hook adapter — the primary enforcement surface (doc §5, §7).

Each Claude Code hook fires a fresh subprocess with an event JSON on stdin. This
module translates that JSON into :class:`Engine` calls and emits the hook's response
JSON on stdout. The engine (keyed by ``session_id``) holds all state on disk, so the
stateless subprocess model is fine.

Mapping (PreToolUse):
  Effect.ALLOW → exit 0, no decision   (respect the user's normal permission flow)
  Effect.ASK   → permissionDecision "ask"
  Effect.DENY  → permissionDecision "deny" + reason  (the agent sees why)

Fail-safe: if the sandbox itself errors on a PreToolUse, we emit "ask" (neither a
silent allow nor a hard block) so a bug never silently disables enforcement.
"""

from __future__ import annotations

import json
import os
import sys

from ddbt.core.engine import Effect, Engine


def _engine(payload: dict) -> Engine:
    """Build the engine for a hook invocation, attaching the blind intent judge when
    DDBT_INTENT_JUDGE is set AND a key is present. If enabled but no key, we fall back to
    deterministic (rather than fail-closed-DENY on every judgeable action — safer UX)."""
    session_id = payload.get("session_id", "default")
    cwd = payload.get("cwd") or "."
    intent_judge = None
    if os.environ.get("DDBT_INTENT_JUDGE") and os.environ.get("ANTHROPIC_API_KEY"):
        from ddbt.judge.intent import AnthropicIntentJudge

        intent_judge = AnthropicIntentJudge(os.environ.get("DDBT_INTENT_MODEL", "claude-haiku-4-5"))
    return Engine(session_id, workspace_root=cwd, intent_judge=intent_judge)


def _pre_output(decision: str, reason: str = "") -> dict:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }


def _context_output(event: str, context: str) -> dict:
    return {"hookSpecificOutput": {"hookEventName": event, "additionalContext": context}}


def handle_pretooluse(payload: dict) -> dict:
    session_id = payload.get("session_id", "default")
    cwd = payload.get("cwd") or "."
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}

    eng = _engine(payload)
    try:
        decision = eng.evaluate_action(tool_name, tool_input, cwd=cwd)
    finally:
        eng.close()

    if decision.effect == Effect.DENY:
        return _pre_output("deny", f"[ddbt/{decision.checkpoint}] {decision.reason}")
    if decision.effect == Effect.ASK:
        return _pre_output("ask", f"[ddbt/{decision.checkpoint}] {decision.reason}")
    return {}  # ALLOW → no objection, exit 0


def handle_posttooluse(payload: dict) -> dict:
    session_id = payload.get("session_id", "default")
    cwd = payload.get("cwd") or "."
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    eng = _engine(payload)
    try:
        # the tool RAN, so a gated (ASK) action was human-approved → confirm + widen
        eng.confirm_from_result(tool_name, tool_input, cwd=cwd)
        eng.record_result(tool_name, tool_input, payload.get("tool_response", {}) or {}, cwd=cwd)
    finally:
        eng.close()
    return {}


def handle_sessionstart(payload: dict) -> dict:
    session_id = payload.get("session_id", "default")
    cwd = payload.get("cwd") or "."
    source = payload.get("source", "startup")
    eng = _engine(payload)
    try:
        result = eng.on_session_start(source, cwd)
    finally:
        eng.close()
    if not result.ok:
        return _context_output(
            "SessionStart",
            f"[ddbt] Boundary 0 HOLD — config/MCP integrity check failed:\n{result.summary()}",
        )
    return {}


def handle_userpromptsubmit(payload: dict) -> dict:
    session_id = payload.get("session_id", "default")
    cwd = payload.get("cwd") or "."
    eng = _engine(payload)
    try:
        context = eng.on_user_prompt(payload.get("prompt", "") or "")
    finally:
        eng.close()
    return _context_output("UserPromptSubmit", context) if context else {}


def handle_configchange(payload: dict) -> dict:
    """Continuous Boundary 0: re-verify config integrity when it changes mid-session.

    A HOLD here blocks the change with exit 2 (the documented ConfigChange block path)
    so a hook-injection / base-URL-redirect tamper can't take effect.
    """
    session_id = payload.get("session_id", "default")
    cwd = payload.get("cwd") or "."
    eng = _engine(payload)
    try:
        result = eng.verify_config(cwd)
    finally:
        eng.close()
    if not result.ok:
        return {"_exit": 2, "_stderr": f"[ddbt] Boundary 0 HOLD — config change rejected:\n{result.summary()}"}
    return {}


def handle_stop(payload: dict) -> dict:
    session_id = payload.get("session_id", "default")
    cwd = payload.get("cwd") or "."
    eng = _engine(payload)
    try:
        result = eng.commit_batch()
    finally:
        eng.close()
    if not result.ok:
        return _context_output("Stop", f"[ddbt] {result.summary()}")
    return {}


_HANDLERS = {
    "PreToolUse": handle_pretooluse,
    "PostToolUse": handle_posttooluse,
    "SessionStart": handle_sessionstart,
    "UserPromptSubmit": handle_userpromptsubmit,
    "Stop": handle_stop,
    "ConfigChange": handle_configchange,
    "FileChanged": handle_configchange,  # same verification on watched-file change
}


def dispatch(event: str, raw_stdin: str) -> int:
    """Parse the event payload, run the handler, print response JSON. Returns exit code."""
    try:
        payload = json.loads(raw_stdin) if raw_stdin.strip() else {}
    except json.JSONDecodeError:
        payload = {}

    handler = _HANDLERS.get(event)
    if handler is None:
        return 0  # unknown event → no objection

    try:
        output = handler(payload)
    except Exception as exc:  # fail-safe (see module docstring)
        if event == "PreToolUse":
            print(json.dumps(_pre_output("ask", f"[ddbt] sandbox error, deferring to human: {exc}")))
        else:
            print(f"[ddbt] hook error on {event}: {exc}", file=sys.stderr)
        return 0

    # a handler may request a blocking exit (e.g. ConfigChange HOLD → exit 2 + stderr)
    if output and "_exit" in output:
        if output.get("_stderr"):
            print(output["_stderr"], file=sys.stderr)
        return int(output["_exit"])
    if output:
        print(json.dumps(output))
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    event = argv[0] if argv else ""
    return dispatch(event, sys.stdin.read())


if __name__ == "__main__":
    raise SystemExit(main())
