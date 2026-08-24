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
import time
from pathlib import Path

from ddbt.core import chromatics
from ddbt.core.engine import Effect, Engine


def _load_grant(cwd: str):
    """The agent's capability ticket, if the user authored one. Looked up at
    ``<project>/.ddbt/grant.json`` first, then ``~/.ddbt/grant.json``. Absent → no ticket
    (the judge alone bounds the agent, exactly as before this file learned about grants)."""
    from ddbt.core.grant import Grant

    for p in (Path(cwd) / ".ddbt" / "grant.json", Path.home() / ".ddbt" / "grant.json"):
        try:
            if p.is_file():
                return Grant.from_dict(json.loads(p.read_text()), now=time.time())
        except (OSError, json.JSONDecodeError):
            continue
    return None


def _engine(payload: dict) -> Engine:
    """Build the engine for a hook invocation. The v4 decider is the LLM step-judge, so a
    provider key is required; the judge fails CLOSED (deny) without one — that's the
    judge-centric design (strict). Model overridable via DDBT_JUDGE_MODEL. A capability
    ticket from .ddbt/grant.json, if present, is enforced deterministically before the judge."""
    session_id = payload.get("session_id", "default")
    cwd = payload.get("cwd") or "."
    from ddbt.judge.provider import make_step_judge

    judge = make_step_judge()
    # gate_offgoal=True: interactive use should GATE a benign off-goal step (ask the human),
    # not brick the task with a hard deny. Injection-linked deviation still hard-denies.
    return Engine(session_id, workspace_root=cwd, step_judge=judge, grant=_load_grant(cwd),
                  gate_offgoal=True)


# ---- attribution: make it unmistakable that DDBT (not Claude) made this call, and which layer ----
_SWATCH = {"none": "🟢", "low": "🟢", "med": "🟡", "high": "🔴"}


def _layer(checkpoint: str) -> str:
    return "ticket" if checkpoint in ("out-of-scope", "grant-fastpath") else "judge"


def _reason(d, heat: str | None = None) -> str:
    """One line Claude Code shows verbatim — carries the 🛡 DDBT marker, the layer that decided
    (ticket vs judge), the chromatic risk band, the session heat, and the human reason. This is
    how a user tells a DDBT block apart from Claude declining on its own."""
    heat_bit = f" · heat:{heat}" if heat else ""
    return (f"🛡 DDBT · {d.state.upper()} · via {_layer(d.checkpoint)} "
            f"[{d.checkpoint}] {_SWATCH.get(d.risk, '')} risk:{d.risk}{heat_bit} — {d.reason}")


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
        heat = chromatics.heat_state(eng._suspicion())[0]
    finally:
        eng.close()

    if decision.effect == Effect.DENY:
        return _pre_output("deny", _reason(decision, heat))
    if decision.effect == Effect.ASK:
        return _pre_output("ask", _reason(decision, heat))
    # ALLOW → stay out of the user's normal permission flow (exit 0, no decision). With
    # DDBT_VERBOSE set, still narrate the approval so you can SEE ddbt clearing the greens —
    # it's how you know ddbt is live and that a passed step was ddbt-approved, not unseen.
    if os.environ.get("DDBT_VERBOSE"):
        print(_reason(decision, heat), file=sys.stderr)
    return {}


def handle_posttooluse(payload: dict) -> dict:
    session_id = payload.get("session_id", "default")
    cwd = payload.get("cwd") or "."
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    eng = _engine(payload)
    try:
        # the tool RAN → quarantine its output (untrusted-by-default) so the judge can
        # inspect later steps for injected/stray behaviour. v4 has no envelope to "widen":
        # a gated (ASK) action that ran was human-approved, and that's recorded by the
        # PreToolUse decision already; nothing more to confirm here.
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
