"""Claude Code hook adapter — the primary enforcement surface (doc §5, §7).

Each hook fires a fresh subprocess with event JSON on stdin; this module translates it into
:class:`Engine` calls (state lives on disk, keyed by session_id, so statelessness is fine) and
prints the response JSON on stdout. PreToolUse maps ALLOW→exit 0 (respect the user's normal
permission flow), ASK→"ask", DENY→"deny"+reason. Fail-safe: a sandbox error on PreToolUse emits
"ask", so a bug never silently disables enforcement.
"""

from __future__ import annotations

import json
import os
import sys
import time

from ddbt.core import chromatics
from ddbt.core.engine import Effect, Engine


def _load_grant(cwd: str):
    """The agent's capability ticket — the inline "policy" block in ddbt.json. Absent → no ticket.
    Loads through Grant.from_dict (nested allow/deny schema)."""
    from ddbt.core import config
    from ddbt.core.grant import Grant

    spec = config.grant_spec(cwd)
    if isinstance(spec, dict):
        try:
            return Grant.from_dict(spec, now=time.time())
        except (TypeError, ValueError, KeyError):
            return None
    return None


def _engine(payload: dict) -> Engine:
    """Build the engine for a hook invocation. The decider is the LLM step-judge (fails closed
    without a provider key); a ticket, if present, is enforced before it. Provider/model and the
    ddbt / gate_offgoal / error_effect axes all come from ddbt.json (see core/config.py)."""
    from ddbt.core import config
    from ddbt.judge.provider import make_step_judge

    from ddbt.plugins import from_config as _plugins_from_config

    session_id = payload.get("session_id", "default")
    cwd = payload.get("cwd") or "."
    return Engine(session_id, workspace_root=cwd, step_judge=make_step_judge(cwd=cwd),
                  grant=_load_grant(cwd), plugins=_plugins_from_config(cwd), **config.engine_kwargs(cwd))


# ---- attribution: make it unmistakable that DDBT (not Claude) made this call, and which layer ----
_SWATCH = {"none": "🟢", "low": "🟢", "med": "🟡", "high": "🔴"}


def _reason(d, heat: str | None = None) -> str:
    """The line Claude Code shows verbatim: the common ddbt preamble + the finding + the risk band —
    a consistent wrapper across every block/ask. Plugin findings already carry the '<detectors ·
    tactic>: We think this operation …' body; judge findings (a plain verb phrase) get the lede here."""
    from ddbt.plugins.base import finding_message, wrap_message
    body = d.reason if d.checkpoint.startswith("plugin:") else finding_message("", d.reason)
    return f"🛡 {wrap_message(body)} · {_SWATCH.get(d.risk, '')}risk:{d.risk}"


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
    if decision.effect in (Effect.ASK, Effect.ASK_OVERRIDE):
        # ASK_OVERRIDE is a would-be block a human may force — surfaced as "ask" with its loud warning.
        return _pre_output("ask", _reason(decision, heat))
    # ALLOW → stay out of the user's normal permission flow (exit 0). DDBT_VERBOSE narrates the
    # approval anyway, so you can see ddbt clearing the greens and know it's live.
    if os.environ.get("DDBT_VERBOSE"):
        print(_reason(decision, heat), file=sys.stderr)
    return {}


def handle_posttooluse(payload: dict) -> dict:
    cwd = payload.get("cwd") or "."
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    eng = _engine(payload)
    try:
        # the tool ran → quarantine its output (untrusted-by-default) so the judge can inspect
        # later steps for injected/stray behaviour.
        eng.record_result(tool_name, tool_input, payload.get("tool_response", {}) or {}, cwd=cwd)
    finally:
        eng.close()
    return {}


def handle_sessionstart(payload: dict) -> dict:
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
    eng = _engine(payload)
    try:
        context = eng.on_user_prompt(payload.get("prompt", "") or "")
    finally:
        eng.close()
    return _context_output("UserPromptSubmit", context) if context else {}


def handle_configchange(payload: dict) -> dict:
    """Continuous Boundary 0: re-verify config integrity on change. A HOLD blocks the change with
    exit 2 so a hook-injection / base-URL-redirect tamper can't take effect mid-session."""
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
