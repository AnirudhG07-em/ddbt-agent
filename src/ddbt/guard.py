"""Guard — the one-call way to put ddbt in front of ANY agent or tool loop.

Wiring an Engine (judge + capability ticket + plugins + config axes) is boilerplate the Claude Code
hook does internally. `Guard` does exactly that wiring from a project's ddbt.json, so any integration
is three lines:

    from ddbt import Guard

    guard = Guard(session_id="my-agent", cwd=".")   # loads judge + plugins + policy from ddbt.json
    guard.goal(user_message)                        # the trusted task (anchors relevance)
    for tool, args in agent_steps:
        d = guard.check(tool, args)                 # -> Decision (allow / ask / deny + reason)
        if d.denied:                 refuse(d.reason)
        elif d.asked:                if not human_confirms(d.reason): continue
        result = run(tool, args)
        guard.record(tool, args, result)            # feeds the cross-step trajectory view

Everything is overridable — pass your own judge / plugins / grant to bypass config. Also a context
manager: `with Guard(...) as g: ...`. Runtime is LLM-free by default (the sift judge); the LLM judge
is a flagged fallback (ddbt.json "judge": "llm").
"""

from __future__ import annotations

import time

from ddbt.core.engine import Decision, Engine


def _grant_from_config(cwd: str):
    """The capability ticket from ddbt.json's inline "policy" block, or None."""
    from ddbt.core import config
    from ddbt.core.grant import Grant

    spec = config.grant_spec(cwd)
    if isinstance(spec, dict):
        try:
            return Grant.from_dict(spec, now=time.time())
        except (TypeError, ValueError, KeyError):
            return None
    return None


class Guard:
    """A ready-to-use ddbt guard for one agent session. Build once, then check()/record() each step."""

    def __init__(self, session_id: str = "default", cwd: str = ".", *, judge=None, plugins=None,
                 grant: object = "auto", base_dir: str | None = None, **engine_kwargs):
        from ddbt.core import config
        cwd = str(cwd)
        if judge is None:
            from ddbt.judge.provider import make_step_judge
            judge = make_step_judge(cwd=cwd)
        if plugins is None:
            from ddbt.plugins import from_config
            plugins = from_config(cwd)
        if grant == "auto":
            grant = _grant_from_config(cwd)
        kw = {**config.engine_kwargs(cwd), **engine_kwargs}
        self.engine = Engine(session_id, workspace_root=cwd, base_dir=base_dir, step_judge=judge,
                             grant=grant, plugins=plugins, **kw)

    def goal(self, prompt: str) -> str:
        """Set the trusted task for this session (a user message). Returns a note if a prior step was
        blocked. Call whenever the user speaks — it anchors what counts as on-goal."""
        return self.engine.on_user_prompt(prompt)

    def check(self, tool: str, args: dict | None = None) -> Decision:
        """Judge a proposed tool call BEFORE it runs. Returns a Decision — use d.allowed/asked/denied."""
        return self.engine.evaluate_action(tool, args or {})

    def record(self, tool: str, args: dict | None = None, result: object = None) -> None:
        """Feed a completed step's result back in (quarantine + provenance + the trajectory ledger).
        Call after a step actually runs, so cross-step detectors see the real history."""
        self.engine.record_result(tool, args or {}, result or {})

    def screen(self, text: str):
        """Screen tool OUTPUT (or any text) for secrets/PII BEFORE the LLM sees it. Returns a Screen —
        use s.redacted (safe to show the model) and s.effect ('ask' if sensitive). For the shell case:
        run `cat .env`, then `guard.screen(output)` so the raw secret never enters the model's context."""
        from ddbt.screen import screen_text
        return screen_text(text)

    def risk(self) -> dict:
        """The session's current heat, as a simple dict — `{'suspicion', 'strictness', 'level'}` where
        level is 'normal' | 'elevated' | 'locked'. Rises only from confirmed evidence (blocked steps,
        corroborated signals); never lowers except on `ddbt clear`."""
        suspicion = self.engine._suspicion()
        strictness = self.engine._strictness()
        return {"suspicion": suspicion, "strictness": strictness,
                "level": ("normal", "elevated", "locked")[min(strictness, 2)]}

    def close(self) -> None:
        self.engine.close()

    def __enter__(self) -> "Guard":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
