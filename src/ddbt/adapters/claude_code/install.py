"""Install/uninstall ddbt hooks into a Claude Code project's settings.json.

Writes a ``hooks`` block whose commands invoke this very Python interpreter as
``python -m ddbt.adapters.claude_code.hook <Event>`` — using an absolute interpreter
path so it works in the hook's non-interactive shell without venv activation.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

EVENTS = ["PreToolUse", "PostToolUse", "SessionStart", "UserPromptSubmit", "Stop", "ConfigChange"]
_MARKER = "ddbt.adapters.claude_code.hook"


def _command(event: str, intent: bool = False, intent_model: str | None = None) -> str:
    # bake the intent-judge env into the command itself so it's active regardless of the
    # hook's (non-interactive) shell environment. The judge still needs ANTHROPIC_API_KEY
    # to be present in the process Claude Code launches.
    prefix = ""
    if intent:
        prefix = "DDBT_INTENT_JUDGE=1 "
        if intent_model:
            prefix += f"DDBT_INTENT_MODEL={intent_model} "
    return f"{prefix}{sys.executable} -m {_MARKER} {event}"


def _hook_entry(event: str, intent: bool = False, intent_model: str | None = None) -> dict:
    timeout = 30 if event in ("PreToolUse", "UserPromptSubmit") else 60
    cmd = _command(event, intent, intent_model)
    return {"matcher": "*", "hooks": [{"type": "command", "command": cmd, "timeout": timeout}]}


def install(project_dir: str, intent: bool = False, intent_model: str | None = None) -> Path:
    project = Path(project_dir)
    settings_path = project / ".claude" / "settings.json"
    settings_path.parent.mkdir(parents=True, exist_ok=True)

    settings: dict = {}
    if settings_path.exists():
        shutil.copy(settings_path, settings_path.with_suffix(".json.ddbt-bak"))
        try:
            settings = json.loads(settings_path.read_text())
        except json.JSONDecodeError:
            settings = {}

    hooks = settings.setdefault("hooks", {})
    for event in EVENTS:
        existing = [e for e in hooks.get(event, []) if _MARKER not in json.dumps(e)]
        hooks[event] = existing + [_hook_entry(event, intent, intent_model)]

    settings_path.write_text(json.dumps(settings, indent=2) + "\n")
    return settings_path


def uninstall(project_dir: str) -> Path:
    settings_path = Path(project_dir) / ".claude" / "settings.json"
    if not settings_path.exists():
        return settings_path
    settings = json.loads(settings_path.read_text())
    hooks = settings.get("hooks", {})
    for event in list(hooks):
        hooks[event] = [e for e in hooks[event] if _MARKER not in json.dumps(e)]
        if not hooks[event]:
            del hooks[event]
    if not hooks:
        settings.pop("hooks", None)
    settings_path.write_text(json.dumps(settings, indent=2) + "\n")
    return settings_path
