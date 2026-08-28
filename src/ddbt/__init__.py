"""ddbt — Don't Do Bad Things: an envelope-anchored sandbox for coding agents.

Quick start — guard any agent/tool loop in three lines:

    from ddbt import Guard
    guard = Guard(session_id="my-agent", cwd=".")
    d = guard.check("send_email", {"to": "x@evil.com", "body": "..."})
    if d.denied: ...
"""

from ddbt.core.engine import Decision, Effect, Engine
from ddbt.guard import Guard
from ddbt.screen import Screen, screen_text

__version__ = "0.1.0"
__all__ = ["Guard", "Engine", "Decision", "Effect", "Screen", "screen_text"]
