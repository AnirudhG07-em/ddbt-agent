"""``ddbt`` command-line interface.

  ddbt install   --project DIR     wire ddbt hooks into .claude/settings.json
  ddbt uninstall --project DIR     remove them
  ddbt trust     --project DIR     baseline current config (Boundary 0 approval)
  ddbt verify    --project DIR     run Boundary 0 integrity check
  ddbt audit     --session ID      print a session's decision trail
  ddbt hook      EVENT             hook entrypoint (reads stdin JSON) — used by Claude Code
"""

from __future__ import annotations

import argparse
import os
import sys

from ddbt.adapters.claude_code import hook as hook_adapter
from ddbt.adapters.claude_code import install as installer
from ddbt.core import bootstrap
from ddbt.core.audit import AuditLogger
from ddbt.store.session import SessionStore


def _cmd_install(args: argparse.Namespace) -> int:
    path = installer.install(args.project)
    written = bootstrap.trust(args.project)
    print(f"✓ ddbt hooks installed → {path}")
    if written:
        print(f"✓ Boundary 0 baseline recorded for: {', '.join(written)}")
    print("  Restart Claude Code in this project for hooks to take effect.")
    return 0


def _cmd_uninstall(args: argparse.Namespace) -> int:
    path = installer.uninstall(args.project)
    print(f"✓ ddbt hooks removed from {path}")
    return 0


def _cmd_trust(args: argparse.Namespace) -> int:
    written = bootstrap.trust(args.project)
    print(f"✓ baseline recorded for: {', '.join(written) or '(no guarded config present)'}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    result = bootstrap.verify(args.project)
    print(result.summary())
    return 0 if result.ok else 1


def _cmd_audit(args: argparse.Namespace) -> int:
    store = SessionStore(args.session)
    try:
        print(f"Audit trail for session {args.session}:")
        print(AuditLogger(store).render())
    finally:
        store.close()
    return 0


def _cmd_hook(args: argparse.Namespace) -> int:
    return hook_adapter.dispatch(args.event, sys.stdin.read())


def _cmd_bench(args: argparse.Namespace) -> int:
    if args.target != "agentdojo":
        print(f"unknown benchmark target: {args.target}", file=sys.stderr)
        return 2
    try:
        import pathlib

        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent / "bench"))
        from harness import run_suite
    except ImportError as exc:
        print(f"benchmark deps missing — install with: uv pip install -e '.[bench]'  ({exc})", file=sys.stderr)
        return 2
    try:
        report = run_suite(suite_name=args.suite, model_id=args.model, limit=args.limit)
    except Exception as exc:  # most commonly a missing API key / model backend
        print(f"benchmark run failed: {exc}\n(Set the provider API key, e.g. OPENAI_API_KEY.)", file=sys.stderr)
        return 1
    print(report.render())
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ddbt", description="Don't Do Bad Things — agent sandbox")
    sub = p.add_subparsers(dest="cmd", required=True)

    def _proj(sp):
        sp.add_argument("--project", default=os.getcwd(), help="project directory (default: cwd)")
        return sp

    _proj(sub.add_parser("install", help="install Claude Code hooks")).set_defaults(fn=_cmd_install)
    _proj(sub.add_parser("uninstall", help="remove Claude Code hooks")).set_defaults(fn=_cmd_uninstall)
    _proj(sub.add_parser("trust", help="baseline config for Boundary 0")).set_defaults(fn=_cmd_trust)
    _proj(sub.add_parser("verify", help="run Boundary 0 integrity check")).set_defaults(fn=_cmd_verify)

    a = sub.add_parser("audit", help="print a session's decision trail")
    a.add_argument("--session", required=True)
    a.set_defaults(fn=_cmd_audit)

    h = sub.add_parser("hook", help="hook entrypoint (used by Claude Code)")
    h.add_argument("event")
    h.set_defaults(fn=_cmd_hook)

    b = sub.add_parser("bench", help="run a security benchmark through the ddbt defense")
    b.add_argument("target", choices=["agentdojo"], help="benchmark to run")
    b.add_argument("--suite", default="workspace", help="AgentDojo suite (workspace/banking/slack/travel)")
    b.add_argument("--model", default="gpt-4o-mini-2024-07-18", help="model id (provider is derived from it)")
    b.add_argument("--limit", type=int, default=5, help="max user tasks")
    b.set_defaults(fn=_cmd_bench)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
