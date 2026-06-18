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
    path = installer.install(args.project, intent=args.intent, intent_model=args.intent_model)
    written = bootstrap.trust(args.project)
    print(f"✓ ddbt hooks installed → {path}")
    if written:
        print(f"✓ Boundary 0 baseline recorded for: {', '.join(written)}")
    if args.intent:
        print(f"✓ blind intent judge ENABLED (model: {args.intent_model})")
        print("  → ensure ANTHROPIC_API_KEY is set in the environment you launch Claude Code from.")
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
    import pathlib

    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent / "bench"))

    # R-Judge — static safety-judge evaluation (F1 vs gold safe/unsafe labels)
    if args.target == "rjudge":
        try:
            import rjudge
        except ImportError as exc:
            print(f"bench deps missing — uv pip install -e '.[bench]'  ({exc})", file=sys.stderr)
            return 2
        data = args.data or str(pathlib.Path(__file__).resolve().parent.parent.parent / "bench" / "data" / "rjudge")
        records = rjudge.load_rjudge(data, limit=args.limit)
        if not records:
            print(f"no R-Judge records under {data} (download with the tarball — see bench/)", file=sys.stderr)
            return 2
        try:
            rep = rjudge.score(records, workers=args.workers)
        except Exception as exc:
            print(f"rjudge run failed: {exc}\n(Set ANTHROPIC_API_KEY.)", file=sys.stderr)
            return 1
        print(rep.render())
        return 0

    # static replay — fast, no live agent, no API key
    if args.target == "static":
        try:
            import static_replay as sr
        except ImportError as exc:
            print(f"bench deps missing — uv pip install -e '.[bench]'  ({exc})", file=sys.stderr)
            return 2
        if args.source == "injecagent":
            if not args.data:
                print("--data PATH required for --source injecagent", file=sys.stderr)
                return 2
            cases = sr.load_injecagent(args.data)
        else:
            cases = sr.load_agentdojo(args.suite, limit=args.limit)
        rep = sr.replay(cases, source=f"{args.source}:{args.suite}" if args.source == "agentdojo" else "injecagent")
        print(rep.render())
        return 0

    if args.target != "agentdojo":
        print(f"unknown benchmark target: {args.target}", file=sys.stderr)
        return 2
    try:
        from harness import run_suite, run_vulnerable_delta
    except ImportError as exc:
        print(f"benchmark deps missing — install with: uv pip install -e '.[bench]'  ({exc})", file=sys.stderr)
        return 2
    try:
        if args.only_vulnerable:
            report = run_vulnerable_delta(
                suite_name=args.suite, model_id=args.model, limit=args.limit, inj_limit=args.inj_limit
            )
        else:
            report = run_suite(
                suite_name=args.suite,
                model_id=args.model,
                limit=args.limit,
                inj_limit=args.inj_limit,
                defended=not args.no_defense,
            )
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

    install_p = _proj(sub.add_parser("install", help="install Claude Code hooks"))
    install_p.add_argument("--intent", action="store_true", help="enable the blind intent judge (needs ANTHROPIC_API_KEY)")
    install_p.add_argument("--intent-model", default="claude-haiku-4-5", help="model for the intent judge")
    install_p.set_defaults(fn=_cmd_install)
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
    b.add_argument("target", choices=["agentdojo", "static", "rjudge"], help="benchmark to run")
    b.add_argument("--workers", type=int, default=4, help="concurrency for static/rjudge replay (lower = fewer rate-limit errors)")
    b.add_argument("--source", choices=["agentdojo", "injecagent"], default="agentdojo", help="static-replay corpus")
    b.add_argument("--data", default=None, help="path to InjecAgent test-case JSON (for --source injecagent)")
    b.add_argument("--suite", default="workspace", help="AgentDojo suite (workspace/banking/slack/travel)")
    b.add_argument("--model", default="gpt-4o-mini-2024-07-18", help="model id (provider is derived from it)")
    b.add_argument("--limit", type=int, default=5, help="max user tasks")
    b.add_argument("--inj-limit", type=int, default=None, help="max injection tasks per user task (cheap smoke: 2-3)")
    b.add_argument("--no-defense", action="store_true", help="run the stock pipeline (baseline, for the delta)")
    b.add_argument("--only-vulnerable", action="store_true",
                   help="run baseline, find pairs the agent gets hijacked on, re-run ONLY those with ddbt → delta")
    b.set_defaults(fn=_cmd_bench)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
