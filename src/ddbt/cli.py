"""``ddbt`` command-line interface.

  ddbt install   --project DIR     wire hooks into .claude/settings.json + write ddbt.json defaults
  ddbt uninstall --project DIR     remove them
  ddbt trust     --project DIR     baseline current config (Boundary 0 approval)
  ddbt verify    --project DIR     run Boundary 0 integrity check
  ddbt audit     --session ID      print a session's decision trail
  ddbt clear     --session ID      clear suspicion after a false positive (audited)
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
    from ddbt.core import config

    path = installer.install(args.project, intent=args.intent, intent_model=args.intent_model)
    # config is written OUT-OF-BAND (~/.ddbt/projects/<hash>/) by default so the guarded agent can't
    # edit its own policy; pass --in-project for a committable ./ddbt.json instead.
    cfg_path, cfg_written = config.write_default(args.project, in_project=args.in_project)
    written = bootstrap.trust(args.project)
    print(f"✓ ddbt hooks installed → {path}")
    where = "in-project (committable)" if args.in_project else "out-of-band (agent-tamper-proof)"
    if cfg_written:
        print(f"✓ default config written → {cfg_path}  [{where}]  (judge · policy allow/deny · plugins)")
    else:
        print(f"• {cfg_path} kept (already present)")
    if written:
        print(f"✓ Boundary 0 baseline recorded for: {', '.join(written)}")
    if args.intent:
        print(f"✓ blind intent judge ENABLED (model: {args.intent_model})")
        print("  → ensure ANTHROPIC_API_KEY is set in the environment you launch Claude Code from.")
    # build the general (non-LLM) judge layer now if it isn't present — no separate `prepare` step.
    if not args.no_prepare:
        if _sift_model_path() is not None:
            print("✓ local judge model already present (shared across projects)")
        else:
            print("→ no local judge model yet — building it (one-time, torch-free) …")
            _build_model("model2vec")   # best-effort; ddbt still runs (LLM/hashing fallback) if it fails
    print('  Teach ddbt a new tool:  ddbt create-rules "notion-cli"   (LLM-drafts good/bad, applies live — no retrain).')
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


def _cmd_clear(args: argparse.Namespace) -> int:
    """Human clearance for a session whose guard tightened on a false positive."""
    from ddbt.core.engine import Engine

    eng = Engine(args.session, workspace_root=os.getcwd(), step_judge=_NullJudge())
    try:
        before = eng.clear_suspicion(args.reason)
    finally:
        eng.close()
    print(f"\u2713 session {args.session}: suspicion {before} \u2192 0, strictness \u2192 NORMAL")
    print(f"  recorded in the audit trail as: {args.reason}")
    return 0


class _NullJudge:
    """Clearing state must never need a model (or an API key)."""

    def judge(self, facts):  # pragma: no cover - never called
        raise AssertionError("clear does not judge")


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


def _print_pack(name: str) -> None:
    from ddbt.core import rules
    beh = (rules.load_pack(name) or {}).get("behaviors", {})
    print("  BAD — will raise risk / gate (deny):")
    for r in (beh.get("deny") or [])[:40]:
        print(f"    ✗ {r}")
    print("  GOOD — known-safe (allow):")
    for r in (beh.get("allow") or [])[:40]:
        print(f"    ✓ {r}")


def _confirm(question: str) -> bool:
    if not sys.stdin.isatty():   # non-interactive → don't auto-integrate; caller prints how to enable
        return False
    try:
        return input(f"{question} [y/N] ").strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


def _cmd_create_rules(args: argparse.Namespace) -> int:
    """Draft a REUSABLE rule-pack for a tool (LLM-assisted, offline), let you VERIFY it, then integrate.
    The pack lives in ~/.ddbt/rules/<name>/ so any project can reference it by name — no retrain."""
    from ddbt.core import config, generate, rules

    name = args.name
    conf = config.llm(args.project)
    provider = args.provider or conf["provider"]
    model = args.model or conf["model"]
    rounds = max(1, min(args.rounds, conf["max_requests"]))
    who = provider or generate.available() or "none"
    print(f"→ drafting a rule-pack for {name!r}  (provider={who}, model={model or 'default'}, rounds={rounds}) …")

    if provider or generate.available():
        try:
            pack = rules.draft(name, args.about, provider=provider, model=model, rounds=rounds)
        except Exception as exc:  # noqa: BLE001 — fall back to an editable starter, never fail hard
            print(f"  LLM draft failed ({exc}); wrote an editable starter instead.")
            pack = rules.starter(name, args.about)
    else:
        print("  no LLM key found (GEMINI_API_KEY / ANTHROPIC_API_KEY) — wrote an editable starter pack.")
        pack = rules.starter(name, args.about)

    path = rules.save_pack(name, pack)
    deny, allow = rules.counts(name)
    safe = rules._safe(name)
    print(f"\n✓ drafted → {path}   ({deny} deny · {allow} allow)\n")
    _print_pack(name)                                          # VERIFY: show the rules before integrating

    # INTEGRATE — verify-then-integrate: enabled only on --enable or an interactive yes.
    do_enable = args.enable or (not args.no_enable and _confirm(f"\nIntegrate '{safe}' into this project now?"))
    if do_enable:
        cfg = config.add_ruleset(name, args.project)
        print(f"✓ enabled for this project → {cfg}  (applies live, no retrain)")
    else:
        print(f"• not enabled yet. Review/edit {path},")
        print(f"  then integrate with:  ddbt enable-rules {safe}")
    print(f"  Reusable anywhere: \"rulesets\": [\"{safe}\"] in any project's ddbt.json.")
    return 0


def _cmd_enable_rules(args: argparse.Namespace) -> int:
    from ddbt.core import config, rules
    if not rules.load_pack(args.name):
        print(f"✗ no rule-pack named {args.name!r} (see `ddbt rules`)")
        return 1
    print(f"✓ enabled {args.name!r} for this project → {config.add_ruleset(args.name, args.project)}")
    return 0


def _cmd_disable_rules(args: argparse.Namespace) -> int:
    from ddbt.core import config
    print(f"✓ disabled {args.name!r} for this project → {config.remove_ruleset(args.name, args.project)}")
    return 0


def _cmd_rules(args: argparse.Namespace) -> int:
    """List the reusable rule-packs available on this machine, and which this project references."""
    from ddbt.core import config, rules

    packs = rules.list_packs()
    if not packs:
        print('no rule-packs yet — create one with:  ddbt create-rules "<tool>"')
        return 0
    active = set(config.load(args.project).get("rulesets") or [])
    print("reusable rule-packs (~/.ddbt/rules/):")
    for n in packs:
        deny, allow = rules.counts(n)
        mark = "●" if n in active else "○"
        print(f"  {mark} {n:22s} {deny:2d} deny · {allow:2d} allow")
    print('\n  ● = referenced by this project    ○ = available but not enabled')
    print('  enable:  ddbt enable-rules <name>      disable:  ddbt disable-rules <name>')
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    """Language-agnostic guard: read a tool call as JSON on stdin, print the Decision as JSON on stdout.
    stdin:  {"session_id","cwd","tool","args",{"goal"?}}   stdout: Decision.to_dict()
    exit code: 0=allow  1=deny  2=ask/ask_override  (so any shell can branch on $?). Session state
    persists on disk by session_id, so per-call subprocesses accumulate the cross-step view.
    For a hot loop, prefer the in-process `from ddbt import Guard` (avoids reloading the model each call)."""
    import json

    from ddbt import Guard
    p = json.loads(sys.stdin.read() or "{}")
    guard = Guard(p.get("session_id", "default"), cwd=p.get("cwd") or ".")
    if p.get("goal"):
        guard.goal(p["goal"])
    d = guard.check(p.get("tool", ""), p.get("args") or {})
    guard.close()
    print(json.dumps(d.to_dict()))
    return {"allow": 0, "deny": 1, "ask": 2, "ask_override": 2}.get(d.effect.value, 0)


def _cmd_record(args: argparse.Namespace) -> int:
    """Feed a completed step back in. stdin: {"session_id","cwd","tool","args","result"}."""
    import json

    from ddbt import Guard
    p = json.loads(sys.stdin.read() or "{}")
    guard = Guard(p.get("session_id", "default"), cwd=p.get("cwd") or ".")
    guard.record(p.get("tool", ""), p.get("args") or {}, p.get("result"))
    guard.close()
    return 0


def _cmd_screen(args: argparse.Namespace) -> int:
    """Redact secrets/PII from text BEFORE a model sees it. stdin: raw text; stdout: JSON
    {sensitive, redacted, findings, effect}. exit 2 if sensitive (so a shell can gate), else 0."""
    import json

    from ddbt import screen_text
    s = screen_text(sys.stdin.read())
    print(json.dumps({"sensitive": s.sensitive, "redacted": s.redacted,
                      "findings": s.findings, "effect": s.effect, "reason": s.reason}))
    return 2 if s.sensitive else 0


def _sift_model_path():
    """Path to the trained sift artifact if it exists, else None (the 'general layer')."""
    import pathlib
    here = pathlib.Path(__file__).resolve()
    return next((up / "sift" / "models" / "sift_judge.joblib" for up in here.parents
                 if (up / "sift" / "models" / "sift_judge.joblib").is_file()), None)


def _build_model(encoder: str = "model2vec", calibrate: bool = False) -> int:
    """Build the general (non-LLM) sift judge: torch-free — model2vec static-embed inference + a
    scikit-learn head. Downloads potion-base-32M once (~130MB) via huggingface_hub; no PyTorch."""
    import pathlib
    import subprocess

    here = pathlib.Path(__file__).resolve()
    train = next((up / "sift" / "train_sift.py" for up in here.parents
                  if (up / "sift" / "train_sift.py").is_file()), None)
    if train is None:
        print("✗ could not find sift/train_sift.py (is the sift/ project present?)")
        return 1
    print(f"→ building the local judge model (encoder={encoder}, torch-free) …")
    try:
        rc = subprocess.call([sys.executable, str(train), "--encoder", encoder], cwd=str(train.parent))
    except OSError as exc:
        print(f"✗ failed to launch training: {exc}")
        return 1
    if rc != 0:
        print("\n✗ build failed. If a dependency is missing, the core set is torch-free:")
        print("    uv pip install numpy scikit-learn model2vec joblib      (NO PyTorch needed)")
        return rc
    print("✓ sift judge ready → sift/models/sift_judge.joblib")
    # warm the net_semantic centroid cache so the first guarded egress is fast (<50ms, no rebuild).
    try:
        from ddbt.judge.embedder import get_encoder
        from ddbt.plugins.net_semantic import NetSemantic
        enc = get_encoder()
        if enc is not None and NetSemantic()._ensure_centroids(enc):
            print("✓ net_semantic centroids cached (semantic egress review ready)")
    except Exception:  # noqa: BLE001 — optional; the plugin rebuilds on first use if skipped
        pass
    if calibrate:
        cal = next((up / "bench" / "calibrate_net_semantic.py" for up in here.parents
                    if (up / "bench" / "calibrate_net_semantic.py").is_file()), None)
        if cal is not None:
            print("\n→ net_semantic calibration report:")
            subprocess.call([sys.executable, str(cal)], cwd=str(cal.parent.parent))
    return 0


def _cmd_prepare(args: argparse.Namespace) -> int:
    """(Re)build the non-LLM sift judge model. Usually not needed by hand — `ddbt install` builds it
    automatically if the general layer is missing. Workspace behaviors/rulesets need NO training."""
    return _build_model(args.encoder, getattr(args, "calibrate", False))


def _cmd_bench(args: argparse.Namespace) -> int:
    import pathlib

    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent / "bench"))

    # AgentDyn is a drop-in fork of AgentDojo (same `agentdojo` import) — default to its
    # primary suite when the target is agentdyn and no --suite was given.
    suite = args.suite or ("shopping" if args.target == "agentdyn" else "workspace")

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
            cases = sr.load_agentdojo(suite, limit=args.limit)
        rep = sr.replay(
            cases,
            source=f"{args.source}:{suite}" if args.source == "agentdojo" else "injecagent",
            workers=args.workers,
        )
        print(rep.render())
        return 0

    # live agent suite — AgentDojo, or its drop-in fork AgentDyn (same harness, new suites)
    if args.target not in ("agentdojo", "agentdyn"):
        print(f"unknown benchmark target: {args.target}", file=sys.stderr)
        return 2
    benchmark = "AgentDyn" if args.target == "agentdyn" else "AgentDojo"
    try:
        from harness import run_suite, run_vulnerable_delta
    except ImportError as exc:
        print(f"benchmark deps missing — install with: uv pip install -e '.[bench]'  ({exc})", file=sys.stderr)
        return 2
    try:
        if args.only_vulnerable:
            report = run_vulnerable_delta(
                suite_name=suite, model_id=args.model, limit=args.limit, inj_limit=args.inj_limit,
                benchmark=benchmark,
            )
        else:
            report = run_suite(
                suite_name=suite,
                model_id=args.model,
                limit=args.limit,
                inj_limit=args.inj_limit,
                defended=not args.no_defense,
                benchmark=benchmark,
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

    install_p = _proj(sub.add_parser("install", help="install hooks + write a default ddbt.json"))
    install_p.add_argument("--intent", action="store_true", help="enable the blind intent judge (needs ANTHROPIC_API_KEY)")
    install_p.add_argument("--intent-model", default="claude-haiku-4-5", help="model for the intent judge")
    install_p.add_argument("--in-project", action="store_true",
                           help="write a committable ./ddbt.json instead of the out-of-band per-project config")
    install_p.add_argument("--no-prepare", action="store_true",
                           help="don't auto-build the local judge model (build later with `ddbt prepare`)")
    install_p.set_defaults(fn=_cmd_install)
    _proj(sub.add_parser("uninstall", help="remove Claude Code hooks")).set_defaults(fn=_cmd_uninstall)
    _proj(sub.add_parser("trust", help="baseline config for Boundary 0")).set_defaults(fn=_cmd_trust)
    _proj(sub.add_parser("verify", help="run Boundary 0 integrity check")).set_defaults(fn=_cmd_verify)

    c = sub.add_parser("clear", help="clear a session's suspicion (audited human override)")
    c.add_argument("--session", required=True)
    c.add_argument("--reason", default="cleared by the user", help="recorded in the audit trail")
    c.set_defaults(fn=_cmd_clear)

    a = sub.add_parser("audit", help="print a session's decision trail")
    a.add_argument("--session", required=True)
    a.set_defaults(fn=_cmd_audit)

    cr = _proj(sub.add_parser("create-rules", help='draft a reusable rule-pack for a tool (LLM-assisted); verify, then enable'))
    cr.add_argument("name", help='the tool/workflow to teach ddbt about, e.g. "notion-cli"')
    cr.add_argument("--about", default="", help="a sentence describing the tool, for a better draft")
    cr.add_argument("--provider", choices=["gemini", "anthropic"], help="LLM provider (default: ddbt.json llm.provider / auto)")
    cr.add_argument("--model", help="model id (default: ddbt.json llm.model / the provider default)")
    cr.add_argument("--rounds", type=int, default=1, help="how many generation requests to merge (capped by llm.max_requests)")
    cr.add_argument("--enable", action="store_true", help="integrate immediately, skip the confirm prompt")
    cr.add_argument("--no-enable", action="store_true", help="only draft (verify) — do not reference it in this project")
    cr.set_defaults(fn=_cmd_create_rules)

    er = _proj(sub.add_parser("enable-rules", help="reference a rule-pack in this project"))
    er.add_argument("name")
    er.set_defaults(fn=_cmd_enable_rules)
    dr = _proj(sub.add_parser("disable-rules", help="un-reference a rule-pack from this project"))
    dr.add_argument("name")
    dr.set_defaults(fn=_cmd_disable_rules)

    _proj(sub.add_parser("rules", help="list reusable rule-packs (~/.ddbt/rules/)")).set_defaults(fn=_cmd_rules)

    # language-agnostic integration: pipe JSON in, get a decision JSON out (see `ddbt <cmd> -h`)
    sub.add_parser("check", help="judge a tool call: stdin JSON {session_id,cwd,tool,args,goal?} → Decision JSON; exit 0/1/2 = allow/deny/ask").set_defaults(fn=_cmd_check)
    sub.add_parser("record", help="record a completed step: stdin JSON {session_id,cwd,tool,args,result}").set_defaults(fn=_cmd_record)
    sub.add_parser("screen", help="redact secrets/PII from stdin text → JSON {sensitive,redacted,findings}; exit 2 if sensitive").set_defaults(fn=_cmd_screen)

    prep = sub.add_parser("prepare", help="train the non-LLM sift judge model (one-time)")
    prep.add_argument("--encoder", default="model2vec", choices=["model2vec", "minilm", "hashing"])
    prep.add_argument("--calibrate", action="store_true",
                      help="also report net_semantic egress-review calibration (held-out + leave-one-category-out)")
    prep.set_defaults(fn=_cmd_prepare)

    h = sub.add_parser("hook", help="hook entrypoint (used by Claude Code)")
    h.add_argument("event")
    h.set_defaults(fn=_cmd_hook)

    b = sub.add_parser("bench", help="run a security benchmark through the ddbt defense")
    b.add_argument("target", choices=["agentdojo", "agentdyn", "static", "rjudge"], help="benchmark to run")
    b.add_argument("--workers", type=int, default=4, help="concurrency for static/rjudge replay (lower = fewer rate-limit errors)")
    b.add_argument("--source", choices=["agentdojo", "injecagent"], default="agentdojo", help="static-replay corpus")
    b.add_argument("--data", default=None, help="path to InjecAgent test-case JSON (for --source injecagent)")
    b.add_argument("--suite", default=None,
                   help="suite (AgentDojo: workspace/banking/slack/travel; AgentDyn: shopping/github/dailylife). "
                        "Default: workspace, or shopping for the agentdyn target")
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
