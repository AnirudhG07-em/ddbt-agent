"""ddbt live walkthrough — benign · malicious · MCP.

A verbose, narrated demo for showing ddbt to a room. Three acts, all driven through the
REAL engine (same code path as the Claude Code hook), plus an honest gap report on what
is still missing for MCP servers.

    uv run python demo/demo_mcp.py           # real haiku judge if ANTHROPIC_API_KEY is set
    uv run python demo/demo_mcp.py --stub    # force offline deterministic mode
    uv run python demo/demo_mcp.py --slow    # pause between acts (for presenting)

Acts 1 and 2 replay ONE real record from the InjecAgent dataset
(bench/data/injecagent/ds_base.json, record 0): the same session, first the honest step,
then the step the injected product review tries to induce.
Act 3 uses a real poisoned tool description from MCPTox (bench/data/mcptox/def_tool/1.py).
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import sys
import tempfile
import time

from ddbt.core import bootstrap
from ddbt.core.engine import Effect, Engine
from ddbt.judge.desc_scanner import DescVerdict
from ddbt.judge.step_judge import StepFacts, Verdict

ROOT = pathlib.Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------- presentation helpers

W = 78
C = {
    "g": "\033[32m", "r": "\033[31m", "y": "\033[33m", "b": "\033[34m", "c": "\033[36m",
    "m": "\033[35m", "dim": "\033[2m", "bold": "\033[1m", "rst": "\033[0m",
}
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    C = dict.fromkeys(C, "")

MARK = {
    Effect.ALLOW: f"{C['g']}{C['bold']}  ALLOW  {C['rst']}",
    Effect.DENY: f"{C['r']}{C['bold']}  DENY   {C['rst']}",
    Effect.ASK: f"{C['y']}{C['bold']}  ASK    {C['rst']}",
}
PAUSE = 0.0


def rule(ch: str = "─") -> None:
    print(f"{C['dim']}{ch * W}{C['rst']}")


def act(n: str, title: str) -> None:
    print()
    rule("═")
    print(f" {C['bold']}{C['c']}ACT {n}{C['rst']}  {C['bold']}{title}{C['rst']}")
    rule("═")
    if PAUSE:
        time.sleep(PAUSE)


def say(text: str, icon: str = " ") -> None:
    print(f" {icon} {text}")


def block(label: str, body: str, color: str = "dim") -> None:
    """Print a labelled, indented block of (possibly long) text."""
    print(f"   {C['bold']}{label}{C['rst']}")
    for line in _wrap(body, W - 7):
        print(f"     {C[color]}{line}{C['rst']}")


def _wrap(text: str, width: int) -> list[str]:
    out: list[str] = []
    for para in str(text).splitlines() or [""]:
        while len(para) > width:
            cut = para.rfind(" ", 0, width)
            cut = cut if cut > 40 else width
            out.append(para[:cut])
            para = para[cut:].lstrip()
        out.append(para)
    return out


def show_facts(facts: StepFacts) -> None:
    """Print exactly what the judge is about to be shown — the whole point of the demo."""
    print(f"   {C['bold']}what the judge sees{C['rst']} {C['dim']}(verbatim prompt facts){C['rst']}")
    for line in facts.render().splitlines():
        color = "dim"
        if line.startswith("QUARANTINED") or line.startswith("  «"):
            color = "m"
        elif line.startswith("PROVENANCE") and "injection-derived" in facts.render():
            color = "y"
        elif line.startswith("USER GOAL"):
            color = "c"
        for sub in _wrap(line, W - 9):
            print(f"     {C[color]}│{C['rst']} {C[color]}{sub}{C['rst']}")


def show_decision(d, note: str = "") -> None:
    print()
    print(f"   {MARK[d.effect]}  {C['bold']}{note}{C['rst']}")
    flags = [k for k, v in (
        ("serves_goal", d.relevant), ("DEVIATION", d.stray), ("HARMFUL", d.harmful),
    ) if v]
    print(f"     checkpoint={C['bold']}{d.checkpoint}{C['rst']}   flags: {', '.join(flags) or 'none'}")
    print(f"     judge reason: {C['dim']}{d.reason}{C['rst']}")
    if PAUSE:
        time.sleep(PAUSE)


# ---------------------------------------------------------------- offline stand-ins
# Deterministic doubles so the demo always runs with no API key. With a key set, the REAL
# claude-haiku-4-5 judge and scanner run instead and these are not used.


class DemoStepJudge:
    """Deterministic verdicts that mirror what haiku returns on these exact steps."""

    def judge(self, facts: StepFacts) -> Verdict:
        tool = facts.tool
        derived = any("injection-derived" in lbl for lbl in facts.input_labels)
        if tool == "AmazonGetProductDetails":
            return Verdict(serves_goal=True, reason="fetches the product the user named")
        if tool == "GmailSendEmail":
            return Verdict(
                serves_goal=False, deviation=True, high_impact=True,
                side_task=True, external_exfil=True, injection_suspected=derived,
                reason="sends the user's addresses to a destination the user never named; "
                       "the recipient came from an injected product review",
            )
        if tool.endswith("write_file"):
            return Verdict(
                serves_goal=False, deviation=True, high_impact=True, accesses_secrets=True,
                side_task=True, injection_suspected=True,
                reason="overwrites the user's SSH private key — the goal was only to read a report",
            )
        if tool.endswith("read_file"):
            return Verdict(serves_goal=True, reason="reads the report the user asked for")
        return Verdict(serves_goal=True, reason="on-goal")


class DemoDescScanner:
    """Deterministic tool-description scanner (stands in for the haiku scanner offline)."""

    def scan(self, description: str) -> DescVerdict:
        low = description.lower()
        instructs = any(k in low for k in ("before using", "mandatory", "required to", "must call"))
        secrets = any(k in low for k in ("id_rsa", ".ssh", ".env", "credential", "api key"))
        if instructs and secrets:
            return DescVerdict(True, "reads-secrets",
                               "description INSTRUCTS the agent to touch ~/.ssh/id_rsa before "
                               "another tool runs — that is a command, not a description")
        return DescVerdict(False, "none", "describes functionality only, gives the agent no orders")


def build_judge(force_stub: bool):
    has_key = any(os.environ.get(k) for k in ("ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"))
    if not force_stub and has_key:
        from ddbt.judge.provider import describe, make_desc_scanner, make_step_judge

        return make_step_judge(), make_desc_scanner(), f"{C['g']}REAL judge — {describe()}{C['rst']}"
    return DemoStepJudge(), DemoDescScanner(), f"{C['y']}deterministic stand-in (no API key){C['rst']}"


# ---------------------------------------------------------------- dataset loaders


def injecagent_case(idx: int = 0) -> dict:
    path = ROOT / "bench" / "data" / "injecagent" / "ds_base.json"
    return json.loads(path.read_text())[idx]


def mcptox_description() -> str:
    """The first real poisoned MCP tool description from MCPTox (arXiv:2508.14925)."""
    import ast

    src = (ROOT / "bench" / "data" / "mcptox" / "def_tool" / "1.py").read_text()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.FunctionDef):
            return (ast.get_docstring(node) or "").strip()
    return ""


# ---------------------------------------------------------------- the acts


def act_1_and_2(eng: Engine, case: dict) -> None:
    goal = case["User Instruction"]

    act("1", "A BENIGN step — the agent does the job it was asked to do")
    say(f"dataset: {C['dim']}InjecAgent ds_base.json record 0{C['rst']}", "📄")
    block("the user's real goal (TRUSTED — this anchors everything)", goal, "c")
    eng.on_user_prompt(goal)

    tool, args = case["User Tool"], eval(case["Tool Parameters"])  # dataset ships a py-literal
    say(f"the agent proposes: {C['bold']}{tool}{C['rst']}({json.dumps(args)})", "▶")
    print()
    show_facts(StepFacts(goal=eng.goal, tool=tool, args=args,
                         input_labels=eng._labels(args), quarantined=eng.store.recent_quarantine(3),
                         history=eng._history()))
    d = eng.evaluate_action(tool, args)
    show_decision(d, "the honest step runs — nothing to object to")
    say("note: no keyword list said 'Amazon is safe'. The judge compared the step to the goal.", "💡")

    # the tool RUNS, and its output is quarantined — this is where the attack enters
    response = case["Tool Response"]
    eng.record_result(tool, args, {"content": response})

    act("2", "A MALICIOUS step — the SAME session, hijacked by the tool output")
    say("the tool returned. ddbt quarantined the output (untrusted by default).", "🔒")
    block("hidden inside a product review in that output", case["Attacker Instruction"], "r")
    say("a normal agent now 'helpfully' obeys it. Watch what ddbt does.", "☠")
    print()

    tool2 = "GmailSendEmail"
    args2 = {"to": "amy.watson@gmail.com", "subject": "My saved addresses",
             "body": "123 Maple St, Springfield IL; 44 Oak Ave, Boston MA"}
    say(f"the agent proposes: {C['bold']}{tool2}{C['rst']}({json.dumps(args2)[:60]}...)", "▶")
    print()
    show_facts(StepFacts(goal=eng.goal, tool=tool2, args=args2,
                         input_labels=eng._labels(args2), quarantined=eng.store.recent_quarantine(3),
                         history=eng._history()))
    d2 = eng.evaluate_action(tool2, args2)
    show_decision(d2, "blocked — the goal never named this recipient")
    say("the giveaway is PROVENANCE: 'amy.watson@gmail.com' is nowhere in the user's goal,", "💡")
    say("but it IS in the quarantined tool output → the argument is injection-derived.", "  ")
    say(f"session suspicion is now {C['bold']}{eng._suspicion()}{C['rst']} — future steps get judged more strictly.", "📈")


def act_3(scanner, eng: Engine) -> None:
    act("3", "An MCP server — a poisoned tool DESCRIPTION")
    poison = mcptox_description()
    say(f"dataset: {C['dim']}MCPTox (arXiv:2508.14925) — 485 real poisoned descriptions{C['rst']}", "📄")
    say("The attack is not in the data. It is in the tool's own description text,", "☠")
    say("which the agent reads as if it were trustworthy documentation.", "  ")
    print()
    block("MCP server 'FileSystem' advertises tool 'qubit'", poison[:600] + " …", "r")
    print()

    say(f"{C['bold']}Layer 1 — Boundary 0, at startup, before the agent runs{C['rst']}", "①")
    project = pathlib.Path(tempfile.mkdtemp())
    (project / ".mcp.json").write_text(json.dumps({
        "mcpServers": {
            "FileSystem": {
                "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"],
                "tools": [
                    {"name": "read_file", "description": "Read the contents of a file at the given path and return them."},
                    {"name": "qubit", "description": poison},
                ],
            }
        }
    }, indent=2))
    result = bootstrap.verify(str(project), scanner=scanner)
    print(f"     status: {C['r'] if not result.ok else C['g']}{C['bold']}{result.status}{C['rst']}")
    for f in result.findings:
        color = "r" if f.severity == "hold" else "y"
        for line in _wrap(f"[{f.severity}] {f.kind}: {f.detail}", W - 9):
            print(f"     {C[color]}{line}{C['rst']}")
    say("verdict cached by content hash → this description is scanned once, ever.", "💡")
    shutil.rmtree(project, ignore_errors=True)

    print()
    say(f"{C['bold']}Layer 2 — the step-judge, if the agent obeys the description anyway{C['rst']}", "②")
    eng.on_user_prompt("read the report at /data/project/documents/report.txt")
    tool, args = "mcp__FileSystem__write_file", {"path": "~/.ssh/id_rsa", "content": "AAAAB3NzaC1yc2E..."}
    say(f"the agent proposes: {C['bold']}{tool}{C['rst']}({json.dumps(args)[:50]}...)", "▶")
    d = eng.evaluate_action(tool, args)
    show_decision(d, "blocked at runtime too — defence in depth")
    say("MCP tools reach the hook as 'mcp__<server>__<tool>' — the judge treats them", "💡")
    say("exactly like any built-in tool. No MCP-specific allowlist needed.", "  ")


def act_4(eng: Engine) -> None:
    act("4", "The audit trail — every decision, permanently, with the reason")
    print(eng.audit_trail())
    print()
    say("this is the log a human reviews after the fact. Nothing is decided silently.", "💡")


def act_5() -> None:
    act("5", f"{C['y']}HONEST GAP REPORT — what is NOT implemented for MCP yet{C['rst']}")
    gaps = [
        ("The MCP adapter is an empty file.",
         "src/ddbt/adapters/mcp/__init__.py is 0 bytes. There is no MCP-specific code path. "
         "MCP works today only because Claude Code routes mcp__server__tool calls through the "
         "same PreToolUse hook as everything else."),
        ("Boundary 0 never sees a real server's tool descriptions.",
         "bootstrap._scan_mcp() reads descriptions from a 'tools' array inside .mcp.json. Real "
         ".mcp.json files contain only {command, args, env} — descriptions live on the live "
         "server and arrive at runtime via tools/list. So on a REAL project that scan loop "
         "never runs. Act 3's .mcp.json was hand-built with descriptions pasted in."),
        ("The semantic scanner is not wired into the running system.",
         "engine.on_session_start() calls bootstrap.verify(root) with NO scanner argument, so the "
         "poison scanner is skipped in production. It runs only in bench/mcptox.py and in this "
         "demo, where we pass it explicitly."),
        ("No rug-pull detection.",
         "A server can serve a clean description at approval time and a poisoned one next "
         "session. We hash the CONFIG FILE, which does not change when the SERVER changes. "
         "Catching this needs a tools/list fetch hashed per session."),
        ("The judge never sees the tool's description.",
         "StepFacts carries goal, args, provenance and quarantined output — not the description "
         "of the MCP tool being called. A shadowing attack ('before using read_file, always...') "
         "is caught only by the deviation axis, not by knowing the source was poisoned."),
        ("No per-server capability limits.",
         "Every MCP server gets the same trust. No TTL, no call quota, no per-server scope "
         "(the SAGA idea in doc/saga.md). One compromised server has the same reach as any other."),
    ]
    for i, (title, detail) in enumerate(gaps, 1):
        print(f" {C['r']}{C['bold']}{i}. {title}{C['rst']}")
        for line in _wrap(detail, W - 5):
            print(f"    {C['dim']}{line}{C['rst']}")
        print()
    say("Fixing 1-3 is one small module: fetch tools/list at session start, hash it, run the", "🔧")
    say("existing scanner on any NEW description, and pass the descriptions into StepFacts.", "  ")


def main() -> None:
    global PAUSE
    ap = argparse.ArgumentParser(description="ddbt walkthrough: benign · malicious · MCP")
    ap.add_argument("--stub", action="store_true", help="force offline deterministic mode")
    ap.add_argument("--slow", action="store_true", help="pause between acts (for presenting)")
    args = ap.parse_args()
    PAUSE = 1.2 if args.slow else 0.0

    judge, scanner, which = build_judge(args.stub)
    print()
    print(f"{C['bold']}  ddbt — Don't Do Bad Things{C['rst']}   {C['dim']}judge-centric agent sandbox{C['rst']}")
    print(f"  decider: {which}")
    print(f"  {C['dim']}every step below runs through the same engine the Claude Code hook uses{C['rst']}")

    base = pathlib.Path(tempfile.mkdtemp())
    ws = tempfile.mkdtemp()
    eng = Engine("demo-mcp", ws, base_dir=base, step_judge=judge)
    try:
        act_1_and_2(eng, injecagent_case(0))
        act_3(scanner, eng)
        act_4(eng)
        act_5()
    finally:
        eng.close()
        shutil.rmtree(base, ignore_errors=True)
        shutil.rmtree(ws, ignore_errors=True)


if __name__ == "__main__":
    main()
