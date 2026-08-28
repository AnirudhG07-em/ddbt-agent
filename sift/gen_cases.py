#!/usr/bin/env python
"""Generate labelled good/bad action cases for a work-system, ONCE, OFFLINE — then retrain.

This is the "ask an LLM for 100-200 cases and instantly train" workflow. The LLM is used ONLY here,
offline, to author training data; the deployed ddbt judge never calls an LLM. Output is appended to
sift/data/domains/<domain>.jsonl, which `ddbt prepare` folds into training automatically.

    # generate 150 database cases with an LLM (needs GEMINI_API_KEY or ANTHROPIC_API_KEY), then retrain
    uv run --extra all python sift/gen_cases.py --domain database --n 150
    uv run ddbt prepare

    # no LLM? write cases by hand in sift/data/domains/<domain>.jsonl (see database.jsonl) and retrain.

Each generated line: {"tool","args","goal","label"(0/1),"domain","category"}.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

PROMPT = """You are creating TRAINING DATA for a security judge that inspects an AI agent's tool
calls in the "{domain}" domain and decides if each is safe (label 0) or unsafe (label 1).

Produce {n} diverse, realistic cases as JSON Lines (one JSON object per line), no prose, no markdown.
Each object: {{"tool": <tool name>, "args": {{...}}, "goal": <the user's trusted request>,
"label": 0 or 1, "category": <short tag>}}.

Balance ~50/50 safe and unsafe. Cover, for {domain}:
- SAFE: scoped reads, the write/action the user explicitly asked for, routine maintenance.
- UNSAFE: destructive/irreversible actions, exfiltration to external destinations, accessing
  secrets/PII to leak, unauthorized privilege changes, covering tracks / disabling logs, and
  actions the user did NOT request. Make unsafe cases realistic, not cartoonish.
{extra}
Output ONLY the JSON Lines."""


def _load_env() -> None:
    """Read KEY=VALUE lines from a .env in this dir or a parent (so the offline generator finds keys)."""
    here = Path(__file__).resolve()
    for up in [here.parent, *here.parents]:
        f = up / ".env"
        if f.is_file():
            for line in f.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
            return


def _gen_gemini(prompt: str) -> str:
    from google import genai
    from google.genai import types
    _load_env()
    key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    client = genai.Client(api_key=key)
    r = client.models.generate_content(
        model="gemini-2.5-flash", contents=prompt,
        config=types.GenerateContentConfig(temperature=0.7, max_output_tokens=8000,
                                           thinking_config=types.ThinkingConfig(thinking_budget=0)))
    return r.text or ""


def _gen_anthropic(prompt: str) -> str:
    import anthropic
    c = anthropic.Anthropic()
    m = c.messages.create(model="claude-haiku-4-5-20251001", max_tokens=8000,
                          messages=[{"role": "user", "content": prompt}])
    return "".join(b.text for b in m.content if getattr(b, "type", "") == "text")


def _parse(text: str, domain: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        line = line.strip().strip("`").strip(",")
        if not (line.startswith("{") and line.endswith("}")):
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "tool" in r and "label" in r and "args" in r:
            r["domain"] = domain
            r.setdefault("goal", "")
            r.setdefault("category", "generated")
            r["label"] = int(bool(r["label"]))
            out.append(r)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="generate domain training cases with an LLM (offline)")
    ap.add_argument("--domain", required=True, help="e.g. database, git, jira, cloud")
    ap.add_argument("--n", type=int, default=150)
    ap.add_argument("--extra", default="", help="extra guidance for the domain (tools, conventions)")
    ap.add_argument("--provider", choices=["gemini", "anthropic"], default="gemini")
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    prompt = PROMPT.format(domain=args.domain, n=args.n, extra=(f"Context: {args.extra}\n" if args.extra else ""))
    text = _gen_gemini(prompt) if args.provider == "gemini" else _gen_anthropic(prompt)
    cases = _parse(text, args.domain)
    if not cases:
        print("✗ no valid cases parsed — try again or check the API key.")
        return 1
    out = Path(args.out or (Path(__file__).resolve().parent / "data" / "domains" / f"{args.domain}.jsonl"))
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("a") as f:  # append so repeated runs accumulate
        for r in cases:
            f.write(json.dumps(r) + "\n")
    n_bad = sum(r["label"] for r in cases)
    print(f"✓ wrote {len(cases)} cases ({n_bad} bad / {len(cases)-n_bad} good) → {out}")
    print("  now retrain:  uv run ddbt prepare")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
