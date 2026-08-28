"""Which LLM backs the judge — one place, so every entry point agrees.

The decider is an LLM, but WHICH LLM is a deployment choice, not an architectural one.
Both backends share the same prompts, the same forced-tool-call schema and the same
fail-closed behaviour, so results are comparable across providers.

Selection order:
  1. ``DDBT_PROVIDER``      — "anthropic" | "gemini" (explicit env wins)
  2. ``ddbt.json``          — the project's declared provider (see core/config.py)
  3. auto-detect from keys  — GEMINI_API_KEY / GOOGLE_API_KEY → gemini,
                              else ANTHROPIC_API_KEY (and no Gemini key) → anthropic
  4. default                — GEMINI (the project default)

``DDBT_JUDGE_MODEL`` (or ``DDBT_MODEL``), then ``ddbt.json`` "model", override the model id.

    export GEMINI_API_KEY=...                     # → gemini-2.5-flash (default)
    export DDBT_PROVIDER=anthropic                # → claude-haiku-4-5
    export DDBT_JUDGE_MODEL=gemini-2.5-pro        # → override the model id

Every entry point prints ``describe()`` before a run. If that line does not say what you
expect, stop: the judge fails CLOSED without a key, and a fail-closed run looks exactly
like a perfect score until you check the benign control.
"""

from __future__ import annotations

import os
from pathlib import Path

ANTHROPIC_DEFAULT = "claude-haiku-4-5"
GEMINI_DEFAULT = "gemini-2.5-flash"

_env_loaded = False


def load_env() -> None:
    """Load ``.env`` into the environment, once, from the cwd or any parent directory.

    Hooks, benchmarks and demos are all launched in ways that do not inherit an
    interactively-exported key, and a missing key does not raise — the judge fails CLOSED,
    which is indistinguishable from a confident DENY. That failure mode already produced
    one bogus 100% benchmark result, so the key is loaded here, in the one place every
    entry point goes through.

    Real environment variables always win: ``.env`` only fills in what is not already set.
    Hand-rolled rather than depending on python-dotenv — it is a dozen lines and this
    runs on the security path.
    """
    global _env_loaded
    if _env_loaded:
        return
    _env_loaded = True
    here = Path.cwd().resolve()
    for d in (here, *here.parents):
        f = d / ".env"
        if not f.is_file():
            continue
        try:
            for raw in f.read_text().splitlines():
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k = k.strip().removeprefix("export ").strip()
                v = v.strip().strip('"').strip("'")
                if k and k not in os.environ:  # never override the real environment
                    os.environ[k] = v
        except OSError:
            pass
        return


def active_provider() -> str:
    """Resolve the provider name without constructing anything. Order: DDBT_PROVIDER env →
    ddbt.json → key auto-detect → project default (gemini)."""
    load_env()
    from ddbt.core import config

    explicit = config.provider()  # env DDBT_PROVIDER, else ddbt.json "provider"
    if explicit in ("anthropic", "claude"):
        return "anthropic"
    if explicit in ("gemini", "google"):
        return "gemini"
    if os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"):
        return "gemini"
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    return "gemini"  # project default — chosen even with no key, so failures say "gemini"


def default_model(provider: str | None = None) -> str:
    from ddbt.core import config

    provider = provider or active_provider()
    override = config.model()  # env DDBT_JUDGE_MODEL/DDBT_MODEL, else ddbt.json "model"
    if override:
        return override
    return GEMINI_DEFAULT if provider == "gemini" else ANTHROPIC_DEFAULT


def active_judge(cwd=None) -> str:
    """Which decider to use: "sift" (default, non-LLM) or "llm" (flagged fallback).
    Order: DDBT_JUDGE env → ddbt.json "judge" → default "sift"."""
    from ddbt.core import config
    env = (os.environ.get("DDBT_JUDGE") or "").strip().lower()
    if env in ("sift", "llm"):
        return env
    val = str(config.load(cwd).get("judge", "sift")).strip().lower()
    return val if val in ("sift", "llm") else "sift"


def make_step_judge(model: str | None = None, cwd=None, **kwargs):
    """Build the step-judge. DEFAULT is the non-LLM sift judge; the LLM is a FLAGGED fallback
    (DDBT_JUDGE=llm, or ddbt.json "judge": "llm"). If sift is selected but its model/deps are
    missing, we fall back to the LLM so enforcement never silently drops."""
    if active_judge(cwd) == "sift":
        from ddbt.judge.sift_judge import SiftJudge
        sift = SiftJudge.load(cwd=cwd)
        if sift is not None:
            return sift
        # sift requested but unavailable → fall through to the LLM so the gate still works
    provider = active_provider()
    model = model or default_model(provider)
    if provider == "gemini":
        from ddbt.judge.gemini import GeminiStepJudge

        return GeminiStepJudge(model, **kwargs)
    from ddbt.judge.step_judge import AnthropicStepJudge

    return AnthropicStepJudge(model, **kwargs)


def make_desc_scanner(model: str | None = None):
    """Build the tool-description poison scanner for the configured provider."""
    provider = active_provider()
    model = model or default_model(provider)
    if provider == "gemini":
        from ddbt.judge.gemini import GeminiDescriptionScanner

        return GeminiDescriptionScanner(model)
    from ddbt.judge.desc_scanner import AnthropicDescriptionScanner

    return AnthropicDescriptionScanner(model)


def key_present(provider: str | None = None) -> bool:
    """Is a usable API key actually set for the chosen provider?"""
    provider = provider or active_provider()
    if provider == "gemini":
        return bool(os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"))
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def describe() -> str:
    """One line for logs/benchmark headers: which model actually decided."""
    provider = active_provider()
    return f"{provider}:{default_model(provider)}"


_announced = False


def preflight(what: str = "run") -> None:
    """Print which model will decide, and abort loudly if no key is set.

    Benchmarks MUST call this. The judge and the scanner both fail closed, so without a
    key every case returns "blocked" and the run reports a flawless score. Refusing to
    start is the only safe behaviour — a wrong number is worse than no number.
    """
    global _announced
    provider = active_provider()
    if not _announced:  # a runner and its suite may both call this; announce once
        print(f"decider: {describe()}")
        _announced = True
    if not key_present(provider):
        var = "GEMINI_API_KEY" if provider == "gemini" else "ANTHROPIC_API_KEY"
        raise SystemExit(
            f"\n  ABORT — no {var} found (checked the environment and .env).\n"
            f"  Every judgement would fail closed, and this {what} would report a\n"
            f"  perfect score made entirely of errors. Set the key and re-run.\n"
        )
