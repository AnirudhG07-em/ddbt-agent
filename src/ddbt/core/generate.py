"""Offline, one-shot LLM text generation — for AUTHORING only (ddbt create-rules).

This is NOT part of the runtime guard (which is LLM-free). It runs only when a human explicitly asks
ddbt to draft rule content, once, and the result is saved as a static rule-pack that the guard then
uses via embeddings. Tries GEMINI then ANTHROPIC, loading keys from the environment or a nearby .env.
"""

from __future__ import annotations

import os
from pathlib import Path


def _load_env() -> None:
    for base in (Path.cwd(), *Path.cwd().parents):
        f = base / ".env"
        if f.is_file():
            for line in f.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip('"\''))
            return


_DEFAULT_MODEL = {"gemini": "gemini-2.5-flash", "anthropic": "claude-haiku-4-5-20251001"}


def available() -> str | None:
    """Which provider we can use ('gemini' | 'anthropic'), or None if no key is present."""
    _load_env()
    if os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"):
        return "gemini"
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    return None


def generate(prompt: str, provider: str | None = None, model: str | None = None) -> str:
    """One prompt → text. `provider`/`model` override the auto-detected defaults (from config.llm()).
    Raises if the chosen provider has no key or the call fails."""
    _load_env()
    prov = (provider or available() or "").lower()
    model = model or _DEFAULT_MODEL.get(prov)
    if prov == "gemini":
        from google import genai
        client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"))
        return client.models.generate_content(model=model, contents=prompt).text or ""
    if prov == "anthropic":
        import anthropic
        m = anthropic.Anthropic().messages.create(model=model, max_tokens=8000,
                                                  messages=[{"role": "user", "content": prompt}])
        return "".join(b.text for b in m.content if getattr(b, "type", None) == "text")
    raise RuntimeError("no LLM available — set GEMINI_API_KEY or ANTHROPIC_API_KEY (or add one to .env), "
                       "or configure ddbt.json \"llm\": {\"provider\": ...}")
