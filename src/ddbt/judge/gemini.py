"""Gemini backends for the step-judge and the tool-description scanner.

Same contract, same prompts, same forced-tool-call schema as the Anthropic backends in
``step_judge.py`` / ``desc_scanner.py`` — only the transport differs, so a benchmark run on
Gemini is directly comparable to one on Claude.

Engineering notes specific to Gemini:
  * forced function call — ``FunctionCallingConfigMode.ANY`` + ``allowed_function_names``
    is Gemini's equivalent of Anthropic's ``tool_choice``: the model MUST emit the verdict
    call, so there is no free-text parsing (a parse failure would become a false DENY).
  * ``parameters_json_schema`` takes the identical JSON Schema dict the Anthropic tool uses.
  * thinking is DISABLED (``thinking_budget=0``). The judge is a fast classifier on a fixed
    rubric; thinking tokens add latency and cost without changing the verdict.
  * safety filters are set to BLOCK_NONE. This is essential and not a shortcut: the judge's
    whole job is to READ attack text. A safety filter that refuses the request would be
    indistinguishable from an infra error and would fail closed into a bogus DENY.
  * fails CLOSED — any error → deny, flagged as ``error=True`` (not a security call).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from ddbt.judge.desc_scanner import _SYSTEM as _DESC_SYSTEM
from ddbt.judge.desc_scanner import _TOOL as _DESC_TOOL
from ddbt.judge.desc_scanner import DescVerdict
from ddbt.judge.step_judge import _SYSTEM, _VERDICT_TOOL, StepFacts, Verdict

DEFAULT_MODEL = "gemini-2.5-flash"


def _config(system: str, tool: dict):
    """Build the GenerateContentConfig that forces `tool` to be called."""
    from google.genai import types

    return types.GenerateContentConfig(
        system_instruction=system,
        temperature=0,
        max_output_tokens=512,
        thinking_config=types.ThinkingConfig(thinking_budget=0),
        tools=[
            types.Tool(
                function_declarations=[
                    types.FunctionDeclaration(
                        name=tool["name"],
                        description=tool["description"],
                        parameters_json_schema=tool["input_schema"],
                    )
                ]
            )
        ],
        tool_config=types.ToolConfig(
            function_calling_config=types.FunctionCallingConfig(
                mode=types.FunctionCallingConfigMode.ANY,
                allowed_function_names=[tool["name"]],
            )
        ),
        # the judge must be allowed to read hostile text — see module docstring
        safety_settings=[
            types.SafetySetting(category=c, threshold=types.HarmBlockThreshold.BLOCK_NONE)
            for c in (
                types.HarmCategory.HARM_CATEGORY_HARASSMENT,
                types.HarmCategory.HARM_CATEGORY_HATE_SPEECH,
                types.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
                types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
            )
        ],
    )


_client_lock = threading.Lock()
_shared_client = None


def _client():
    """One shared, retrying client for the whole process.

    Benchmarks fan out across worker threads. Creating a client per thread raced on the
    underlying connection pool and produced `ReadError: Bad file descriptor` — which fails
    CLOSED and is then indistinguishable from a real detection, so it silently corrupts
    results. One client, built once under a lock, with retries on transient errors (the
    Anthropic backend gets these from `max_retries=8`; Gemini needs them stated).
    """
    global _shared_client
    with _client_lock:
        if _shared_client is None:
            import os

            from google import genai
            from google.genai import types

            from ddbt.judge.provider import load_env

            load_env()
            key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
            http = types.HttpOptions(
                timeout=120_000,  # ms
                retry_options=types.HttpRetryOptions(attempts=8, initial_delay=1.0, max_delay=30.0),
            )
            _shared_client = genai.Client(api_key=key, http_options=http) if key else genai.Client(
                http_options=http
            )
        return _shared_client


def _first_call(resp, name: str) -> dict | None:
    """Pull the forced function call's arguments out of the response."""
    for cand in resp.candidates or []:
        for part in (getattr(cand.content, "parts", None) or []):
            fc = getattr(part, "function_call", None)
            if fc is not None and fc.name == name:
                return dict(fc.args or {})
    return None


@dataclass(slots=True)
class GeminiStepJudge:
    """Drop-in replacement for :class:`AnthropicStepJudge`, backed by the Gemini API."""

    model: str = DEFAULT_MODEL
    max_tokens: int = 512  # accepted for signature parity; the cap lives in _config()
    system: str = _SYSTEM  # swappable so we can A/B prompt variants
    _client: object = None
    _cache: dict = field(default_factory=dict)
    _lock: object = field(default_factory=threading.Lock)

    def _client_obj(self):
        if self._client is None:
            self._client = _client()
        return self._client

    def judge(self, facts: StepFacts) -> Verdict:
        key = facts.cache_key()
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        verdict = self._judge_uncached(facts)
        with self._lock:
            self._cache[key] = verdict
        return verdict

    def _judge_uncached(self, facts: StepFacts) -> Verdict:
        try:
            resp = self._client_obj().models.generate_content(
                model=self.model,
                contents=facts.render(),
                config=_config(self.system, _VERDICT_TOOL),
            )
            d = _first_call(resp, "record_verdict")
            if d is None:
                return Verdict.errored("judge returned no verdict function call")
            return Verdict(
                serves_goal=bool(d.get("serves_goal", False)),
                deviation=bool(d.get("deviation", True)),
                harmful=bool(d.get("harmful", False)),
                high_impact=bool(d.get("high_impact", False)),
                requests_secrecy=bool(d.get("requests_secrecy", False)),
                side_task=bool(d.get("side_task", False)),
                accesses_secrets=bool(d.get("accesses_secrets", False)),
                external_exfil=bool(d.get("external_exfil", False)),
                injection_suspected=bool(d.get("injection_suspected", False)),
                reason=str(d.get("reason", "")),
            )
        except Exception as exc:  # fail CLOSED, but FLAG as error (not a real deny)
            return Verdict.errored(f"judge unavailable ({type(exc).__name__}: {exc})"[:200])


@dataclass(slots=True)
class GeminiDescriptionScanner:
    """Drop-in replacement for :class:`AnthropicDescriptionScanner`, backed by Gemini."""

    model: str = DEFAULT_MODEL
    _client: object = None

    def _client_obj(self):
        if self._client is None:
            self._client = _client()
        return self._client

    def scan(self, description: str) -> DescVerdict:
        try:
            resp = self._client_obj().models.generate_content(
                model=self.model,
                contents=f"TOOL DESCRIPTION (untrusted):\n«{description[:4000]}»",
                config=_config(_DESC_SYSTEM, _DESC_TOOL),
            )
            d = _first_call(resp, "record_scan")
            if d is None:
                return DescVerdict.errored("scanner returned no verdict function call")
            return DescVerdict(bool(d.get("poison", True)), str(d.get("kind", "other")), str(d.get("reason", "")))
        except Exception as exc:  # fail closed, but FLAGGED as an error — never a detection
            return DescVerdict.errored(f"scanner unavailable ({type(exc).__name__}: {exc})"[:180])
