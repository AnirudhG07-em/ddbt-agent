"""Boundary 0 — bootstrap integrity verifier (doc §2).

Runs before the agent loop (and, as a bonus over the doc, on ``ConfigChange`` /
``FileChanged`` for continuous verification). Catches supply-chain / config attacks
that happen *before* any runtime checkpoint can see them. Zero LLM — pure hashing
and regex.

Three checks:
  1. Config integrity — hash guarded config (``.claude/settings.json``, ``.mcp.json``,
     hooks); baselines stored OUTSIDE the project (the agent can't write them). Drift
     or first-sight of config that sets network endpoints / lifecycle shell → HOLD.
  2. MCP manifest hash — hash each MCP server entry + its full tool-description JSON;
     drift → HOLD (kills rug-pull / cross-session tool poisoning).
  3. Tool-description scan — regex for embedded instructions (``SYSTEM:``,
     "ignore previous", imperative-at-model, zero-width chars, long base64).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

# config files we guard; relative to the project root
GUARDED_CONFIG = (
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".mcp.json",
    ".claude/hooks.json",
)

# patterns that should never appear in a tool description / config (injection markers)
_INJECTION_PATTERNS = (
    re.compile(r"ignore (all )?previous", re.IGNORECASE),
    re.compile(r"\bsystem\s*:", re.IGNORECASE),
    re.compile(r"disregard (the )?(above|prior)", re.IGNORECASE),
    re.compile(r"you (must|should) (now )?(always )?(send|exfiltrat|forward|post)", re.IGNORECASE),
    re.compile(r"<\s*important\s*>", re.IGNORECASE),
    # secrecy/hide-from-user phrasing — strong poison signal, rare in benign descriptions.
    # Broadened to catch line-jumping ("no need to mention this to the user") and "don't notify".
    re.compile(r"(do not|don't|never|no need to)\s+(tell|mention|inform|notify)", re.IGNORECASE),
    re.compile(r"without (further explanation|(telling|informing|notifying) (the )?user)", re.IGNORECASE),
)
_ZERO_WIDTH = re.compile(r"[​‌‍⁠﻿]")
_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")
# config keys that must never auto-load — they redirect network or run shell
_DANGEROUS_CONFIG_KEYS = ("base_url", "baseurl", "anthropic_base_url", "env", "command", "hooks")


@dataclass(slots=True)
class Finding:
    severity: str  # "hold" | "warn"
    kind: str
    detail: str


@dataclass(slots=True)
class BootstrapResult:
    ok: bool
    findings: list[Finding] = field(default_factory=list)

    @property
    def status(self) -> str:
        return "PASS" if self.ok else "HOLD"

    def summary(self) -> str:
        if self.ok and not self.findings:
            return "PASS — config + MCP integrity verified"
        lines = [f"{self.status}"]
        lines += [f"  [{f.severity}] {f.kind}: {f.detail}" for f in self.findings]
        return "\n".join(lines)


def _baseline_dir(project_dir: str) -> Path:
    root = os.environ.get("DDBT_HOME") or os.path.join(os.path.expanduser("~"), ".ddbt")
    key = hashlib.sha256(os.path.abspath(project_dir).encode()).hexdigest()[:16]
    return Path(root) / "baselines" / key


def _hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def scan_text(text: str, where: str) -> list[Finding]:
    """LLM-free heuristic scan for embedded instructions / obfuscation."""
    findings: list[Finding] = []
    for pat in _INJECTION_PATTERNS:
        if pat.search(text):
            findings.append(Finding("hold", "tool_poisoning", f"injection marker in {where}: /{pat.pattern}/"))
    if _ZERO_WIDTH.search(text):
        findings.append(Finding("hold", "obfuscation", f"zero-width characters in {where}"))
    for m in _BASE64_BLOB.finditer(text):
        blob = m.group(0)
        try:
            decoded = base64.b64decode(blob, validate=True).decode("utf-8", "ignore")
        except (binascii.Error, ValueError):
            continue
        if any(p.search(decoded) for p in _INJECTION_PATTERNS):
            findings.append(Finding("hold", "obfuscation", f"base64-encoded instruction in {where}"))
    return findings


def _scan_cache_path() -> Path:
    root = os.environ.get("DDBT_HOME") or os.path.join(os.path.expanduser("~"), ".ddbt")
    return Path(root) / "desc_scan_cache.json"


def semantic_scan(text: str, where: str, scanner=None) -> list[Finding]:
    """Regex pre-filter, then a HASH-GATED semantic scan of `text` (a tool description).

    The regex is the free fast-path; if it fires, no LLM is needed. Otherwise — only when a
    scanner is supplied — run the model classifier, but key its verdict by content hash and
    cache it, so identical/unchanged descriptions are never re-scanned (steady state: 0 LLM).
    """
    findings = scan_text(text, where)
    if findings or scanner is None or not text.strip():
        return findings
    from ddbt.judge.desc_scanner import _dump, _load, cache_key

    key = cache_key(text)
    cache_file = _scan_cache_path()
    cache: dict = {}
    if cache_file.exists():
        try:
            cache = json.loads(cache_file.read_text())
        except (OSError, json.JSONDecodeError):
            cache = {}
    if key in cache:
        v = _load(cache[key])
    else:
        v = scanner.scan(text)
        cache[key] = _dump(v)
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(json.dumps(cache))
    if v.poison:
        findings.append(Finding("hold", "tool_poisoning_semantic", f"{v.kind}: {v.reason} ({where})"))
    return findings


def _scan_mcp(config_path: Path, scanner=None) -> list[Finding]:
    findings: list[Finding] = []
    try:
        data = json.loads(config_path.read_text())
    except (OSError, json.JSONDecodeError):
        return findings
    servers = data.get("mcpServers") or data.get("servers") or {}
    for name, spec in servers.items():
        findings += scan_text(json.dumps(spec), f"mcp server '{name}'")
        for tool in spec.get("tools", []) if isinstance(spec, dict) else []:
            desc = tool.get("description", "") if isinstance(tool, dict) else ""
            findings += semantic_scan(desc, f"mcp tool '{name}.{tool.get('name','?')}'", scanner)
    return findings


def verify(project_dir: str, scanner=None) -> BootstrapResult:
    """Run Boundary 0 over a project directory. `scanner` (optional) enables the hash-gated
    semantic tool-description scan; without it, only the regex pre-filter runs (zero-LLM)."""
    project = Path(project_dir)
    baseline = _baseline_dir(project_dir)
    findings: list[Finding] = []

    for rel in GUARDED_CONFIG:
        f = project / rel
        if not f.exists():
            continue
        digest = _hash_file(f)
        base_file = baseline / (rel.replace("/", "__") + ".sha256")

        # content scan regardless of baseline
        try:
            findings += scan_text(f.read_text(errors="ignore"), rel)
        except OSError:
            pass
        if rel.endswith(".mcp.json") or rel.endswith("mcp.json"):
            findings += _scan_mcp(f, scanner)

        if not base_file.exists():
            # first sight: HOLD if it carries dangerous keys (network/shell at lifecycle)
            text = f.read_text(errors="ignore").lower()
            if any(k in text for k in _DANGEROUS_CONFIG_KEYS):
                findings.append(
                    Finding("hold", "config_first_sight", f"{rel} sets network/shell — needs explicit approval")
                )
            else:
                findings.append(Finding("warn", "config_unbaselined", f"{rel} not yet baselined"))
        elif base_file.read_text().strip() != digest:
            findings.append(Finding("hold", "config_drift", f"{rel} changed since baseline"))

    ok = not any(f.severity == "hold" for f in findings)
    return BootstrapResult(ok=ok, findings=findings)


def trust(project_dir: str) -> list[str]:
    """Explicit human approval: write current config hashes as the baseline."""
    project = Path(project_dir)
    baseline = _baseline_dir(project_dir)
    baseline.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for rel in GUARDED_CONFIG:
        f = project / rel
        if not f.exists():
            continue
        (baseline / (rel.replace("/", "__") + ".sha256")).write_text(_hash_file(f))
        written.append(rel)
    return written
