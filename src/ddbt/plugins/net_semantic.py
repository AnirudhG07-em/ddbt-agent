"""net_semantic — meaning-based egress review, the semantic complement to net_filter's keyword rules.

net_filter decides on STRUCTURE (denylists, SSRF ranges, high-impact verbs, destination provenance) —
precise, but only catches what's enumerated. This layer decides on MEANING, in the embedding space of
the Model2Vec model sift already loads (distributional hypothesis: similar meaning → nearby vectors).
It answers two questions no keyword can:

  1. Payload sensitivity — is what's leaving semantically LIKE credentials / customer-PII / source code /
     internal-financial data, even phrased in words no regex lists? (nearest-centroid over exemplars)
  2. Goal-relatedness — is the destination semantically related to the user's stated task? An attacker's
     endpoint is essentially never task-relevant (cosine(task, destination) is low). This is the Task
     Shield principle, made deterministic.

Because static embeddings are topical and reword-able, this layer is ASK-ONLY: it raises a human check
when a sensitive-looking payload heads to a task-unrelated external destination. It NEVER denies on its
own — a DENY always requires a deterministic corroborator (that's net_filter's job). Reuses the sift
encoder (zero extra memory); degrades to a no-op if the model isn't available.

Design note — we deliberately do NOT classify the destination by embedding its hostname. Measured: bare
hosts don't carry embeddable purpose (mean host×purpose cosine ~0.16, flat); only dictionary-word hosts
(github.io, pastebin.com) classify, and those the net_filter denylist already handles precisely, while
the ones that matter (billing.internal, payroll-run.io, novel hosts) are noise. The destination axis is
served by net_filter (deterministic reputation) + goal-relatedness here — adding host-purpose centroids
would add noise, not signal. Both thresholds are calibrated: bench/calibrate_net_semantic.py.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import numpy as np

from ddbt.core.ledger import MAX_SCAN_CHARS, destinations, flatten, is_external
from ddbt.judge.embedder import get_encoder
from ddbt.plugins.base import Plugin, PluginContext, PreVerdict

# Exemplars define each concept by MEANING — a payload need only be semantically near them, not match
# any keyword. Extend per workspace via ddbt.json {"net_semantic": {"exemplars": {"class": [...]}}}.
_SENSITIVE = {
    "credentials": [
        "aws_secret_access_key = AKIAIOSFODNN7EXAMPLE", "-----BEGIN RSA PRIVATE KEY-----",
        "api key sk-live-abcdef bearer token", "password: hunter2 login credentials",
        "database connection string with username and password", "oauth refresh token eyJhbGciOi",
        "ssh private key id_rsa", "service account json private_key",
    ],
    "customer_pii": [
        "customer full name and social security number 123-45-6789", "list of user emails and phone numbers",
        "patient medical record diagnosis and treatment history", "credit card number 4111 1111 1111 1111 cvv 123",
        "home mailing addresses of our clients", "date of birth and passport number", "payroll and salary details",
    ],
    "source_code": [
        "def authenticate(user): return db.query(select * from users)", "import os\nclass PaymentService:",
        "proprietary ranking algorithm implementation internal", "private repository source code and secrets",
        "our internal microservice handler and config", "function that signs requests with the master key",
    ],
    "financial_internal": [
        "confidential quarterly revenue projections unreleased", "internal budget and margin spreadsheet",
        "pre-announcement earnings figures material non-public", "merger and acquisition deal terms confidential",
        "board deck strategy and financials internal only",
    ],
}
# 'public_benign' must represent the FULL benign register — not just small talk but the everyday
# WORK-TOPICAL content that is public/non-sensitive (roadmaps, docs, marketing, already-released
# figures, OSS). Without the business register here, ordinary work text reads as 'sensitive' by
# being merely closer to a sensitive centroid than to chit-chat. Kept disjoint from the eval set.
_PUBLIC = [
    # small talk / operational chatter
    "the weather is nice today thanks", "here is the meeting agenda for tomorrow",
    "status update: the build is passing", "reminder about the team lunch on friday",
    "thanks for your help, talk soon", "great work on the demo everyone",
    # benign WORK-TOPICAL (public / non-sensitive) — the register the hard-negatives live in
    "our published product roadmap and release notes for the community",
    "the public developer documentation and api reference guide",
    "a marketing blog post and customer-facing announcement we already shared",
    "the quarterly earnings summary that was already released to investors",
    "open source repository readme, license, and contribution guidelines",
    "the public conference agenda, speaker list, and room assignments",
    "our partners and integrations as listed on the public website",
    "a public job posting and a link to the careers page",
    "high-level headcount plans and which teams are hiring, nothing personal",
    "the customer testimonial they approved for the public case study",
]


class NetSemantic(Plugin):
    name = "net_semantic"
    headline = "Something that looks sensitive is about to leave the workspace."

    # Defaults are CALIBRATED, not guessed — bench/calibrate_net_semantic.py, chosen by 5-fold CV
    # (Fβ=2, recall-weighted) on a held-out egress set with out-of-distribution + MITRE groups:
    # TEST Fβ 0.83, train→test gap +0.03, OOD recall 92%. sensitivity_margin=0.0 is the natural
    # nearest-centroid boundary ("more sensitive-like than public-like"); relatedness carries precision.
    def __init__(self, trusted_domains: tuple[str, ...] = (), exemplars: dict | None = None,
                 sensitivity_margin: float = 0.0, relatedness_max: float = 0.225, min_chars: int = 24):
        self.trusted = tuple(d.lower() for d in trusted_domains)
        self.sensitivity_margin = sensitivity_margin      # top sensitive centroid must beat 'public' by this
        self.relatedness_max = relatedness_max            # destination this-unrelated to the task → suspicious
        self.min_chars = min_chars
        self._sens = {**{k: list(v) for k, v in _SENSITIVE.items()}, **(exemplars or {})}
        self._centroids = None                             # built lazily from the encoder

    def _cache_path(self) -> Path:
        # keyed by exemplar content so a config override rebuilds; kept out of the workspace.
        key = hashlib.blake2b(json.dumps({**self._sens, "_pub": _PUBLIC}, sort_keys=True).encode(),
                              digest_size=8).hexdigest()
        base = Path(os.environ.get("DDBT_HOME") or (Path.home() / ".ddbt")) / "cache"
        return base / f"net_semantic_{key}.npz"

    def _ensure_centroids(self, enc) -> bool:
        """Build (once) the L2-normalized mean vector per class. Cached to disk so the per-call hook
        subprocess loads a tiny npz (~ms) instead of re-embedding 48 exemplars (~100ms) every call."""
        if self._centroids is not None:
            return bool(self._centroids)
        path = self._cache_path()
        try:
            if path.is_file():
                data = np.load(path)
                self._centroids = {k: data[k] for k in data.files}
                return True
        except Exception:  # noqa: BLE001 — a corrupt cache just triggers a rebuild
            pass
        self._centroids = {}
        try:
            for cls, exs in {**self._sens, "public_benign": _PUBLIC}.items():
                v = enc.encode(exs).mean(axis=0)
                n = np.linalg.norm(v)
                self._centroids[cls] = (v / n if n else v).astype(np.float32)
            path.parent.mkdir(parents=True, exist_ok=True)
            np.savez(path, **self._centroids)
        except Exception:  # noqa: BLE001 — any embed/write failure disables the layer, never breaks a call
            self._centroids = {}
        return bool(self._centroids)

    def pre_check(self, tool: str, args: dict, ctx: PluginContext) -> PreVerdict | None:
        text = flatten(args)[:MAX_SCAN_CHARS]
        if len(text) < self.min_chars:
            return None
        dests = destinations(text)
        # Only review a REAL egress to an EXTERNAL destination. No destination → nothing can leak;
        # an internal/trusted destination → inside the boundary. Both skip (precision: a benign command
        # that merely reads sensitive-looking text isn't an exfil).
        if not dests or not any(is_external(d, self.trusted) for d in dests):
            return None
        # a USER-NAMED destination is an intended send (the user chose it) — don't second-guess it,
        # the same rule net_filter uses. This removes benign "send X to the address I gave you" ASKs.
        goal = (ctx.goal or "").lower()
        if any(d in goal for d in dests):
            return None
        enc = get_encoder()
        if enc is None or not self._ensure_centroids(enc):
            return None
        try:
            v = enc.encode([text])[0]
        except Exception:  # noqa: BLE001
            return None
        sims = {cls: float(c @ v) for cls, c in self._centroids.items()}
        pub = sims.pop("public_benign", 0.0)
        sens_cls, sens = max(sims.items(), key=lambda kv: kv[1])
        if sens - pub < self.sensitivity_margin:
            return None   # payload doesn't read as sensitive → nothing to ask about

        # sensitive payload heading outside — is the destination semantically related to the task?
        rel = None
        if ctx.goal and dests:
            try:
                gv = enc.encode([ctx.goal])[0]
                dv = enc.encode([" ".join(dests) + " " + text[:200]])[0]
                rel = float(gv @ dv)
            except Exception:  # noqa: BLE001
                rel = None
        if rel is not None and rel >= self.relatedness_max:
            return None   # the destination fits the task → allow

        where = dests[0] if dests else "an external destination"
        relnote = f", and {where} is not clearly related to your task (rel={rel:.2f})" if rel is not None \
            else f" to {where}"
        return PreVerdict("ask",
            f"Data-egress review · this payload reads like {sens_cls.replace('_', ' ')}{relnote} — "
            f"confirm before sending (semantic check, not a keyword match)", self.name)
