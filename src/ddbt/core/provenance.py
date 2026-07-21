"""Where did this value come from? — structural provenance over tool output.

The old check asked "does this argument appear in recent quarantined text?" and called any
match *injection-derived*. That is wrong in the common case, because the normal agent
pattern IS read-then-act: read the email, reply to the sender; list the repo, edit a file.
Almost every legitimate argument comes from tool output. Flagging all of them makes the
defence unusable, and flagging none of them makes it useless.

The real question is not *did this come from tool output* but **could an attacker have
chosen it?** That has a purely structural answer:

    An identifier that IS the complete value of a field was chosen by the schema of the
    system that produced it   -> FIELD   (first-party; an attacker cannot pick it freely)

    An identifier found EMBEDDED INSIDE a longer free-text string was chosen by whoever
    wrote that text                                          -> CONTENT (attacker-authorable)

So in a mail response:

    {"from": "news@site.com",                      -> FIELD    the mail system set this
     "subject": "Your Global Economy update",      -> (no identifier in it)
     "body": "...email them to amy@evil.com..."}   -> CONTENT  the sender wrote this

Same data type, same tool, opposite trust — decided by position in the structure, not by
what the text says. No wordlists, and nothing an attacker can reword their way out of:
to get FIELD trust they would have to control the producing system's schema, not its prose.

Note the regexes here EXTRACT identifiers; they never decide policy. Rewriting an address
does not help an attacker, because the label depends on *where it sits*, not what it is.
"""

from __future__ import annotations

import re

# --- identifier extraction (mechanical parsing, not policy) ---
_PATTERNS = (
    ("email", re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]*\w")),
    ("url", re.compile(r"https?://[^\s<>\"')\]]+")),
    ("path", re.compile(r"(?:~|\.{1,2})?/[\w.@~-]+(?:/[\w.@~-]+)*")),
    ("phone", re.compile(r"\+\d[\d\s().-]{6,}\d")),
    ("handle", re.compile(r"@[A-Za-z0-9_]{3,}")),
)
# what may sit between identifiers and still count as a pure list of values ("a@x, b@y")
_SEPARATORS = re.compile(r"^[\s,;|]*$")

FIELD = "field"  # first-party: the producing system chose this
CONTENT = "content"  # attacker-authorable: found inside free text


def extract(value: str) -> list[tuple[str, str]]:
    """Identifiers inside `value`, as (kind, text).

    Patterns are applied in the order of _PATTERNS and each claims its span, so a match is
    never re-reported as a weaker kind: "a@gmail.com" is one email, not an email plus the
    handle "@gmail", and "https://evil.com/x" is one URL, not a URL plus the path
    "/evil.com/x". Without this the same bytes appear under several kinds and every
    downstream count is inflated.
    """
    found: list[tuple[str, str]] = []
    claimed: list[tuple[int, int]] = []
    for kind, pat in _PATTERNS:
        for m in pat.finditer(value):
            start, end = m.span()
            if any(start < c_end and end > c_start for c_start, c_end in claimed):
                continue  # already covered by an earlier, more specific pattern
            hit = m.group(0).rstrip(".,;:)]}'\"")
            if len(hit) < 4:
                continue
            claimed.append((start, start + len(hit)))
            found.append((kind, hit))
    return found


def _walk(obj, path: str = "$"):
    """Yield (json_path, string_leaf) for every string in a nested structure."""
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{path}[{i}]")


def classify(leaf: str, identifiers: list[tuple[str, str]]) -> str:
    """FIELD if the leaf is exactly this set of identifiers, else CONTENT.

    "news@site.com"          -> FIELD    (the leaf IS the identifier)
    "a@x.com, b@y.com"       -> FIELD    (leaf is a list of identifiers, nothing else)
    "mail them at a@x.com"   -> CONTENT  (the identifier is embedded in prose)
    """
    remainder = leaf
    for _, text in identifiers:
        remainder = remainder.replace(text, "", 1)
    return FIELD if _SEPARATORS.match(remainder) else CONTENT


def index_response(response) -> list[dict]:
    """Turn a tool response into provenance rows: every identifier, with where it sat.

    Returns [{value, kind, path, origin}]. `response` may be a dict/list (preferred — the
    structure is the whole point) or a bare string, which is treated as free content.
    """
    rows: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for path, leaf in _walk(response):
        leaf = leaf.strip()
        if not leaf:
            continue
        identifiers = extract(leaf)
        if not identifiers:
            continue
        origin = classify(leaf, identifiers)
        for kind, text in identifiers:
            key = (text.lower(), origin)
            if key in seen:
                continue
            seen.add(key)
            rows.append({"value": text, "kind": kind, "path": path, "origin": origin})
    return rows
