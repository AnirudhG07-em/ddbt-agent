#!/usr/bin/env python
"""Merge a shell sandbox's settings (e.g. em-bash temp.json) into a ddbt.json — the UNION of ours and
theirs: their allowed domains become ddbt's trusted web hosts, their + ddbt's secret paths are unioned
into the file deny floor (deny is always additive), their denied domains are added to web.deny.

The sandbox's write-allow list is NOT mapped onto ddbt (ddbt guards exfil/destruction/known-attacks,
not write-location — importing it would only over-restrict ddbt's own reads). Cloud-metadata SSRF stays
blocked even if localhost/loopback is allow-listed (net_filter honours the allow-list, never metadata).

    uv run python scripts/merge_sandbox.py [sandbox.json] [out.json]     # defaults: temp.json → ddbt.json
"""
import json
import sys

sandbox = sys.argv[1] if len(sys.argv) > 1 else "temp.json"
out = sys.argv[2] if len(sys.argv) > 2 else "ddbt.json"
sb = json.load(open(sandbox))
net, fs = sb.get("network", {}), sb.get("filesystem", {})

def dom(d):                       # ".npmjs.org" -> "npmjs.org" (ddbt matches host + subdomains by suffix)
    return d.lstrip(".").lower()

_DIRS = {"~/.ssh", "~/.aws", "~/.gnupg", "~/.config/gcloud"}
def path_glob(p):                 # a secret DIR -> dir/* ; a concrete file kept as-is
    p = p.rstrip("/")
    return p + "/*" if p in _DIRS else p

# denyWrite patterns that are really extensions/names -> recursive globs
_WRITE = {".env": "**/.env*", ".env.": "**/.env*", ".pem": "**/*.pem", "*.key": "**/*.key"}

DDBT_FLOOR = ["~/.ssh/*", "**/id_rsa*", "~/.aws/*", "**/credentials*", "**/*.pem", "**/.env*"]
deny = DDBT_FLOOR + [path_glob(p) for p in fs.get("denyRead", [])] \
                  + [_WRITE.get(p, path_glob(p)) for p in fs.get("denyWrite", [])]
seen = set()
deny = [x for x in deny if not (x in seen or seen.add(x))]

cfg = {
    "judge": "sift", "ddbt": True, "gate_offgoal": True,
    "goal_shift": "allow",        # shell: follow the user's changing intent; only injections are blocked
    "deny_mode": "block",
    "policy": {
        "tools": {"allow": ["Read", "Grep", "Glob", "LS", "Bash", "Write", "Edit", "NotebookRead", "TodoWrite"], "deny": []},
        "files": {"deny": deny},
        "web": {"allow": sorted({dom(d) for d in net.get("allowedDomains", [])}),
                "deny": sorted({dom(d) for d in net.get("deniedDomains", [])})},
        "email": {"allow": [], "deny": []},
        "quotas": {},
    },
}
json.dump(cfg, open(out, "w"), indent=2)
print(f"wrote {out}  ({len(deny)} secret-deny paths · {len(cfg['policy']['web']['allow'])} trusted domains)")
