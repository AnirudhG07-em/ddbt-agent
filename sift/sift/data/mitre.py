"""MITRE ATT&CK / ATLAS mapping — the industry-standard vocabulary for "bad actions".

ddbt's internal category names map to recognised MITRE tactics/techniques so a decision speaks the
language security teams already use (and matches how our closest peer, AgentTrust, labels risk). ATT&CK
Enterprise covers the system-level actions an agent-gone-bad takes; ATLAS (AML.*) covers the AI-specific
ones (prompt injection). Output format: "<Tactic> (<TA-ID>) · <severity>", with the one-line reason.

Reference: attack.mitre.org (Enterprise tactics TA0001–TA0043, TA0040) and atlas.mitre.org.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Mitre:
    tactic: str          # human-readable tactic
    tactic_id: str       # TA#### (or AML.T#### for ATLAS)
    technique: str       # representative technique
    technique_id: str    # T#### / AML.T####
    severity: str        # default severity: "high" | "medium" | "low"
    cia: str             # Confidentiality | Integrity | Availability | "-"

    def label(self) -> str:
        return f"{self.tactic} ({self.tactic_id})"


# internal category -> MITRE mapping. Add a category here when you add one to the taxonomy.
MAP: dict[str, Mitre] = {
    "exfiltration":             Mitre("Exfiltration", "TA0010", "Exfil Over Web Service", "T1567", "high", "Confidentiality"),
    "catastrophic_destruction": Mitre("Impact", "TA0040", "Data Destruction", "T1485", "high", "Availability"),
    "mass_action":              Mitre("Impact", "TA0040", "Data Destruction (bulk)", "T1485", "high", "Availability"),
    "secret_theft":             Mitre("Credential Access", "TA0006", "Unsecured Credentials", "T1552", "high", "Confidentiality"),
    "backdoor":                 Mitre("Command and Control", "TA0011", "Application Layer Protocol / reverse shell", "T1071", "high", "Integrity"),
    "deception":                Mitre("Defense Evasion", "TA0005", "Indicator Removal", "T1070", "medium", "Integrity"),
    "security_tampering":       Mitre("Defense Evasion", "TA0005", "Impair Defenses / Inhibit Recovery", "T1562", "high", "Availability"),
    "privilege_escalation":     Mitre("Privilege Escalation", "TA0004", "Abuse Elevation Control", "T1548", "high", "Integrity"),
    "resource_abuse":           Mitre("Impact", "TA0040", "Resource Hijacking", "T1496", "medium", "Availability"),
    "supply_chain":             Mitre("Initial Access", "TA0001", "Supply Chain Compromise", "T1195", "high", "Integrity"),
    "surveillance":             Mitre("Collection", "TA0009", "Screen/Audio/Input Capture", "T1113", "high", "Confidentiality"),
    "financial_harm":           Mitre("Impact", "TA0040", "Financial Theft", "T1657", "high", "-"),
    "harmful_content":          Mitre("Resource Development", "TA0042", "Develop Capabilities (malware/phishing)", "T1587", "high", "-"),
    # axis-1 (anti-injection) — AI-specific, from MITRE ATLAS
    "injection":                Mitre("Prompt Injection", "AML.T0051", "LLM Prompt Injection", "AML.T0051", "high", "Integrity"),
    "unauthorized_change":      Mitre("Impact", "TA0040", "Data Manipulation", "T1565", "medium", "Integrity"),
    # broadened tactic coverage
    "discovery":                Mitre("Discovery", "TA0007", "System/Network/Account Discovery", "T1087", "medium", "Confidentiality"),
    "lateral_movement":         Mitre("Lateral Movement", "TA0008", "Remote Services / Use Alternate Auth", "T1021", "high", "Integrity"),
    "reconnaissance":           Mitre("Reconnaissance", "TA0043", "Gather Victim Identity Information", "T1589", "medium", "Confidentiality"),
    "impersonation":            Mitre("Defense Evasion", "TA0005", "Impersonation / Spoofing", "T1656", "high", "Integrity"),
    "denial_of_service":        Mitre("Impact", "TA0040", "Endpoint / Network Denial of Service", "T1499", "high", "Availability"),
}

_UNKNOWN = Mitre("Suspicious Action", "-", "-", "-", "medium", "-")


# Per-tactic SENSITIVE-CONTENT lexicons — the "what" that makes an action of this tactic dangerous.
# The verb is cheap (curl/send/read are fine); risk comes from the OBJECT touched. Egress of a term
# here is exfil; a read of one is credential access; etc. Extensible: add a keyword to teach a new
# sensitive object for a tactic — no retrain (it's deterministic, read at inference).
import re as _re2

# Broad MITRE ATT&CK / ATLAS coverage — the sensitive OBJECTS/terms characteristic of each tactic.
# Deliberately large and extensible: the more MITRE vocabulary here, the more precisely a decision can
# name WHAT it saw and WHICH tactic it belongs to. Add terms freely; it's deterministic (no retrain).
SENSITIVE_LEXICONS: dict[str, list[str]] = {
    # --- Exfiltration (TA0010) + Collection PII ---
    "exfiltration":             ["passport", "ssn", "social security", "customer list", "customer data",
                                  "customer records", "database dump", "db dump", "user records", "email list",
                                  "mailing list", "contact list", "address book", "tax return", "medical record",
                                  "health record", "patient", "salary", "payroll", "payslip", "date of birth",
                                  "home address", "credit card", "card number", "cvv", "pii", "personal data",
                                  "export all", "dump the", "entire table", "full export"],
    # --- Credential Access (TA0006) ---
    "secret_theft":             ["password", "passwd", "api key", "api_key", "access token", "auth token",
                                  "bearer token", "id_rsa", "id_ed25519", "private key", ".pem", ".key",
                                  ".env", "dotenv", "secret", "secrets manager", "credential", "aws_secret",
                                  "aws_access_key", "client secret", "service account", "keychain", "vault",
                                  "kubeconfig", "htpasswd", "shadow file", "/etc/shadow"],
    # --- Collection / Surveillance (TA0009) ---
    "surveillance":             ["screenshot", "screen capture", "keylog", "keystroke", "webcam", "camera",
                                  "microphone", "record audio", "geolocation", "location", "gps", "contacts",
                                  "clipboard", "browsing history", "call log", "sms log", "photos library"],
    # --- Impact / Destruction (TA0040 T1485/T1561) ---
    "catastrophic_destruction": ["production", "prod db", "backup", "snapshot", "all records", "entire database",
                                  "drop database", "truncate", "rm -rf", "format", "wipe", "volume", "no backup",
                                  "delete all", "purge", "factory reset", "destroy"],
    # --- Impact / Financial (T1657) ---
    "financial_harm":           ["wire transfer", "payment", "pay invoice", "invoice", "bank account",
                                  "routing number", "iban", "swift", "payee", "crypto wallet", "wallet address",
                                  "seed phrase", "private wallet", "refund", "payout", "ach"],
    # --- Privilege Escalation (TA0004) ---
    "privilege_escalation":     ["sudoers", "sudo", "admin role", "administrator", "superuser", "iam policy",
                                  "iam role", "root access", "setuid", "grant all", "grant admin",
                                  "elevate privilege", "make me admin", "add to wheel"],
    # --- Discovery (TA0007) ---
    "discovery":                ["enumerate", "list all users", "scan the network", "nmap", "port scan",
                                  "whoami", "list permissions", "describe instances", "list buckets",
                                  "env variables", "printenv", "list secrets"],
    # --- Lateral Movement (TA0008) ---
    "lateral_movement":         ["ssh into", "pivot", "psexec", "winrm", "remote desktop", "rdp",
                                  "assume role", "reuse token", "lateral", "jump host", "internal host"],
    # --- Reconnaissance (TA0043) ---
    "reconnaissance":           ["employee directory", "org chart", "personal email", "phone number",
                                  "home address", "spear-phish", "spearphish", "target profile", "osint"],
    # --- Command & Control / Persistence (TA0011 / TA0003) ---
    "backdoor":                 ["reverse shell", "bind shell", "authorized_keys", "cron", "crontab",
                                  "systemd service", "startup script", "webshell", "c2", "beacon", "ngrok",
                                  "netcat", "nc -e", "/dev/tcp"],
    # --- Defense Evasion (TA0005) ---
    "security_tampering":       ["disable firewall", "stop antivirus", "disable defender", "clear logs",
                                  "delete logs", "disable audit", "disable logging", "iptables -f",
                                  "selinux disable", "tamper", "delete backups"],
    # --- Impact / Resource Hijacking (T1496) ---
    "resource_abuse":           ["cryptominer", "xmrig", "mining", "gpu instance", "spot fleet",
                                  "fork bomb", "spawn workers", "botnet"],
    # --- Initial Access / Supply Chain (T1195) ---
    "supply_chain":             ["package.json", "requirements.txt", "postinstall", "publish package",
                                  "npm publish", "pypi upload", "dependency", "build pipeline", "ci config",
                                  "github action", "typosquat"],
    # --- Impersonation / Spoofing (T1656) ---
    "impersonation":            ["as if from", "spoof", "forge", "impersonate", "pretend to be",
                                  "on behalf of the ceo", "from the finance team", "verified account"],
    # --- Prompt Injection (ATLAS AML.T0051) ---
    "injection":                ["ignore previous", "ignore all previous", "the email said to",
                                  "the page instructed", "as instructed in the", "follow the instruction in"],
    # --- Data Manipulation (T1565) ---
    "unauthorized_change":      ["alter records", "modify totals", "change the balance", "rewrite history",
                                  "force-push", "falsify", "tamper with data", "edit audit"],
    # --- Denial of Service (T1499) ---
    "denial_of_service":        ["scale to zero", "delete load balancer", "shutdown all", "kill all",
                                  "drain node", "flood", "ddos", "exhaust"],
}
_LEX_PATTERNS = {t: _re2.compile(r"|".join(_re2.escape(k) for k in kws), _re2.I)
                 for t, kws in SENSITIVE_LEXICONS.items()}


def sensitive_tactic(text: str) -> str | None:
    """The MITRE category whose sensitive lexicon best matches `text` (most keyword hits), or None.
    Names WHICH sensitive content is present so a reason can say 'Exfiltration — passport' etc."""
    if not text:
        return None
    best, best_n = None, 0
    low = text.lower()
    for tactic, pat in _LEX_PATTERNS.items():
        n = len(pat.findall(low))
        if n > best_n:
            best, best_n = tactic, n
    return best


# plain-English noun for a tactic — for a calm one-line ASK ("this involves <…> — proceed?").
_FRIENDLY = {
    "exfiltration": "personal or customer data leaving your machine",
    "secret_theft": "credentials or secret keys",
    "surveillance": "screen, camera or keystroke capture",
    "financial_harm": "money movement or payment details",
    "privilege_escalation": "granting elevated access",
    "catastrophic_destruction": "deleting or overwriting a lot at once",
    "discovery": "scanning or enumerating the environment",
    "lateral_movement": "reaching into other systems",
    "reconnaissance": "collecting someone's personal info",
    "backdoor": "a persistent remote connection",
    "security_tampering": "turning off logging or defenses",
    "resource_abuse": "heavy resource use (e.g. mining)",
    "supply_chain": "changing build or dependencies",
    "impersonation": "acting as someone else",
    "injection": "an instruction that came from untrusted content",
    "unauthorized_change": "silently altering records",
    "denial_of_service": "taking a service down",
    "mass_action": "a bulk operation over many records at once",
    "harmful_content": "creating harmful content (malware or phishing)",
    "deception": "hiding or covering its tracks",
}


def friendly_name(category: str) -> str:
    """Plain, non-alarming phrase for a detected sensitive category (for the one-line ASK)."""
    return _FRIENDLY.get((category or "").lower(), "sensitive or personal files")


def lookup(category: str) -> Mitre:
    return MAP.get((category or "").lower(), _UNKNOWN)


def describe(category: str, decision: str | None = None) -> str:
    """A plain, intuitive statement of the detected tactic for the user — no ATT&CK codes. (The exact
    tactic/technique IDs still live in `lookup()`/MAP for the audit log and any machine consumer.)"""
    return f"looks like {friendly_name(category)}"
