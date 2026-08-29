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


def lookup(category: str) -> Mitre:
    return MAP.get((category or "").lower(), _UNKNOWN)


def describe(category: str, decision: str | None = None) -> str:
    """'<Tactic> (<TA-ID>) · <severity>' — severity escalates to high on a DENY."""
    m = lookup(category)
    sev = "high" if (decision or "").upper() == "DENY" and m.severity != "high" else m.severity
    return f"{m.label()} · {sev}"
