"""IntelMQ classification.type vocabulary + native→IntelMQ mapping helpers.

Governance: add new classification.type values to CLASSIFICATION_TYPES with a
short comment. Add per-source `{native: intelmq}` maps alongside the source.
No separate YAML/versioning process (YAGNI for this tool's scale).
"""

# IntelMQ classification.type subset relevant to IP threat intel. Extensible.
CLASSIFICATION_TYPES = frozenset({
    "blacklist",            # generic curated blocklist, no subcategory available
    "c2-server",            # command & control
    "malware-distribution", # serves/delivers malware (e.g. ThreatFox payload_delivery)
    "malware",              # malware sample / payload
    "scanner",              # aggressive scanning
    "brute-force",          # credential/protocol brute force (e.g. blocklist_de ssh)
    "phishing",
    "botnet",
    "exploit",
    "proxy",
    "tor",
    "vulnerable-system",
    "misconfiguration",
    "abuse-reports",
    "spam",
    "ddos",
    "other",                # fallback for unmappable values
})

THREATFOX_MAP = {
    "botnet_cc": "c2-server",
    "payload_delivery": "malware-distribution",
    "payload": "malware",
    "cc_skimming": "phishing",
}

# blocklist_de attack-type code -> IntelMQ. VERIFY codes against
# https://www.blocklist.de/en/export.html before relying on them (Task 7).
BLOCKLIST_DE_MAP = {
    "ssh": "brute-force",
    "mail": "spam",
    "bots": "botnet",
    "bruteforcelogin": "brute-force",
    "apache": "scanner",
}

# OTX pulse threat_type -> IntelMQ. Populate from REST /pulses/subscribed
# actual field values during Task 8.
OTX_MAP: dict[str, str] = {}


def normalize(raw_type, mapping: dict, default: str = "blacklist") -> str:
    """Map a source-native category to an IntelMQ classification.type.

    Unknown raw values fall back to `default`; if `default` itself is not in
    the vocabulary, return "other". Output is always a valid vocab member.
    """
    v = mapping.get((raw_type or "").strip().lower(), default)
    return v if v in CLASSIFICATION_TYPES else "other"
