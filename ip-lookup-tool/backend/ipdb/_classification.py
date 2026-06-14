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

# ip2proxy proxy_type → IntelMQ. DCH (datacenter/hosting) intentionally absent:
# it has no clean IntelMQ mapping, so normalize() passes it through RAW ("dch")
# rather than mislabeling it "proxy" or bloating the vocabulary with ad-hoc types.
PROXY_MAP = {
    "vpn": "proxy",
    "pub": "proxy",
    "tor": "tor",
}

# OTX pulse threat_type -> IntelMQ. Populate from REST /pulses/subscribed
# actual field values during Task 8.
OTX_MAP: dict[str, str] = {}


def normalize(raw_type, mapping: dict) -> str:
    """Map a source-native category to a CONTROLLED IntelMQ classification.type
    (the cross-source corroboration axis).

    A clearly-mapped value (present in `mapping` AND in the vocabulary) is used
    as-is. Anything else -> "other" (a controlled bucket that still participates
    in corroboration). Raw native values are NOT passed through here — sources
    that want to preserve an unmappable native value stash it in `extra` (see
    ip2proxy._proxy_evidence). This keeps the vocabulary from growing on every
    edge case while keeping the corroboration axis intact.
    """
    key = (raw_type or "").strip().lower()
    mapped = mapping.get(key)
    if mapped and mapped in CLASSIFICATION_TYPES:
        return mapped
    return "other"
