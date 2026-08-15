"""IntelMQ classification.type vocabulary + native→IntelMQ mapping helpers.

Governance: add new classification.type values to CLASSIFICATION_TYPES with a
short comment. Add per-source `{native: intelmq}` maps alongside the source.
No separate YAML/versioning process (YAGNI for this tool's scale).
"""

import re

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
    "url": "malware-distribution",
}

# blocklist_de 子列表文件名 -> IntelMQ（2026-08-15 已激活，键=子列表文件名）。
# 源按文件名分发到对应 attack-type（ssh/bruteforcelogin/ftp/imap/sip → brute-force；
# mail → spam；bots/ircbot → botnet；apache → scanner）。strongips/all 无类型信息，
# 不进表，由源代码兜底 blacklist（见 Task 6 实现）。
BLOCKLIST_DE_MAP = {
    "ssh": "brute-force",
    "bruteforcelogin": "brute-force",
    "ftp": "brute-force",
    "imap": "brute-force",
    "sip": "brute-force",
    "mail": "spam",
    "bots": "botnet",
    "ircbot": "botnet",
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

# OTX pulse name protocol keyword -> IntelMQ. The /pulses/activity feed is
# auto-generated "IMMEDIATE THREAT: {PROTO} Intrusion from..." pulses with
# adversary="Automated Scanner". Protocol keywords from the pulse name map
# to IntelMQ categories; unmapped protocols default to "scanner".
OTX_PROTOCOL_MAP = {
    "smtp": "brute-force",
    "ftp": "brute-force",
    "ssh": "brute-force",
    "imap": "brute-force",
    "pop3": "brute-force",
    "rdp": "brute-force",
    "sip": "brute-force",
    "http": "scanner",
    "https": "scanner",
    "apache": "exploit",
    "web": "scanner",
}

# MISP attribute category → IntelMQ. "network activity" deliberately absent:
# most IP attributes land there and it's too vague to map honestly, so it falls
# to "other" (raw category preserved in extra.native_type) — same philosophy as
# ip2proxy DCH in PROXY_MAP. Keys MUST be lowercase — normalize() lowercases the
# input before lookup.
MISP_CATEGORY_MAP = {
    "payload delivery": "malware-distribution",
    "payload installation": "malware",
    "artifacts dropped": "malware",
    "payload type": "malware",
    "spam": "spam",
    "botnet": "botnet",
}

# TweetFeed (0xDanielLopez/TweetFeed) — infosec-X IOC feed. The `tag` field is a
# space-separated hashtag list (e.g. "#C2 #CobaltStrike"); tweetfeed.harvest
# splits it and applies the FIRST mappable hashtag. C2/RAT-infra tags collapse
# to c2-server; malware-family tags without a vocab slot (#ransomware, #APT…)
# fall to "other" with the raw tag preserved in extra.native_type (Convention 2).
TWEETFEED_MAP = {
    "#phishing": "phishing",
    "#c2": "c2-server",
    "#cobaltstrike": "c2-server",
    "#remcos": "c2-server",
    "#sliver": "c2-server",
    "#interactsh": "c2-server",
    "#deimos": "c2-server",
    "#asyncrat": "c2-server",
    "#formbook": "c2-server",
    "#quasar": "c2-server",
    "#malware": "malware",
    "#botnet": "botnet",
    "#mirai": "botnet",
    "#mozi": "botnet",
    "#ddos": "ddos",
}

# URLhaus (abuse.ch) malware-distribution-URL feed. The `tags` column is a
# comma-separated list mixing malware-family names with file/arch noise
# (``32-bit,elf,mips,Mozi``). urlhaus.harvest splits on ``,`` and applies the
# first mappable tag. Only IoT-botnet families map to the ``botnet`` dead slot;
# every other row falls to ``malware-distribution`` (the base classification —
# every URLhaus URL serves malware), so ``other``% stays near 0. Raw tags +
# reporter are preserved in ``extra``.
URLHAUS_MAP = {
    "mirai": "botnet",
    "mozi": "botnet",
    "hajime": "botnet",
}

# urlhaus `threat` 列（row[5]）原值 → IntelMQ。threat 是上游显式定性字段，
# 优先于 tags 映射；malware_download 无可映射值，落 tags 兜底链路。
URLHAUS_THREAT_MAP = {
    "credential_phishing": "phishing",
}

# dataplane.org signal → IntelMQ. sshpwauth/telnetlogin are credential
# brute-force against the sensor; dnsrd = source IPs sending recursive DNS
# queries (probing), not open resolvers — scanner, not misconfiguration.
DATAPLANE_MAP = {
    "sshpwauth": "brute-force",
    "telnetlogin": "brute-force",
    "dnsrd": "scanner",
}

# reportedip (reportedip.de) — CSV `categories` 字段是 ;-分隔数字码。1-58 全码
# 均为官方公开分类(per https://reportedip.com/wp-json/reportedip/v2/categories):
# 1-30 通用攻击,31-58 WordPress 攻击细分。code→IntelMQ 映射基于官方分类名语义。
# 一个 IP 多码 → N evidence(按 canonical 分组);未在表内的未来新增码(59+)→ other 兜底。
# code 9 Open Proxy→proxy、code 29 Zero-Day→exploit 为语义修正(映射语义要对,非数据驱动)。
REPORTEDIP_MAP = {
    # 1-30 通用
    "1": "scanner", "2": "scanner", "14": "scanner",       # DNS compromise/poisoning, port scan
    "3": "phishing", "7": "phishing", "8": "phishing", "17": "phishing",  # fraud/phishing/spoofing
    "4": "ddos", "6": "ddos",
    "5": "brute-force", "18": "brute-force", "22": "brute-force",  # FTP/credential/SSH brute-force
    "9": "proxy",                                          # open proxy
    "10": "spam", "11": "spam", "12": "spam",               # web/email/blog spam
    "15": "exploit", "16": "exploit", "19": "exploit", "21": "exploit",  # hacking/SQLi/bad-bot/web-app
    "20": "malware", "24": "malware", "25": "malware", "26": "malware", "27": "malware",  # exploited/mining/C2/trojan
    "23": "botnet",                                        # IoT targeted
    "28": "other", "29": "exploit", "30": "c2-server",     # supply chain(无净 IntelMQ 槽)/zero-day/nation-state
    "13": "proxy",                                         # VPN IP → proxy(低威胁,归 proxy)
    # 31-58 WordPress 攻击细分
    "31": "brute-force", "32": "brute-force", "33": "brute-force", "34": "brute-force",  # WP login/admin/XML-RPC/REST 爆破
    "35": "exploit", "36": "exploit", "37": "exploit", "38": "exploit",  # WP plugin/theme/core/0-day 漏洞
    "39": "spam", "40": "spam", "41": "spam", "42": "spam", "47": "spam", "49": "spam",  # WP comment/contact/reg/trackback/SEO spam
    "43": "malware", "44": "malware", "45": "malware", "46": "malware",  # WP file-upload/code-inj/DB-inj/backdoor
    "48": "scanner", "55": "scanner", "56": "scanner", "57": "scanner", "58": "scanner",  # WP content-scraping/user-enum/version/plugin scan/config exposure
    "50": "exploit",                                       # WP redirect hijacking
    "51": "ddos",                                          # WP resource exhaustion
    "52": "other", "53": "other", "54": "other",           # WP media/search/cron abuse(无净 IntelMQ 槽)
}

# reportedip code → 官方分类名(per reportedip.com v2/categories API, 2026-08-11)。
# 每码一名;harvest 按组去重。未来新增码(59+)或缺失 → harvest 回退原始码字符串。
REPORTEDIP_CODE_THEMATIC = {
    "1": "DNS Compromise", "2": "DNS Poisoning", "3": "Fraud Orders",
    "4": "DDoS Attack", "5": "FTP Brute-Force", "6": "Ping of Death",
    "7": "Phishing", "8": "Fraud VoIP", "9": "Open Proxy",
    "10": "Web Spam", "11": "Email Spam", "12": "Blog Spam",
    "13": "VPN IP", "14": "Port Scan", "15": "Hacking",
    "16": "SQL Injection", "17": "Spoofing", "18": "Brute-Force",
    "19": "Bad Web Bot", "20": "Exploited Host", "21": "Web App Attack",
    "22": "SSH", "23": "IoT Targeted", "24": "Cryptocurrency Mining",
    "25": "Ransomware C&C", "26": "Banking Trojan", "27": "Mobile Malware",
    "28": "Supply Chain Attack", "29": "Zero-Day Exploit", "30": "Nation State",
    "31": "WP Login Brute Force", "32": "WP Admin Brute Force",
    "33": "WP XML-RPC Brute Force", "34": "WP REST API Abuse",
    "35": "WP Plugin Exploit", "36": "WP Theme Exploit",
    "37": "WP Core Exploit", "38": "WP Zero-Day Exploit",
    "39": "WP Comment Spam", "40": "WP Contact Form Spam",
    "41": "WP Registration Spam", "42": "WP Trackback Spam",
    "43": "WP File Upload Malware", "44": "WP Code Injection",
    "45": "WP Database Injection", "46": "WP Backdoor Installation",
    "47": "WP SEO Spam", "48": "WP Content Scraping", "49": "WP Fake SEO Bot",
    "50": "WP Redirect Hijacking", "51": "WP Resource Exhaustion",
    "52": "WP Media Library Abuse", "53": "WP Search Abuse", "54": "WP Cron Abuse",
    "55": "WP User Enumeration", "56": "WP Version Scanning",
    "57": "WP Plugin Scanning", "58": "WP Config Exposure",
}


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


# ── MISP severity + type inference ──────────────────────────────────────────
# MISP attribute category alone is too coarse: ~99.8% of IP attributes land in
# "Network activity" (→ "other") regardless of what the event is actually about.
# These resolvers use the signals MISP already gives us — Event.threat_level_id
# (severity), the event title (what the event is about), and to_ids — to produce
# a faithful classification instead of a blanket malicious/other.

# Event.threat_level_id (1=High … 4=Undefined) → (verdict, reliability).
# Reliability scales the merged confidence (mean reliability × 100) per attribute.
MISP_THREAT_LEVEL: dict[str, tuple[str, float]] = {
    "1": ("malicious", 0.80),   # High
    "2": ("malicious", 0.60),   # Medium
    "3": ("suspicious", 0.40),  # Low
    "4": ("suspicious", 0.25),  # Undefined
}

# Event-title keyword → IntelMQ type, checked in priority order (first match
# wins). Patterns are lowercase-matched against the lowercased title. Order
# matters: c2 before malware (CobaltStrike is C2), brute before scan
# (pop3gropers is a brute-force feed), etc.
_MISP_TITLE_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b(c2|c&c|cnc|command[- ]?and[- ]?control|cobalt\s*strike)\b"), "c2-server"),
    (re.compile(r"phish"), "phishing"),
    (re.compile(r"(brute|pop3gropers)"), "brute-force"),
    (re.compile(r"\bscan"), "scanner"),
    (re.compile(r"botnet|mirai|fbot|hajime"), "botnet"),
    (re.compile(r"(malware|trojan|backdoor|worm|stealer|loader|ransom|infosteal|vawtrak|emotet|njrat|locky|trickbot)"), "malware"),
    (re.compile(r"\bspam"), "spam"),
    (re.compile(r"ddos"), "ddos"),
    (re.compile(r"\bvpn\b|astrill"), "proxy"),
    (re.compile(r"\bproxy\b"), "proxy"),
    (re.compile(r"\btor\b"), "tor"),
]
# Generic OSINT IOC/blocklist dumps (no subcategory available) → blacklist
# rather than a misleading concrete type or "other".
_MISP_GENERIC_BLOCKLIST = re.compile(r"(maltrail|\bioc\b|osint.*(indicator|intel)|blocklist|\bfeed\b)")

# Recognised malware family names for inline tag display. Lowercased, hyphenated.
_MISP_FAMILY_RE = re.compile(
    r"(mirai[-/]?(?:fbot)?|fbot|vawtrak|emotet|njrat|locky|trickbot|vidar|redline|dcrat|hajime|cobalt\s*strike)",
    re.IGNORECASE,
)


def resolve_misp_type(category: str, info: str) -> str:
    """Infer an IntelMQ classification.type from a MISP attribute's category
    and event title.

    Order: concrete title keyword → mapped category → generic blocklist rescue
    → "other". The title is usually the richest signal; the category map covers
    the rare explicit categories (Payload delivery, etc.); the blocklist rescue
    turns generic IOC dumps into "blacklist" instead of the vague "other".
    """
    title = (info or "").lower()
    for pattern, ctype in _MISP_TITLE_RULES:
        if pattern.search(title):
            return ctype
    mapped = normalize(category, MISP_CATEGORY_MAP)
    if mapped != "other":
        return mapped
    if _MISP_GENERIC_BLOCKLIST.search(title):
        return "blacklist"
    return "other"


def extract_malware_family(info: str) -> str | None:
    """Pull a short malware-family name from the event title, or None.

    Returned lowercase with normalised separators (e.g. "Mirai-Fbot" →
    "mirai-fbot", "CobaltStrike" → "cobalt-strike") so it renders cleanly as a
    threat-tag suffix.
    """
    m = _MISP_FAMILY_RE.search(info or "")
    if not m:
        return None
    return re.sub(r"[\s/]+", "-", m.group(1).lower())

