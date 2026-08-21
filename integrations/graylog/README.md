# Graylog integration: enrich logs with local IP Radar verdicts

Turn any log line with a source IP into an enriched event — country, ASN,
carrier, and a fused threat verdict — using Graylog's built-in
**Lookup Tables** (HTTP JSONPath data adapter). No plugin, no Graylog
restart: the lookup hits your local IP Radar instance, so enrichment is
unlimited, sub-millisecond, and never leaves the machine.

What you get per IP in one lookup:

| Field | JSON path in adapter |
|---|---|
| Threat verdict | `threat.verdict` (`malicious` / `suspicious` / `benign`) |
| Threat confidence | `threat.confidence` (0–100, multi-source fused) |
| Hit types | `threat.types` (e.g. `["blacklist","proxy"]`) |
| Country | `country.value` |
| ASN | `asn.value` / `as_name.value` |

The `threat.*` fields are the fused view (worst classification by
precedence + its confidence). `classifications.*` keeps the per-type
detail with per-source evidence if you want deeper pipelines.

## Prerequisites

- IP Radar running locally: `http://127.0.0.1:8000`
  (`docker compose up -d --build`, see main README)
- Graylog 4.x+ (Lookup Tables shipped in 3.1+; URL allowlist in 5.x —
  see step 0)

## Step 0 — allowlist the URL (Graylog 5.x only)

Graylog ≥5.1 requires data-adapter URLs to be allowlisted:
**System → Lookup Tables → Allowlist** (or `graylog.conf`:
`lookup_allowlist` / REST `System/LookupTableAllowlist`). Add:

```
http://127.0.0.1:8000/api/lookup/*
```

## Step 1 — data adapter

**System → Lookup Tables → Data Adapters → Create**

- Name: `ipradar-verdict`
- Type: **HTTP JSONPath**
- URL: `http://127.0.0.1:8000/api/lookup/${key}`
- Single value JSONPath: `$.threat.verdict`
- (optional) HTTP headers: none needed — the API is auth-free on localhost
- Refresh: never (IP Radar data refreshes itself in the background)

Test with `141.98.10.63` → expect `malicious`.

## Step 2 — lookup table

**System → Lookup Tables → Create**

- Name: `ipradar-threat`
- Data adapter: `ipradar-verdict` · Cache: default

## Step 3 — repeat for more fields (optional)

One adapter per field, e.g. `ipradar-confidence`
(`$.threat.confidence`), `ipradar-country` (`$.country.value`),
`ipradar-asn` (`$.as_name.value`). Each gets its own lookup table.

## Step 4 — pipeline rule

**System → Pipelines → Manage rules → Create** (connect it to a stream
that carries your logs):

```
rule "ipradar enrich src_ip"
when
    has_field("src_ip")
then
    let verdict     = lookup("ipradar-threat", to_string($message.src_ip));
    let confidence  = lookup("ipradar-confidence", to_string($message.src_ip));
    let country     = lookup("ipradar-country", to_string($message.src_ip));
    set_field("ipradar_verdict", verdict);
    set_field("ipradar_confidence", to_long(confidence));
    set_field("ipradar_country", country);
end
```

Now `ipradar_verdict: malicious` is a first-class field — alert on it,
route by it, chart it:

```
rule "alert on confirmed malicious source"
when
    to_string($message.ipradar_verdict) == "malicious"
    AND to_long($message.ipradar_confidence) >= 70
then
    set_field("alert", true);
end
```

## Notes

- **Why one adapter per field**: the HTTP JSONPath adapter returns a
  single JSONPath per table. The `threat` summary exists precisely so
  integrations need at most 2–3 paths instead of walking
  `classifications.*` per threat type.
- **Unknown IPs** return `benign` / `0` — not an error. Treat "no
  evidence" as a valid answer, not a lookup failure.
- Reserved/private ranges (RFC1918, loopback) return `benign` with
  `is_reserved: true`; see `/api/lookup/10.0.0.1` to inspect.
- The API is unauthenticated by design — keep it bound to localhost /
  a private network (same rule as IP Radar itself).
