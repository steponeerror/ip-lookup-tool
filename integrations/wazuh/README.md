# Wazuh integration: enrich alerts with local IP Radar verdicts

A drop-in replacement angle for the built-in VirusTotal integration: every
Wazuh alert that carries an IP gets a follow-up alert with an ECS
`threat.indicator` payload produced by your **local** IP Radar instance.

Why over the built-in VirusTotal integration:

| | VirusTotal (public API) | IP Radar |
|---|---|---|
| Quota | 500 req/day, 4 req/min | unlimited (localhost) |
| Privacy | every alert IP goes to Google | queries never leave the machine |
| Coverage | files/URLs/hashes | IPs: 29 fused feeds |
| Explainability | black-box score | per-source evidence chain |

## How it works

```
Wazuh alert (with data.src_ip)
   → Integrator module fires custom-ipradar
      → GET http://127.0.0.1:8000/api/lookup/<ip>
      → verdict ≠ benign ⇒ follow-up alert written back into the queue
   → your indexers/Dashboard see: integration.ipradar.* + threat.indicator.*
```

Benign IPs produce **no** follow-up (noise control). IP Radar down?
The script skips enrichment and alerting continues untouched.

## Install

1. IP Radar running on the Wazuh manager host (or reachable from it):

   ```bash
   git clone https://github.com/steponeerror/ip-radar && cd ip-radar
   docker compose up -d --build   # http://127.0.0.1:8000
   ```

2. Copy the script:

   ```bash
   cp integrations/wazuh/custom-ipradar /var/ossec/integrations/
   chown root:wazuh /var/ossec/integrations/custom-ipradar
   chmod 750 /var/ossec/integrations/custom-ipradar
   ```

3. Add to `/var/ossec/etc/ossec.conf` (inside `<ossec_config>`):

   ```xml
   <integration>
     <name>custom-ipradar</name>
     <hook_url>http://127.0.0.1:8000</hook_url>
     <alert_format>json</alert_format>
     <level>3</level>
   </integration>
   ```

   `<level>3</level>` fires on most meaningful alerts — raise it to reduce
   lookup volume. `<hook_url>` is the IP Radar base URL (same field the
   Slack/Shuffle integrations use for their endpoint).

4. Restart: `systemctl restart wazuh-manager`

5. Tail the log: `tail -f /var/ossec/logs/integrations.log` (add `debug` as
   the 5th integration option or run the script by hand with a sample alert
   file to troubleshoot).

## The follow-up alert

```json
{
  "integration": "ipradar",
  "alert_id": 1724250992.2850145,
  "ipradar": {
    "ip": "141.98.10.63",
    "verdict": "malicious",
    "confidence": 80,
    "types": ["blacklist"],
    "is_cdn": false,
    "sources": ["emerging_threats", "firehol", "spamhaus"]
  },
  "threat": {
    "framework": "MITRE ATT&CK",
    "indicator": {
      "name": "141.98.10.63",
      "type": "ipv4-addr",
      "confidence": "High",
      "description": "IP Radar fused verdict: malicious (80/100), types: blacklist, country: LT, ASN: HOSTBALTIC",
      "provider": "IP Radar (emerging_threats, firehol, spamhaus)",
      "sightings": 3
    }
  }
}
```

Dashboard-hunt it with `integration: ipradar` or `threat.indicator.confidence: High`.

## Tuning

- **Only alert at higher confidence**: edit `MIN_CONFIDENCE_TO_ALERT` in the
  script (default `1` — reports every suspicious/malicious verdict).
- **Timeouts**: `LOOKUP_TIMEOUT = 5s`; slow lookups skip enrichment rather
  than block the integrator.
- **IP fields scanned**: `data.src_ip`, `data.dest_ip`, `data.source_ip`,
  `srcip`, `dstip` — deduplicated automatically.

## Notes

- Modeled on Wazuh's bundled `maltiverse` integration (same argument
  contract, same queue-socket event format, ECS `threat.indicator` shape),
  so it behaves like a first-class integration.
- The script never writes to Wazuh internals beyond the analysis queue
  socket; removal = delete file + remove the `<integration>` block.
