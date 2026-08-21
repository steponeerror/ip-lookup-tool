# Fail2ban pre-ban triage via IP Radar

Before fail2ban bans an IP, ask your local IP Radar instance for a fused
multi-source verdict, and route the ban accordingly:

| Verdict | Action |
|---|---|
| malicious, confidence ≥ threshold (default 70) | ban + record to a persistent confirmed-malicious list (feed it to ipset/firewall for long bans) |
| CDN / known service edge | **skip the ban** (exit 100), log for manual review — no more banning Cloudflare |
| benign / no evidence | normal short ban (fail2ban default behavior) |

The lookup is a localhost HTTP call — no rate limits, no per-query traffic
leaving your machine, sub-millisecond on a warm store.

## Install

```bash
# IP Radar running locally first (http://127.0.0.1:8000)
git clone https://github.com/steponeerror/ip-radar && cd ip-radar
docker compose up -d --build

# then the action:
sudo cp scripts/fail2ban/ipradar.conf /etc/fail2ban/action.d/
```

In `/etc/fail2ban/jail.local`:

```ini
[sshd]
action = %(known/action)s
         ipradar
```

Tunables:

```ini
# stricter gate, week-long list for confirmed hosts
action = ipradar[threshold=80]
```

| Option | Default | Meaning |
|---|---|---|
| `url` | `http://127.0.0.1:8000` | IP Radar base URL |
| `threshold` | `70` | malicious confidence gate (0-100) |
| `timeout` | `3` | lookup timeout; on failure banning proceeds normally |
| `longlist` | `/var/lib/fail2ban/ipradar/confirmed.txt` | confirmed-malicious IP log |

## Design notes

- **Never blocks banning.** If IP Radar is down or times out, the action
  no-ops and fail2ban behaves exactly as without it. A dead intel sidecar
  must not disable your firewall.
- **Enforcement stays in fail2ban.** The action only *classifies* and
  *records*; it doesn't install firewall rules. Feed `confirmed.txt` to
  ipset/nftables yourself if you want week-long drops.
- `norestored = 1` — tickets restored from a restart are not re-triaged.
