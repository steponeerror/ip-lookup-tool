"""Tor exit addresses source — IpListSource with custom parse_raw."""
import ipaddress
import re
from ._base import IpListSource


_EXIT_ADDR_RE = re.compile(r"^ExitAddress\s+(\S+)")


class TorExitSource(IpListSource):
    name = "tor_exits"
    url = "https://check.torproject.org/exit-addresses"
    filename = "tor-exit-addresses.txt"
    fields = ("is_tor",)
    stale_days = 1
    reliability = 0.95
    authoritative_for = ["is_tor"]

    def parse_raw(self, raw: bytes) -> list[str]:
        ips = []
        for line in raw.decode(errors="ignore").splitlines():
            m = _EXIT_ADDR_RE.match(line)
            if m:
                try:
                    ipaddress.IPv4Address(m.group(1))
                    ips.append(m.group(1))
                except (ipaddress.AddressValueError, ValueError):
                    continue
        return ips

    def get_insert_data(self) -> dict:
        # Tor exits are /32 hosts
        return {"is_tor": True}
