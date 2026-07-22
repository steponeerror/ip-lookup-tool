"""X4BNet VPN list source — IpListSource subclass."""
from ._base import IpListSource


class X4BNetVPNSource(IpListSource):
    name = "x4bnet_vpn"
    url = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt"
    filename = "x4bnet_vpn.txt"
    fields = ("is_vpn",)
    classification_type = "proxy"
    verdict = "suspicious"
    stale_days = 7
    reliability = 0.70
    authoritative_for = ["is_vpn"]

    def get_insert_data(self) -> dict:
        from .._evidence import Evidence
        return Evidence(
            classification_type=self.classification_type,
            verdict=self.verdict,
            reliability=self.reliability,
            is_vpn=True,
            native_types={"is_vpn": "VPN"},
            extra={"native_type": self.classification_type},
        ).to_dict()
