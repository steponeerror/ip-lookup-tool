"""Tor exit addresses source — IpListSource with custom parse_raw.

归一化文件行形态：`ip[,ts]`（ts 为 ExitAddress 行内时间戳，空格已转 T）；
无 ts 行兼容（仅 ip）。
"""
import ipaddress
import re
from ._base import IpListSource


_EXIT_ADDR_RE = re.compile(r"^ExitAddress\s+(\S+)(?:\s+(\S+ \S+))?")


class TorExitSource(IpListSource):
    name = "tor_exits"
    url = "https://check.torproject.org/exit-addresses"
    filename = "tor-exit-addresses.txt"
    fields = ("is_tor",)
    classification_type = "tor"
    verdict = "suspicious"
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
                except (ipaddress.AddressValueError, ValueError):
                    continue
                ts = m.group(2).replace(" ", "T") if m.group(2) else ""
                ips.append(f"{m.group(1)},{ts}" if ts else m.group(1))
        return ips

    def rebuild(self) -> int:
        """重建 LMDB。覆写基类：文件行为 `ip[,ts]`（parse_raw 归一化产物），
        ts → last_seen（per-row，基类单一 insert_data 不支持）。"""
        import ipaddress as _ipa
        import time
        from ._lmdb import covered_ip_count, rebuild_lmdb
        from .._evidence import Evidence
        if not self._path.exists():
            return 0
        old_reader = self._reader
        records = []
        covered = []
        with open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                ip, _, ts = line.partition(",")
                try:
                    net = _ipa.IPv4Network(f"{ip.strip()}/32", strict=False)
                except (_ipa.AddressValueError, ValueError):
                    continue
                ev = Evidence(
                    classification_type=self.classification_type,
                    verdict=self.verdict,
                    reliability=self.reliability,
                    is_tor=True,
                    native_types={"is_tor": "TOR"},
                    last_seen=ts.strip() or None,
                ).to_dict()
                records.append((str(net), [ev]))
                covered.append(str(net))
        try:
            cov = covered_ip_count(covered)
            n = rebuild_lmdb(records, self._lmdb_base,
                             reader_setter=lambda e: setattr(self, "_reader", e),
                             flag_setter=lambda v: setattr(self, "_disjoint", v),
                             covered=cov)
            self._count = n
            self._covered_ips = cov
            self._loaded_at = time.time()
            return n
        finally:
            if old_reader is not None:
                try:
                    old_reader.close()
                except Exception:
                    pass

    def get_insert_data(self) -> dict:
        from .._evidence import Evidence
        return Evidence(
            classification_type=self.classification_type,
            verdict=self.verdict,
            reliability=self.reliability,
            is_tor=True,
            native_types={"is_tor": "TOR"},
        ).to_dict()
