"""Spamhaus DROP list — IpListSource subclass."""
from ._base import IpListSource


class SpamhausSource(IpListSource):
    name = "spamhaus"
    url = "https://www.spamhaus.org/drop/drop.txt"
    filename = "spamhaus_drop.txt"
    fields = ("is_malicious",)
    classification_type = "blacklist"
    verdict = "malicious"
    stale_days = 1
    reliability = 0.90
    authoritative_for = ["is_malicious"]

    def rebuild(self, progress=None) -> int:
        """重建 LMDB。覆写基类：保留 `;` 后的 SBL 案件编号 → extra.sbl_id
        （基类直接截断丢弃）。"""
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
                sbl_id = ""
                if ";" in line:
                    line, _, tail = line.partition(";")
                    line = line.strip()
                    tail = tail.strip()
                    if tail.startswith("SBL"):
                        sbl_id = tail.split()[0]
                if not line:
                    continue
                try:
                    net = _ipa.IPv4Network(line, strict=False)
                except (_ipa.AddressValueError, ValueError):
                    continue
                ev = Evidence(
                    classification_type=self.classification_type,
                    verdict=self.verdict,
                    reliability=self.reliability,
                    extra={"sbl_id": sbl_id} if sbl_id else None,
                ).to_dict()
                records.append((str(net), [ev]))
                covered.append(str(net))
        try:
            cov = covered_ip_count(covered)
            n = rebuild_lmdb(records, self._lmdb_base,
                             reader_setter=lambda e: setattr(self, "_reader", e),
                             flag_setter=lambda v: setattr(self, "_disjoint", v),
                             covered=cov, progress=progress)
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
