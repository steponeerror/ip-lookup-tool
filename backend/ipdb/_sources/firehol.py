"""Firehol blocklist source — IpListSource subclass with multi-list download."""
import logging
import time
from pathlib import Path
from urllib.parse import urlparse

from ._base import IpListSource
from ._download import download_file, CancelToken, CancelledError
from .._types import SourceHealth

_BASE_URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master"

logger = logging.getLogger(__name__)


class FireholBlocklistSource(IpListSource):
    name = "firehol"
    url = ""  # unused — custom download() handles multiple URLs
    filename = "firehol"  # directory name
    fields = ("is_malicious",)
    classification_type = "blacklist"
    verdict = "malicious"
    stale_days = 1
    reliability = 0.50
    authoritative_for = []

    def __init__(self, data_dir: Path, selected_lists: list[str] | None = None):
        self._lists = selected_lists or ["firehol_level1", "firehol_level2"]
        super().__init__(data_dir=data_dir)
        self._path = data_dir / "firehol"  # directory, not file
        self._files = [self._path / f"{name}.netset" for name in self._lists]

    @property
    def download_host(self) -> str | None:
        # url class attr is "" but downloads actually come from _BASE_URL.
        return urlparse(_BASE_URL).hostname

    def download(self, token: CancelToken | None = None) -> None:
        self._path.mkdir(parents=True, exist_ok=True)
        for list_name in self._lists:
            if token is not None and token.is_cancelled():
                raise CancelledError(f"{self.name} download cancelled")
            url = f"{_BASE_URL}/{list_name}.netset"
            dest = self._path / f"{list_name}.netset"
            logger.info(f"Downloading {list_name}...")
            try:
                download_file(url, dest, token=token,
                              headers={"User-Agent": "ip-lookup-tool/1.0"})
                if not dest.read_bytes().strip():
                    dest.unlink(missing_ok=True)   # don't leave stale to be mixed in
            except Exception as e:
                logger.error(f"Failed to download {list_name}: {e}")
                dest.unlink(missing_ok=True)       # don't leave stale to be mixed in

    def load(self) -> int:
        """纯 mmap:打开已有 LMDB env,读 sidecar,不重建。"""
        from ._lmdb import (read_ptr, open_env_read, cleanup_stale, count_path,
                            cov_path, read_disjoint_flag)
        cleanup_stale(self._lmdb_base)
        epoch = read_ptr(self._lmdb_base)
        if epoch is None:
            self._reader = None
            self._disjoint = False
            return 0
        self._disjoint = read_disjoint_flag(self._lmdb_base, epoch)
        self._reader = open_env_read(
            self._lmdb_base.parent / f"{self._lmdb_base.name}.{epoch}")
        cp, vp = count_path(self._lmdb_base), cov_path(self._lmdb_base)
        self._count = int(cp.read_text().strip()) if cp.exists() else 0
        self._covered_ips = int(vp.read_text().strip()) if vp.exists() else 0
        self._loaded_at = time.time()
        return self._count

    def rebuild(self) -> int:
        """重建 LMDB(唯一重建入口)。新 epoch + ptr swap reader。

        Multi-file mtime gating (like cn_isp): if the ptr is already newer
        than the newest netset, the rebuild is a no-op but still opens the
        reader and refreshes sidecars — so callers that enqueue firehol after
        a partial state (env exists, sidecars missing) self-heal.

        Per-list attribution (2026-08-15): 每列表独立 Evidence 带 tags=
        [列表名]；同 CIDR 双列表命中合并 tags（dict 累积，消除旧实现
        L2 put 覆盖 L1 的顺序问题）。同起止不同长度 CIDR 仍依赖审计脚本
        零冲突（scripts/audit_lmdb_invariants.py）。
        """
        import ipaddress as _ipa
        from ._lmdb import covered_ip_count, rebuild_lmdb
        from .._evidence import Evidence
        if not self._path.exists():
            return 0
        old_reader = self._reader

        acc: dict[str, dict] = {}
        for list_name in self._lists:
            p = self._path / f"{list_name}.netset"
            if not p.exists():
                continue
            with open(p, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        net = str(_ipa.IPv4Network(line, strict=False))
                    except (_ipa.AddressValueError, ValueError):
                        continue
                    if net in acc:
                        for t in (list_name,):
                            if t not in acc[net]["tags"]:
                                acc[net]["tags"].append(t)
                    else:
                        acc[net] = Evidence(
                            classification_type=self.classification_type,
                            verdict=self.verdict,
                            reliability=self.reliability,
                            tags=[list_name],
                        ).to_dict()
        records = [(cidr, [ev]) for cidr, ev in acc.items()]

        def _enum():
            return iter(acc.keys())

        try:
            cov = covered_ip_count(_enum())
            n = rebuild_lmdb(records, self._lmdb_base,
                             reader_setter=lambda e: setattr(self, "_reader", e),
                             covered=cov)
            self._covered_ips = cov
            self._count = n
            self._loaded_at = time.time()
            return n
        finally:
            if old_reader is not None:
                try:
                    old_reader.close()
                except Exception:
                    pass          # lmdb env 二次 close/已失效:容忍

    def query(self, ip: str):
        if self._reader is None:
            return {}
        import lmdb as _lmdb
        from ._lmdb import (
            ip_to_int, lookup, read_ptr, open_env_read, read_disjoint_flag)
        ip_int = ip_to_int(ip)
        try:
            node = lookup(self._reader, ip_int, disjoint=self._disjoint)
        except (_lmdb.Error, OSError):
            # 撞上刚 close 的旧 env:读 ptr 重开重试一次(与 MMDB 时代同模式)
            epoch = read_ptr(self._lmdb_base)
            self._reader = (open_env_read(
                self._lmdb_base.parent / f"{self._lmdb_base.name}.{epoch}")
                if epoch is not None else None)
            if self._reader is None:
                return {}
            self._disjoint = read_disjoint_flag(self._lmdb_base, epoch)
            node = lookup(self._reader, ip_int, disjoint=self._disjoint)
        if node is None:
            return {}
        return node

    def health(self) -> SourceHealth:
        import time
        mtimes = []
        if self._path.exists():
            for list_name in self._lists:
                p = self._path / f"{list_name}.netset"
                if p.exists():
                    mtimes.append(p.stat().st_mtime)
        file_mtime = max(mtimes) if mtimes else None
        last_updated = (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(file_mtime))
                        if file_mtime else None)
        is_stale = file_mtime is None or (
            time.time() - file_mtime > self.stale_days * 86400)
        return SourceHealth(
            name=self.name,
            loaded=self._reader is not None,
            record_count=self._count,
            last_updated=last_updated,
            is_stale=is_stale,
            covered_ips=self._covered_ips,
        )
