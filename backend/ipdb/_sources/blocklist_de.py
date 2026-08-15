"""Blocklist.de 多子列表源 — firehol 式目录 + 攻击类型归属。

订阅 10 个攻击类型子列表 + all.txt 兜底（第 11 个列表，blacklist 兜底分类、
优先级最低）。实测 all.txt ≠ 子列表并集（约 ±0.1% 漂移：26 IP 只在 all.txt、
140 IP 只在子列表），双订阅保证零丢失。同 IP 命中多列表时按
brute-force > botnet > spam > scanner > blacklist 裁决 classification_type，
全部认领子列表名保留在 native_categories。
"""
import logging
import shutil
import time
from pathlib import Path

from ._base import IpListSource
from ._download import download_file, CancelToken, CancelledError
from .._types import SourceHealth
from .._classification import BLOCKLIST_DE_MAP

_BASE_URL = "https://lists.blocklist.de/lists"

logger = logging.getLogger(__name__)

# 迭代序即 native_categories 的记录序；all.txt 放最后（优先级最低的兜底）
_LISTS = ["mail", "ssh", "bruteforcelogin", "ftp", "imap", "sip",
          "bots", "ircbot", "apache", "strongips", "all"]

_PRIORITY = {"brute-force": 0, "botnet": 1, "spam": 2, "scanner": 3, "blacklist": 4}


class BlocklistDeSource(IpListSource):
    name = "blocklist_de"
    url = ""  # unused — custom download() handles multiple URLs
    filename = "blocklist_de"  # directory name
    fields = ("is_malicious",)
    classification_type = "blacklist"   # 兜底（无映射子列表 / all.txt）
    verdict = "malicious"
    stale_days = 1
    reliability = 0.65
    authoritative_for = []

    def __init__(self, data_dir: Path, selected_lists: list[str] | None = None):
        self._lists = selected_lists or list(_LISTS)
        super().__init__(data_dir=data_dir)
        self._path = data_dir / "blocklist_de"  # directory, not file
        self._files = [self._path / f"{name}.txt" for name in self._lists]

    @property
    def download_host(self) -> str | None:
        return "lists.blocklist.de"

    def _cleanup_legacy(self) -> None:
        """删除旧单文件时代的 blocklist_de.txt 及其 LMDB sidecar。

        sidecar 形态两种：LMDB epoch 目录（blocklist_de.txt.lmdb.N/）用
        rmtree；ptr/count/cov 等文件形态 sidecar 用 unlink。"""
        legacy = self._path.parent / "blocklist_de.txt"
        legacy.unlink(missing_ok=True)
        for side in self._path.parent.glob("blocklist_de.txt.lmdb.*"):
            if side.is_dir():
                shutil.rmtree(side, ignore_errors=True)
            else:
                side.unlink(missing_ok=True)

    def download(self, token: CancelToken | None = None) -> None:
        self._path.mkdir(parents=True, exist_ok=True)
        self._cleanup_legacy()
        for list_name in self._lists:
            if token is not None and token.is_cancelled():
                raise CancelledError(f"{self.name} download cancelled")
            url = f"{_BASE_URL}/{list_name}.txt"
            dest = self._path / f"{list_name}.txt"
            logger.info(f"Downloading blocklist_de/{list_name}...")
            try:
                download_file(url, dest, token=token,
                              headers={"User-Agent": "ip-lookup-tool/1.0"})
                if not dest.read_bytes().strip():
                    dest.unlink(missing_ok=True)   # don't leave stale to be mixed in
            except Exception as e:
                logger.error(f"Failed to download blocklist_de/{list_name}: {e}")
                dest.unlink(missing_ok=True)       # don't leave stale to be mixed in

    def load(self) -> int:
        """纯 mmap:打开已有 LMDB env,读 sidecar,不重建。"""
        from ._lmdb import read_ptr, open_env_read, cleanup_stale, count_path, cov_path
        cleanup_stale(self._lmdb_base)
        epoch = read_ptr(self._lmdb_base)
        if epoch is None:
            self._reader = None
            return 0
        self._reader = open_env_read(
            self._lmdb_base.parent / f"{self._lmdb_base.name}.{epoch}")
        cp, vp = count_path(self._lmdb_base), cov_path(self._lmdb_base)
        self._count = int(cp.read_text().strip()) if cp.exists() else 0
        self._covered_ips = int(vp.read_text().strip()) if vp.exists() else 0
        self._loaded_at = time.time()
        return self._count

    def rebuild(self) -> int:
        """重建 LMDB(唯一重建入口)。多列表累积:同 CIDR 按优先级裁决
        classification_type,全部认领列表名进 native_categories。"""
        import ipaddress as _ipa
        from ._lmdb import covered_ip_count, rebuild_lmdb
        from .._evidence import Evidence
        if not self._path.exists():
            return 0
        old_reader = self._reader

        # cidr -> {"classification_type": ..., "native_categories": [...]}
        acc: dict[str, dict] = {}
        for list_name in self._lists:
            p = self._path / f"{list_name}.txt"
            if not p.exists():
                continue
            cls = BLOCKLIST_DE_MAP.get(list_name, "blacklist")
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
                        cur = acc[net]
                        if _PRIORITY[cls] < _PRIORITY[cur["classification_type"]]:
                            cur["classification_type"] = cls
                        if list_name not in cur["native_categories"]:
                            cur["native_categories"].append(list_name)
                    else:
                        acc[net] = {"classification_type": cls,
                                    "native_categories": [list_name]}

        records = [
            (cidr, [Evidence(
                classification_type=info["classification_type"],
                verdict=self.verdict,
                reliability=self.reliability,
                native_categories=info["native_categories"],
            ).to_dict()])
            for cidr, info in acc.items()
        ]

        try:
            cov = covered_ip_count(iter(acc.keys()))
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
        import ipaddress as _ipa
        import lmdb as _lmdb
        from ._lmdb import lookup, read_ptr, open_env_read
        ip_int = int(_ipa.IPv4Address(ip))
        try:
            node = lookup(self._reader, ip_int)
        except (_lmdb.Error, OSError):
            # 撞上刚 close 的旧 env:读 ptr 重开重试一次(与 MMDB 时代同模式)
            epoch = read_ptr(self._lmdb_base)
            self._reader = (open_env_read(
                self._lmdb_base.parent / f"{self._lmdb_base.name}.{epoch}")
                if epoch is not None else None)
            if self._reader is None:
                return {}
            node = lookup(self._reader, ip_int)
        if node is None:
            return {}
        return node

    def health(self) -> SourceHealth:
        import time
        mtimes = []
        if self._path.exists():
            for list_name in self._lists:
                p = self._path / f"{list_name}.txt"
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
