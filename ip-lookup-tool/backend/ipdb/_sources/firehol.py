"""Firehol blocklist source — IpListSource subclass with multi-list download."""
import time
import urllib.request
from pathlib import Path

from ._base import IpListSource
from .._types import SourceHealth

_BASE_URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master"


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

    def download(self) -> None:
        self._path.mkdir(parents=True, exist_ok=True)
        for list_name in self._lists:
            url = f"{_BASE_URL}/{list_name}.netset"
            dest = self._path / f"{list_name}.netset"
            import logging
            logger = logging.getLogger(__name__)
            logger.info(f"Downloading {list_name}...")
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": "ip-lookup-tool/1.0"})
                with urllib.request.urlopen(req, timeout=120) as resp:
                    data = resp.read()
                if not data.strip():
                    continue
                with open(dest, "wb") as f:
                    f.write(data)
            except Exception as e:
                logger.error(f"Failed to download {list_name}: {e}")

    def load(self) -> int:
        import ipaddress as _ipa
        import pytricia

        tree = pytricia.PyTricia(32)
        count = 0
        if not self._path.exists():
            self._tree = tree
            return 0
        for list_name in self._lists:
            p = self._path / f"{list_name}.netset"
            if not p.exists():
                continue
            with open(p) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        net = _ipa.IPv4Network(line, strict=False)
                    except (_ipa.AddressValueError, ValueError):
                        continue
                    tree.insert(str(net), [{"classification_type": self.classification_type,
                                            "verdict": self.verdict}])
                    count += 1
        self._tree = tree
        self._count = count
        self._loaded_at = time.time()
        return count

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
            loaded=self._tree is not None,
            record_count=self._count,
            last_updated=last_updated,
            is_stale=is_stale,
        )
