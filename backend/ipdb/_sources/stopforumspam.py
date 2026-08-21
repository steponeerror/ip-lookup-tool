"""StopForumSpam listed IP feed — per-IP spam evidence (Source subclass).

`listed_ip_365_all.zip` lists every IP active as a forum spammer within the
last 365 days, one record per line as `"ip","total","last_seen"` (total =
report count). Replaces the old toxic_ip_cidr.txt (60 CIDRs, zero extra
fields) — spec D7 / Q13-A. Download limited to 3/day/IP; stale_days=1 keeps
the daily scheduler under the limit. NOTE: the .txt→.csv rename orphans the
old LMDB on upgrade — load() sweeps it; until the first download lands the
source contributes nothing (self-heals, see _cleanup_legacy_txt).
"""
import csv
import logging
import zipfile
from urllib.parse import urlparse

from .._source_base import Source
from .._evidence import Evidence
from ._download import download_file, CancelToken

logger = logging.getLogger(__name__)


class StopForumSpamSource(Source):
    # Hard cap on the decompressed inner file (streamed, never fully trusted):
    # real feed ≈15 MB; cap leaves headroom while stopping zip bombs.
    MAX_INNER_BYTES = 256 * 1024 * 1024
    name = "stopforumspam"
    url = "https://www.stopforumspam.com/downloads/listed_ip_365_all.zip"
    filename = "stopforumspam.csv"
    fields = ("spam",)
    classification_type = "spam"
    verdict = "informational"
    stale_days = 1
    reliability = 0.70

    def load(self) -> int:
        self._cleanup_legacy_txt()
        return super().load()

    def _cleanup_legacy_txt(self):
        """One-shot: D7 renamed filename .txt→.csv, so the old raw file and
        its LMDB base (raw + epoch dirs + sidecars) are orphaned forever —
        cleanup_stale only sweeps the current base name."""
        import shutil
        (self._data_dir / "stopforumspam.txt").unlink(missing_ok=True)
        for child in self._data_dir.glob("stopforumspam.txt.lmdb*"):
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink(missing_ok=True)

    @property
    def download_host(self) -> str | None:
        return urlparse(self.url).hostname

    def download(self, token: CancelToken | None = None) -> None:
        self._data_dir.mkdir(parents=True, exist_ok=True)
        zip_path = self._data_dir / "stopforumspam.zip"
        try:
            download_file(self.url, zip_path, token=token,
                          headers={"User-Agent": "ip-lookup-tool/1.0"})
            data = zip_path.read_bytes()
            if not data.strip():
                raise RuntimeError(f"Empty response from {self.url}")
            if data[:4] == b"PK\x03\x04":
                with zipfile.ZipFile(zip_path) as z:
                    name = next((n for n in z.namelist() if n.endswith(".txt") or n.endswith(".csv")), None)
                    if name is None:
                        raise RuntimeError("no data file inside sfs zip")
                    buf = bytearray()
                    with z.open(name) as inner:   # stream: bomb hits the cap, not RAM
                        while chunk := inner.read(1 << 20):
                            buf += chunk
                            if len(buf) > self.MAX_INNER_BYTES:
                                raise RuntimeError(
                                    f"inner file too large (> {self.MAX_INNER_BYTES} bytes): {name}")
                    data = bytes(buf)
            self._path.write_bytes(data)
        finally:
            zip_path.unlink(missing_ok=True)

    def harvest(self):
        with open(self._path, "r", encoding="utf-8", errors="ignore") as f:
            for row in csv.reader(f):
                if len(row) < 3 or not row[0].strip():
                    continue
                ip = row[0].strip().strip('"')
                try:
                    total = int(row[1].strip().strip('"'))
                except ValueError:
                    continue
                last_seen = row[2].strip().strip('"') or None
                yield ip, Evidence(
                    classification_type=self.classification_type,
                    verdict=self.verdict,
                    reporter_count=total,
                    first_seen=last_seen,   # single-timestamp double-fill → decay
                    last_seen=last_seen,
                )
