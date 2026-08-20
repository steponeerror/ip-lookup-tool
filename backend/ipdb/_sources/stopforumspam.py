"""StopForumSpam listed IP feed — per-IP spam evidence (Source subclass).

`listed_ip_365_all.zip` lists every IP active as a forum spammer within the
last 365 days, one record per line as `"ip","total","last_seen"` (total =
report count). Replaces the old toxic_ip_cidr.txt (60 CIDRs, zero extra
fields) — spec D7 / Q13-A. Download limited to 3/day/IP; stale_days=1 keeps
the daily scheduler under the limit. 429 keeps the previous LMDB data.
"""
import csv
import io
import logging
import zipfile
from urllib.parse import urlparse

from .._source_base import Source
from .._evidence import Evidence
from ._download import download_file, CancelToken

logger = logging.getLogger(__name__)


class StopForumSpamSource(Source):
    name = "stopforumspam"
    url = "https://www.stopforumspam.com/downloads/listed_ip_365_all.zip"
    filename = "stopforumspam.csv"
    fields = ("spam",)
    classification_type = "spam"
    verdict = "informational"
    stale_days = 1
    reliability = 0.70

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
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    name = next((n for n in z.namelist() if n.endswith(".txt") or n.endswith(".csv")), None)
                    if name is None:
                        raise RuntimeError("no data file inside sfs zip")
                    data = z.read(name)
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
                    last_seen=last_seen,
                )
