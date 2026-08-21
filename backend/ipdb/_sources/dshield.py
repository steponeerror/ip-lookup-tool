"""DShield recommended block list — Source subclass (top attacking /24s).

https://feeds.dshield.org/block.txt — tab-separated:
    start end prefix attacks as-name country abuse-mail
No last_seen upstream (attacks is a rolling count). Small feed (~20 rows,
top-20 attacking class C subnets). Direct source replaces what firehol's
aggregate drops (spec D8/Q14-A).
"""
import logging
from urllib.parse import urlparse

from .._source_base import Source
from .._evidence import Evidence
from ._download import CancelToken

logger = logging.getLogger(__name__)


class DshieldSource(Source):
    name = "dshield"
    url = "https://feeds.dshield.org/block.txt"
    filename = "dshield.txt"
    fields = ("is_malicious",)
    classification_type = "scanner"
    verdict = "malicious"
    stale_days = 1
    reliability = 0.70

    @property
    def download_host(self) -> str | None:
        return urlparse(self.url).hostname

    def download(self, token: CancelToken | None = None) -> None:
        self._data_dir.mkdir(parents=True, exist_ok=True)
        data = self._http_get(self.url)
        if not data.strip():
            raise RuntimeError(f"Empty response from {self.url}")
        self._path.write_bytes(data)

    def harvest(self):
        with open(self._path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                cols = line.split("\t")
                if len(cols) < 6:
                    continue
                start, _end, prefix, attacks, as_name, country = cols[:6]
                try:
                    attacks_n = int(attacks)
                    prefix_n = int(prefix)
                except ValueError:
                    continue
                # '-' is dshield's unknown-placeholder for as-name/country;
                # emit None rather than a literal '-' vote (final-review fix).
                as_name = as_name if as_name != "-" else None
                country = country if country != "-" else None
                yield f"{start}/{prefix_n}", Evidence(
                    classification_type=self.classification_type,
                    verdict=self.verdict,
                    reporter_count=attacks_n,
                    as_name=as_name,
                    country_code=country,
                )
