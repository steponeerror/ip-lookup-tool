"""IPsum source — CsvSource subclass."""
from ._base import CsvSource


class IPsumSource(CsvSource):
    name = "ipsum"
    url = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
    filename = "ipsum.txt"
    fields = ("is_malicious",)
    classification_type = "blacklist"
    verdict = "malicious"
    stale_days = 1
    reliability = 0.55
    authoritative_for = []
    _min_count: int = 3

    def __init__(self, data_dir, min_count: int = 3):
        self._min_count = min_count
        super().__init__(data_dir=data_dir)

    def parse_row(self, row: list[str]) -> dict | None:
        if not row:
            return None
        # IPsum format: <ip>,<appearances>
        if len(row) > 1:
            try:
                appearances = int(row[1].strip())
            except ValueError:
                return None
            if appearances < self._min_count:
                return None
        return {"_ip": row[0].strip(), "is_malicious": True}
