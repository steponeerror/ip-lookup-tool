"""GeoLite2-City via P3TERX/GeoLite.mmdb — first .mmdb-input source.

Download GeoLite2-City.mmdb (~66MB), harvest via maxminddb mmap iteration,
rebuild into LMDB streaming (single_evidence). The .mmdb is feedstock only —
queries go through the same LMDB mmap as every other source.

Routing (spec 2026-08-16): city.names.en → canonical `city` (English keeps
FactualVoting vote-coherent with proxyscrape); zh-CN → extra.city_zh;
country.iso_code → canonical `country_code` (6th vote). Networks carrying
neither signal are skipped; IPv6 networks skipped (pipeline is IPv4-only);
registered_country is deliberately never read (registration ≠ location).

Data: MaxMind GeoLite2 (GeoLite2 EULA / CC BY 4.0), rehosted by
github.com/P3TERX/GeoLite.mmdb, refreshed every 2-4 days.
"""
from .._evidence import Evidence
from .._source_base import Source


class GeoLiteCitySource(Source):
    name = "geolite_city"
    fields = ("city", "country_code")
    url = ("https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/"
           "GeoLite2-City.mmdb")
    filename = "geolite_city.mmdb"
    stale_days = 7
    reliability = 0.85
    authoritative_for = []
    single_evidence = True

    def download(self, token=None) -> None:
        from ._download import download_file
        download_file(self.url, self._path, token=token,
                      headers={"User-Agent": "ip-lookup-tool/1.0"})
        # 单发原子（无内置重试）：失败→任务失败→下轮调度重试（同 ip2proxy/firehol）。
        # 试开校验：corrupt/空文件 unlink，既有 LMDB 继续服务，is_stale 触发下轮重下。
        import maxminddb
        try:
            reader = maxminddb.open_database(self._path)
        except Exception:
            self._path.unlink(missing_ok=True)
            raise
        reader.close()

    def harvest(self):
        import maxminddb
        with maxminddb.open_database(self._path) as reader:
            for network, record in reader:
                if network.version != 4:
                    continue
                names = (record.get("city") or {}).get("names") or {}
                city_en = names.get("en")
                city_zh = names.get("zh-CN")
                cc = (record.get("country") or {}).get("iso_code")
                if not city_en and not cc:
                    continue
                extra = {"city_zh": city_zh} if city_zh else {}
                yield str(network), Evidence(
                    city=city_en or None,
                    country_code=cc or None,
                    extra=extra,
                )
