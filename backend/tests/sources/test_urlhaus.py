"""URLhaus (Source subclass) — URL→IP extraction + per-row classification + Principle.

Covers: domain-host rows dropped (noise), IP-host extraction, botnet mapping
(mirai/Mozi/hajime), malware-distribution base for the rest, native_type +
reporter + url_status preserved (Convention 1 + preserve-signal), comment
block skipped.
"""
from pathlib import Path

from ipdb._sources.urlhaus import URLhausSource

SAMPLE = (
    "##### urlhaus header #####\n"
    "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
    '"1","2026-07-30 11:54:23","http://61.54.253.89:37352/bin.sh","online","2026-07-30 11:54:23","malware_download","32-bit,elf,mips,Mozi","x","geenensp"\n'
    '"2","2026-07-30 11:54:23","http://1.2.3.4/x","online","2026-07-30 11:54:23","malware_download","CoinMiner","x","rep"\n'
    '"3","2026-07-30 11:54:23","http://bad.example.com/x","online","2026-07-30 11:54:23","malware_download","mirai","x","rep"\n'
    '"4","2026-07-30 11:54:23","http://5.6.7.8/y","online","2026-07-30 11:54:23","malware_download","None","x","rep"\n'
    '"5","2026-07-30 11:54:23","http://9.10.11.12/z","online","2026-07-30 11:54:23","malware_download","elf,hajime","x","rep"\n'
)


def test_urlhaus_drops_domain_hosts_and_classifies(tmp_path: Path):
    (tmp_path / "urlhaus.csv").write_text(SAMPLE)
    s = URLhausSource(data_dir=tmp_path)
    assert s.load() == 4                    # rows 1,2,4,5 (IP-host); row 3 domain dropped

    bot = s.query("61.54.253.89")[0]        # Mozi tag
    assert bot["classification_type"] == "botnet"
    assert bot["extra"]["tags_raw"] == "32-bit,elf,mips,Mozi"   # raw preserved
    assert bot["extra"]["reporter"] == "geenensp"
    assert bot["malware_name"] == "Mozi"                          # enriched: matched family
    assert bot.get("last_seen") == "2026-07-30T11:54:23"          # enriched: last_online recency

    hajime = s.query("9.10.11.12")[0]       # hajime tag
    assert hajime["classification_type"] == "botnet"

    miner = s.query("1.2.3.4")[0]           # CoinMiner → base
    assert miner["classification_type"] == "malware-distribution"
    assert miner["extra"]["tags_raw"] == "CoinMiner"

    none_tags = s.query("5.6.7.8")[0]       # "None" tags → base
    assert none_tags["classification_type"] == "malware-distribution"
    assert none_tags["extra"]["url_status"] == "online"            # recency signal preserved


def test_urlhaus_domain_rows_not_in_db(tmp_path: Path):
    """A domain-host URL must not contribute its (non-IP) host — IP tool."""
    (tmp_path / "urlhaus.csv").write_text(
        '# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n'
        '"1","2026-07-30","http://bad.example.com/x","online","2026-07-30","malware_download","mirai","x","r"\n'
        '"2","2026-07-30","http://203.0.113.7/x","online","2026-07-30","malware_download","mirai","x","r"\n'
    )
    s = URLhausSource(data_dir=tmp_path)
    assert s.load() == 1                    # only the IP-host row survives
    assert s.query("203.0.113.7")


def test_urlhaus_native_categories_filters_noise_and_excludes_matched_family(tmp_path: Path):
    """Native categories: split tags, filter arch noise, exclude matched family."""
    (tmp_path / "urlhaus.csv").write_text(
        '# "dateadded","url","url_status","last_online","threat","tags","urlhaus_link","reporter"\n'
        '"1","2026-08-01","http://1.2.3.4/x","online","2026-08-05","malware_download","32-bit,elf,mips,Mozi","u1","r1"\n'
        '"2","2026-08-01","http://5.6.7.8/y","online","2026-08-05","malware_download","mirai,TrickBot","u2","r2"\n'
        '"3","2026-08-01","http://9.10.11.12/z","online","2026-08-05","malware_download","","u3","r3"\n'
    )
    s = URLhausSource(data_dir=tmp_path)
    s.load()

    # Row 1: Mozi matched, noise filtered, native_categories empty
    one = {e["classification_type"]: e for e in s.query("1.2.3.4")}
    assert one["botnet"]["malware_name"] == "Mozi"
    assert one["botnet"].get("native_categories", []) == []          # Mozi excluded (in malware_name), noise filtered
    assert "tags_raw" in (one["botnet"].get("extra") or {})  # raw preserved
    assert "native_type" not in (one["botnet"].get("extra") or {})

    # Row 2: mirai matched, TrickBot preserved in native_categories
    two = {e["classification_type"]: e for e in s.query("5.6.7.8")}
    assert two["botnet"]["malware_name"] == "mirai"
    assert two["botnet"]["native_categories"] == ["TrickBot"]  # other family preserved

    # Row 3: empty tags → empty native_categories, no malware_name
    three = {e["classification_type"]: e for e in s.query("9.10.11.12")}
    assert three["malware-distribution"].get("native_categories", []) == []   # empty tags → empty
    assert three["malware-distribution"].get("malware_name") in (None, "")
