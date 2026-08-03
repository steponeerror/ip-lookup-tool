"""TweetFeed (Source subclass) — per-row hashtag classification + Principle.

Covers: non-IP rows filtered (noise), per-row classification via TWEETFEED_MAP,
multi-hashtag handling, empty/unmappable → other, native_type + reporter
preserved (Convention 1 + preserve-signal).
"""
from pathlib import Path

from ipdb._sources.tweetfeed import TweetFeedSource

SAMPLE = (
    "2025-07-31 00:00:11,urldna_bot,domain,bad.example.com,#phishing,https://x.com/1\n"
    "2025-07-31 00:10:31,catnap707,ip,172.67.166.60,#phishing,https://x.com/2\n"
    "2025-07-31 01:00:00,res1,ip,1.2.3.4,#C2 #CobaltStrike,https://x.com/3\n"
    "2025-07-31 02:00:00,res2,ip,5.6.7.8,,https://x.com/4\n"                  # empty tag
    "2025-07-31 03:00:00,res3,ip,9.10.11.12,#ransomware,https://x.com/5\n"    # unmappable
)


def test_tweetfeed_filters_nonip_and_classifies_per_row(tmp_path: Path):
    (tmp_path / "tweetfeed.csv").write_text(SAMPLE)
    s = TweetFeedSource(data_dir=tmp_path)
    assert s.load() == 4                        # 4 IP rows; the domain row filtered as noise

    phish = s.query("172.67.166.60")[0]
    assert phish["classification_type"] == "phishing"
    assert phish["extra"]["native_type"] == "#phishing"     # Convention 1
    assert phish["extra"]["reporter"] == "catnap707"        # preserve-signal
    assert phish["extra"]["tweet_url"] == "https://x.com/2" # enriched: provenance
    assert phish["verdict"] == "malicious"

    c2 = s.query("1.2.3.4")[0]
    assert c2["classification_type"] == "c2-server"         # multi-hashtag, first mapped wins
    assert c2["extra"]["native_type"] == "#C2 #CobaltStrike"  # full raw tag preserved

    empty = s.query("5.6.7.8")[0]
    assert empty["classification_type"] == "other"          # empty tag → other

    unmap = s.query("9.10.11.12")[0]
    assert unmap["classification_type"] == "other"          # unmappable → other
    assert unmap["extra"]["native_type"] == "#ransomware"   # raw still preserved


def test_tweetfeed_nonip_rows_filtered(tmp_path: Path):
    """domain/url/hash rows must not enter the IP DB (Principle: filter non-IP noise)."""
    (tmp_path / "tweetfeed.csv").write_text(
        "2025-07-31 00:00:11,a,domain,bad.example.com,#phishing,x\n"
        "2025-07-31 00:00:11,a,url,http://bad.example.com/x,#phishing,x\n"
        "2025-07-31 00:00:11,a,sha256,abc123,#phishing,x\n"
        "2025-07-31 00:00:11,a,ip,203.0.113.55,#phishing,x\n"
    )
    s = TweetFeedSource(data_dir=tmp_path)
    assert s.load() == 1                        # only the IP row survives
    assert s.query("203.0.113.55")
