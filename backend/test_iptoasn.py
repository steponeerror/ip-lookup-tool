"""Tests for IPtoASNSource — Task 4.2 migration onto the Source base.

Validates range→CIDR expansion via harvest(), which yields scalar Evidence
(country_code/asn/as_name/ip_range — NO classification_type) per CIDR.
"""
import gzip
import io
import pathlib
from pathlib import Path

from ipdb._sources.iptoasn import IPtoASNSource


def _write_fixture(path: Path, lines: list[str]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for ln in lines:
            f.write(ln + "\n")


def test_harvest_expands_range_to_cidr_scalar_evidence(tmp_path: Path):
    """One TSV range row → one (cidr, Evidence) pair with scalar slots only."""
    _write_fixture(
        tmp_path / "ip-to-asn.tsv",
        ["1.0.0.0\t1.0.0.255\t13335\tUS\tCloudflare"],
    )
    src = IPtoASNSource(data_dir=tmp_path)
    rows = list(src.harvest())

    assert len(rows) == 1
    cidr, ev = rows[0]
    assert cidr == "1.0.0.0/24"
    assert ev.asn == 13335
    assert ev.country_code == "US"
    assert ev.as_name == "Cloudflare"
    assert ev.ip_range == "1.0.0.0/24"
    # scalar source: no fusion-core fields set
    assert ev.classification_type is None
    assert ev.verdict == "malicious"  # dataclass default, but not set by harvest
    assert ev.reliability is None


def test_harvest_then_load_query_round_trip(tmp_path: Path):
    """harvest() output flows through base load() → MMDB → query() returns list[dict]."""
    _write_fixture(
        tmp_path / "ip-to-asn.tsv",
        ["1.0.0.0\t1.0.0.255\t13335\tUS\tCloudflare"],
    )
    src = IPtoASNSource(data_dir=tmp_path)
    n = src.load()
    assert n == 1

    recs = src.query("1.0.0.5")
    assert isinstance(recs, list)
    assert len(recs) == 1
    rec = recs[0]
    # canonical ip_range slot is stored (no more internal _net key)
    assert rec["ip_range"] == "1.0.0.0/24"
    assert rec["asn"] == 13335
    assert rec["country_code"] == "US"
    assert rec["as_name"] == "Cloudflare"
    assert "_net" not in rec


def test_harvest_skips_asn_zero(tmp_path: Path):
    """asn==0 rows are dropped (preserves legacy behavior)."""
    _write_fixture(
        tmp_path / "ip-to-asn.tsv",
        [
            "1.0.0.0\t1.0.0.255\t13335\tUS\tCloudflare",   # kept
            "2.0.0.0\t2.0.0.255\t0\tXX\tNobody",           # asn==0 → skipped
        ],
    )
    src = IPtoASNSource(data_dir=tmp_path)
    rows = list(src.harvest())
    asns = [ev.asn for _, ev in rows]
    assert asns == [13335]


def test_harvest_skips_short_and_invalid_rows(tmp_path: Path):
    """len(parts) < 5 and invalid IPs/asn are skipped (legacy contract)."""
    _write_fixture(
        tmp_path / "ip-to-asn.tsv",
        [
            "1.0.0.0\t1.0.0.255\t13335\tUS\tCloudflare",  # valid
            "9.9.9.9\t9.9.9.10\t13335\tUS",               # too few columns
            "",                                           # blank
            "not-an-ip\t1.0.0.1\t13335\tUS\tBad",         # invalid start IP
            "1.0.0.0\t1.0.0.1\tnot-an-asn\tUS\tBad",      # invalid asn (ValueError)
        ],
    )
    src = IPtoASNSource(data_dir=tmp_path)
    rows = list(src.harvest())
    assert len(rows) == 1
    assert rows[0][1].asn == 13335


def test_harvest_drops_empty_country_and_as_name(tmp_path: Path):
    """Empty country_code/as_name become None so Evidence.to_dict() omits them.
    Real TSV rows always have trailing columns — we test with empty-in-middle."""
    _write_fixture(
        tmp_path / "ip-to-asn.tsv",
        ["1.0.0.0\t1.0.0.255\t13335\t\tCloudflare"],  # country empty, as_name set
    )
    src = IPtoASNSource(data_dir=tmp_path)
    rows = list(src.harvest())
    assert len(rows) == 1
    _, ev = rows[0]
    assert ev.asn == 13335
    assert ev.country_code is None
    assert ev.as_name == "Cloudflare"
    d = ev.to_dict()
    assert "country_code" not in d
    assert d["as_name"] == "Cloudflare"
    assert d["asn"] == 13335


def test_download_overwrites_existing_destination_on_windows(tmp_path, monkeypatch):
    """Regression: tmp_path.rename(target) raises WinError 183 on Windows when the
    destination already exists. The fix must use an overwrite-capable primitive so a
    re-download over the prior file succeeds.

    On POSIX os.rename silently replaces, so the bug is invisible here — we simulate
    Windows os.rename semantics by making Path.rename raise FileExistsError when the
    target exists. Path.replace (os.replace) is unaffected, mirroring real Windows.
    """
    # Prior successful download left a stale destination file (the trigger condition).
    (tmp_path / "ip-to-asn.tsv").write_text("STALE OLD CONTENT\n")

    gz_bytes = gzip.compress(
        b"1.0.0.0\t1.0.0.255\t13335\tUS\tCloudflare\n")

    def _fake_urlopen(*args, **kwargs):
        return io.BytesIO(gz_bytes)

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    _real_rename = pathlib.Path.rename

    def _windows_rename(self, target):
        if Path(target).exists():
            raise FileExistsError(
                "[WinError 183] Cannot create a file when that file already "
                f"exists: {self!r} -> {Path(target)!r}")
        return _real_rename(self, target)

    monkeypatch.setattr(pathlib.Path, "rename", _windows_rename)

    src = IPtoASNSource(data_dir=tmp_path)
    src.download()  # must not raise

    content = (tmp_path / "ip-to-asn.tsv").read_text()
    assert "13335" in content
    assert "STALE OLD CONTENT" not in content
    assert not (tmp_path / "ip-to-asn.tsv.tmp").exists()
    assert not (tmp_path / "ip-to-asn.tsv.gz").exists()
