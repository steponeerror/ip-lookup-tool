"""Tests for IpListSource base class behavior."""
import tempfile
from pathlib import Path
from ipdb._sources._base import IpListSource


class TestIpListSource:
    def test_parse_raw_strips_comments(self):
        class TestSource(IpListSource):
            name = "test"
            url = "https://example.com/test.txt"
            filename = "test.txt"
            fields = ("is_test",)

        src = TestSource(data_dir=Path("/tmp"))
        raw = b"1.2.3.4\n# comment\n5.6.7.0/24\n"
        entries = src.parse_raw(raw)
        assert entries == ["1.2.3.4", "5.6.7.0/24"]

    def test_get_insert_data_default(self):
        class TestSource(IpListSource):
            name = "test"
            url = "https://example.com/test.txt"
            filename = "test.txt"
            fields = ("is_malicious",)

        src = TestSource(data_dir=Path("/tmp"))
        data = src.get_insert_data()
        assert data == {"is_malicious": True}

    def test_load_strips_inline_comments(self, tmp_path):
        # spamhaus DROP format: "CIDR ; SBLxxxx" — inline comment after CIDR.
        # Must load all CIDRs/IPs, not silently drop them.
        class SpamhausLike(IpListSource):
            name = "spamhaus_like"
            url = "https://example.com/drop.txt"
            filename = "drop.txt"
            fields = ("is_malicious",)

        (tmp_path / "drop.txt").write_text(
            "; header comment line\n"
            "1.10.16.0/20 ; SBL256894\n"
            "1.2.3.4\n"
            "5.6.7.0/24 ; SBL000001\n"
            "\n"
        )
        src = SpamhausLike(data_dir=tmp_path)
        count = src.load()

        assert count == 3
        assert src.query("1.10.16.5") == [{"is_malicious": True}]
        assert src.query("5.6.7.1") == [{"is_malicious": True}]
        assert src.query("9.9.9.9") == {}


def test_get_insert_data_with_classification_type(tmp_path):
    class TypedSource(IpListSource):
        name = "typed"
        url = "https://example.com/list.txt"
        filename = "list.txt"
        fields = ("is_malicious",)
        classification_type = "blacklist"
        verdict = "malicious"

    src = TypedSource(data_dir=tmp_path)
    data = src.get_insert_data()
    assert data["classification_type"] == "blacklist"
    assert data["verdict"] == "malicious"
    assert "native_type" not in (data.get("extra") or {})  # retired (Plan B Task 1)


def test_get_insert_data_without_classification_type_unchanged():
    class LegacySource(IpListSource):
        name = "legacy"
        url = "https://example.com/legacy.txt"
        filename = "legacy.txt"
        fields = ("is_legacy",)

    src = LegacySource(data_dir=Path("/tmp"))
    data = src.get_insert_data()
    assert "extra" not in data
    assert data == {"is_legacy": True}
