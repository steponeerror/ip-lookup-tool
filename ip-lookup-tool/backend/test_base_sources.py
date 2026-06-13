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
