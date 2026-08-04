"""feodo was removed (sunset 2026-03, redundant with threatfox). Guard against
re-introducing references to it in the registry/merge maps."""
import re
from pathlib import Path

BACKEND = Path(__file__).parent
TARGETS = ["ipdb/_registry.py", "ipdb/_merge.py"]


def test_no_feodo_in_registry_or_merge():
    for rel in TARGETS:
        text = (BACKEND / rel).read_text(encoding="utf-8")
        assert not re.search(r"\bfeodo\b", text), (
            f"`feodo` still referenced in {rel} — remove SOURCE_RELIABILITY, "
            "AUTHORITATIVE_SOURCES, and category entries")


def test_feodo_source_file_deleted():
    assert not (BACKEND / "ipdb" / "_sources" / "feodo.py").exists()
