from ipdb._sources.stopforumspam import StopForumSpamSource


def test_stopforumspam_loads_cidr_list(tmp_path):
    (tmp_path / "stopforumspam.txt").write_text(
        "109.200.1.0/24\n"
        "109.200.16.0/20\n"
        "174.76.30.11/32\n"
        "\n"                # blank line — skipped
        "# comment line\n"  # comment — skipped
    )
    s = StopForumSpamSource(data_dir=tmp_path)
    assert s.load() == 3

    hit = s.query("109.200.1.5")[0]               # inside the /24
    assert hit["classification_type"] == "spam"
    assert hit["extra"] == {"native_type": "spam"}
    assert hit["verdict"] == "informational"
    assert hit["reliability"] == 0.70

    assert s.query("174.76.30.11")[0]["classification_type"] == "spam"   # exact /32
    assert s.query("109.200.20.5")[0]["classification_type"] == "spam"   # inside /20, outside /24
    assert s.query("8.8.8.8") == {}                                     # non-matching
