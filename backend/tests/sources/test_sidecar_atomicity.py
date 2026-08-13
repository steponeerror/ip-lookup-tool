"""#4 sidecar atomicity: the .count/.cov sidecars must commit atomically with
the MMDB so an OOM-kill / SIGKILL during rebuild can never leave a fresh MMDB
paired with a stale or missing sidecar (which would silently misreport
record_count / covered_ips on the next load).

The fix stages mmdb + .count + .cov to temp paths inside rebuild_mmdb and
os.replace()s all three as the final step. A crash anywhere before that final
step leaves either all-old (pre-rebuild) or all-new (committed) on disk — never
a mix."""
import os

from ipdb._sources._base import IpListSource
from ipdb._sources._mmdb import rebuild_mmdb


class _List(IpListSource):
    name, filename, fields = "t", "t.txt", ("is_malicious",)


def test_rebuild_commits_all_three_files_together(tmp_path):
    """After a clean rebuild, mmdb + .count + .cov all exist and are mutually
    consistent. Baseline sanity the atomic path must not regress."""
    (tmp_path / "t.txt").write_text("1.2.3.0/24\n10.0.0.0/16\n")
    s = _List(data_dir=tmp_path)
    n = s.rebuild()
    assert n == 2
    assert s._mmdb_path.exists()
    assert s._mmdb_path.with_suffix(".count").read_text() == "2"
    assert s._mmdb_path.with_suffix(".cov").read_text() == str(256 + 65536)


def test_rebuild_mmdb_leaves_no_fresh_mmdb_without_sidecars(tmp_path):
    """#4 lock: rebuild_mmdb's contract is that when it returns, the on-disk
    MMDB already has matching .count/.cov sidecars. Pre-fix, rebuild_mmdb
    os.replace'd the MMDB but left sidecar writing to the caller — so the moment
    rebuild_mmdb returned, a fresh MMDB sat on disk with stale/missing sidecars
    (the OOM-kill window). Post-fix, all three are staged and os.replace'd
    together inside rebuild_mmdb, so this invariant holds at function return."""
    mmdb = tmp_path / "t.mmdb"
    # Seed an OLD committed state (old mmdb + old sidecars) so we can detect a
    # fresh-mmdb/stale-sidecar split.
    records_old = [("9.9.9.0/24", [{"x": 1}])]
    rebuild_mmdb(iter(records_old), mmdb,
                 reader_setter=lambda r: None, database_type="IP-Radar-t")
    mmdb.with_suffix(".count").write_text("1")
    mmdb.with_suffix(".cov").write_text("256")

    # Now rebuild with NEW records (2 CIDRs) — this is the operation that, if
    # non-atomic, can leave a fresh 2-record MMDB with the stale "1"/"256"
    # sidecars.
    records_new = [("1.2.3.0/24", [{"x": 1}]), ("10.0.0.0/16", [{"x": 1}])]
    n = rebuild_mmdb(iter(records_new), mmdb,
                     reader_setter=lambda r: None, database_type="IP-Radar-t")

    # The count returned must already be reflected on disk (not left to a caller).
    count_on_disk = mmdb.with_suffix(".count")
    cov_on_disk = mmdb.with_suffix(".cov")
    assert count_on_disk.exists(), (
        "rebuild_mmdb returned but .count sidecar is missing — fresh-MMDB/"
        "missing-sidecar crash window (#4)"
    )
    assert cov_on_disk.exists(), (
        "rebuild_mmdb returned but .cov sidecar is missing (#4)"
    )
    assert count_on_disk.read_text() == str(n), (
        f"fresh MMDB has {n} records but .count still reads "
        f"{count_on_disk.read_text()!r} — fresh-MMDB/stale-count split (#4)"
    )


def test_rebuild_recovers_when_sidecars_missing(tmp_path):
    """If a crash DID leave sidecars missing (defensive: covers any path the
    atomic commit can't reach, e.g. manual deletion), load() must degrade
    gracefully — never crash, report 0 rather than a misleading stale count."""
    (tmp_path / "t.txt").write_text("1.2.3.0/24\n10.0.0.0/16\n")
    s = _List(data_dir=tmp_path)
    s.rebuild()
    # simulate a crash that lost the sidecars but left the MMDB
    s._mmdb_path.with_suffix(".count").unlink()
    s._mmdb_path.with_suffix(".cov").unlink()
    fresh = _List(data_dir=tmp_path)
    loaded = fresh.load()        # must not raise
    assert loaded == 0           # missing count sidecar → 0, not stale
    assert fresh._covered_ips == 0
