"""#4 sidecar atomicity: the .count/.cov sidecars must commit atomically with
the ptr swap so an OOM-kill / SIGKILL during rebuild can never leave a fresh
LMDB epoch paired with a stale or missing sidecar (which would silently
misreport record_count / covered_ips on the next load).

rebuild_lmdb stages .count + .cov to temp paths and os.replace()s them (then
the ptr) as the final step. A crash anywhere before that final step leaves
either all-old (pre-rebuild) or all-new (committed) on disk — never a mix."""
import os

from ipdb._sources._base import IpListSource
from ipdb._sources._lmdb import count_path, cov_path, read_ptr, rebuild_lmdb


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


def test_rebuild_lmdb_leaves_no_fresh_epoch_without_sidecars(tmp_path):
    """#4 lock: rebuild_lmdb's contract is that when it returns, the .count/.cov
    sidecars on disk already match the newly-committed ptr epoch. Pre-fix (the
    old rebuild_mmdb), sidecar writing was left to the caller — so the moment
    the store was swapped, a fresh store sat on disk with stale/missing sidecars
    (the OOM-kill window). Post-fix, sidecars are staged and os.replace'd
    together with the ptr inside rebuild_lmdb, so this invariant holds at
    function return."""
    base = tmp_path / "t.txt.lmdb"
    # Seed an OLD committed state (epoch1 + stale sidecars) so we can detect a
    # fresh-epoch/stale-sidecar split.
    records_old = [("9.9.9.0/24", [{"x": 1}])]
    rebuild_lmdb(iter(records_old), base, lambda e: e.close())
    count_path(base).write_text("1")
    cov_path(base).write_text("256")

    # Now rebuild with NEW records (2 CIDRs) — this is the operation that, if
    # non-atomic, can leave a fresh 2-record epoch with the stale "1"/"256"
    # sidecars.
    records_new = [("1.2.3.0/24", [{"x": 1}]), ("10.0.0.0/16", [{"x": 1}])]
    n = rebuild_lmdb(iter(records_new), base, lambda e: e.close(), covered=512)

    # The count returned must already be reflected on disk (not left to a caller).
    count_on_disk = count_path(base)
    cov_on_disk = cov_path(base)
    assert count_on_disk.exists(), (
        "rebuild_lmdb returned but .count sidecar is missing — fresh-epoch/"
        "missing-sidecar crash window (#4)"
    )
    assert cov_on_disk.exists(), (
        "rebuild_lmdb returned but .cov sidecar is missing (#4)"
    )
    assert count_on_disk.read_text() == str(n), (
        f"fresh epoch has {n} records but .count still reads "
        f"{count_on_disk.read_text()!r} — fresh-epoch/stale-count split (#4)"
    )
    assert cov_on_disk.read_text() == "512", (
        f"fresh epoch covered=512 but .cov still reads "
        f"{cov_on_disk.read_text()!r} — fresh-epoch/stale-cov split (#4)"
    )
    assert read_ptr(base) == 2, "ptr must point at the newly-built epoch"


def test_rebuild_recovers_when_sidecars_missing(tmp_path):
    """If a crash DID leave sidecars missing (defensive: covers any path the
    atomic commit can't reach, e.g. manual deletion), load() must degrade
    gracefully — never crash, report 0 rather than a misleading stale count."""
    (tmp_path / "t.txt").write_text("1.2.3.0/24\n10.0.0.0/16\n")
    s = _List(data_dir=tmp_path)
    s.rebuild()
    s._reader.close()               # 同进程双开同 epoch 会报错;先关再 load
    # simulate a crash that lost the sidecars but left the MMDB
    s._mmdb_path.with_suffix(".count").unlink()
    s._mmdb_path.with_suffix(".cov").unlink()
    fresh = _List(data_dir=tmp_path)
    loaded = fresh.load()        # must not raise
    assert loaded == 0           # missing count sidecar → 0, not stale
    assert fresh._covered_ips == 0
