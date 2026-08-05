"""Tests for cancel-aware atomic download helper."""
import threading
from pathlib import Path
from unittest.mock import patch

from ipdb._sources._download import CancelToken, CancelledError, download_file


class _FakeResp:
    def __init__(self, chunks, status=200):
        self._chunks = list(chunks)
        self.status = status
        self.closed = False
        self.headers = {}
    def read(self, n):
        if not self._chunks:
            return b""
        data = self._chunks.pop(0)
        return data[:n]
    def close(self):
        self.closed = True
    def __enter__(self):
        return self
    def __exit__(self, *a):
        self.close()


def _patch_urlopen(resp):
    return patch("urllib.request.urlopen", return_value=resp)


def test_download_file_writes_atomically(tmp_path: Path):
    dest = tmp_path / "out.txt"
    resp = _FakeResp([b"hello-", b"world"])
    with _patch_urlopen(resp):
        download_file("http://x/y", dest)
    assert dest.read_bytes() == b"hello-world"
    assert not (tmp_path / "out.txt.tmp").exists()  # tmp cleaned


def test_pre_cancelled_token_raises_and_no_dest(tmp_path: Path):
    dest = tmp_path / "out.txt"
    token = CancelToken()
    token.cancel()
    resp = _FakeResp([b"data"])
    with _patch_urlopen(resp):
        try:
            download_file("http://x/y", dest, token=token)
            assert False, "expected CancelledError"
        except CancelledError:
            pass
    assert not dest.exists()
    assert not (tmp_path / "out.txt.tmp").exists()


def test_cancel_mid_stream_cleans_tmp(tmp_path: Path):
    dest = tmp_path / "out.txt"
    token = CancelToken()
    resp = _FakeResp([b"chunk1"])

    def fake_read(n):
        token.cancel()           # cancel during the read
        return b"chunk1"
    resp.read = fake_read
    with _patch_urlopen(resp):
        try:
            download_file("http://x/y", dest, token=token)
            assert False, "expected CancelledError"
        except CancelledError:
            pass
    assert not dest.exists()
    assert not (tmp_path / "out.txt.tmp").exists()


def test_token_threadsafe_cancel():
    t = CancelToken()
    assert not t.is_cancelled()
    threading.Thread(target=t.cancel).start()
    for _ in range(100):
        if t.is_cancelled():
            break
    assert t.is_cancelled()
