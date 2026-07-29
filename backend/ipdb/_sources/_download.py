"""Cancel-aware atomic download helper shared by file-backed sources."""
import os
import urllib.request
from pathlib import Path


class CancelledError(Exception):
    """Raised when a download is cancelled via its CancelToken."""


class CancelToken:
    """Thread-safe cancellation flag checked between download chunks."""

    def __init__(self):
        import threading
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    def is_cancelled(self) -> bool:
        return self._event.is_set()


def download_file(
    url: str,
    dest: Path,
    token: CancelToken | None = None,
    *,
    connect_timeout: float = 10,
    read_timeout: float = 30,
    headers: dict | None = None,
    chunk_size: int = 65536,
) -> None:
    """Stream `url` to `dest` atomically.

    Writes a sibling .tmp file, then os.replace onto `dest` on success — so
    readers only ever see a complete old or new file. Checks `token` between
    chunks; on cancel/failure the .tmp is removed and `dest` is untouched.
    """
    if token is not None and token.is_cancelled():
        raise CancelledError("cancelled before start")

    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.parent / (dest.name + ".tmp")
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(
            req, timeout=connect_timeout
        ) as resp:  # connect timeout applies; read loop enforces read timeout
            with open(tmp, "wb") as f:
                while True:
                    if token is not None and token.is_cancelled():
                        raise CancelledError("cancelled mid-stream")
                    chunk = resp.read(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
        os.replace(str(tmp), str(dest))
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
