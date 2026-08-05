"""Cancel-aware atomic download helper shared by file-backed sources."""
import os
import threading
import urllib.request
from pathlib import Path
from typing import Callable, Optional


class CancelledError(Exception):
    """Raised when a download is cancelled via its CancelToken."""


class CancelToken:
    """Thread-safe cancellation flag checked between download chunks.

    Also carries an optional ``on_progress`` reporter so ``download_file`` can
    stream byte progress (received, total) to the task runner without each
    source having to thread a callback through its ``download()`` signature —
    every source already passes its ``token`` to ``download_file``.
    """

    def __init__(self):
        self._event = threading.Event()
        self.on_progress: Optional[Callable[[int, int], None]] = None

    def cancel(self) -> None:
        self._event.set()

    def is_cancelled(self) -> bool:
        return self._event.is_set()


def download_file(
    url: str,
    dest: Path,
    token: CancelToken | None = None,
    *,
    timeout: float = 30,
    headers: dict | None = None,
    chunk_size: int = 65536,
) -> None:
    """Stream `url` to `dest` atomically.

    Writes a sibling .tmp file, then os.replace onto `dest` on success — so
    readers only ever see a complete old or new file. Checks `token` between
    chunks; on cancel/failure the .tmp is removed and `dest` is untouched.

    Args:
        timeout: stdlib urllib socket timeout applied to all socket ops
            (connect+read); it cannot be split, and bounds abort latency
            to one read.
    """
    if token is not None and token.is_cancelled():
        raise CancelledError("cancelled before start")

    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.parent / (dest.name + ".tmp")
    req = urllib.request.Request(url, headers=headers or {})
    on_progress = getattr(token, "on_progress", None) if token is not None else None
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            total = int(resp.headers.get("Content-Length") or 0)
            received = 0
            with open(tmp, "wb") as f:
                while True:
                    if token is not None and token.is_cancelled():
                        raise CancelledError("cancelled mid-stream")
                    chunk = resp.read(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    received += len(chunk)
                    if on_progress is not None:
                        on_progress(received, total)
            if on_progress is not None and total > 0:
                on_progress(received, total)  # ensure final 100% lands
        os.replace(str(tmp), str(dest))
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
