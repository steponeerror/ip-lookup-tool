"""lifespan wires the batch process pool (M workers) per uvicorn worker."""
import main
import ipdb._batch_pool as bp


def test_lifespan_creates_and_clears_pool(monkeypatch):
    """After lifespan startup, a pool is set; after shutdown, it's cleared."""
    monkeypatch.setattr(bp, "detect_host", lambda: (16, 3900))  # -> (N=2, M=6)
    monkeypatch.setattr(bp, "load_perf_config", lambda *a, **k: None)
    monkeypatch.setattr(main, "_startup", lambda: None)  # avoid real load_db
    import asyncio
    from fastapi import FastAPI

    app = FastAPI(lifespan=main.lifespan)

    async def run():
        async with main.lifespan(app):
            assert bp.get_pool() is not None
        # after exit, pool cleared
        assert bp.get_pool() is None

    asyncio.run(run())


def test_lifespan_sets_m_from_layout(monkeypatch):
    monkeypatch.setattr(bp, "detect_host", lambda: (4, 4096))  # -> (N=1, M=3)
    monkeypatch.setattr(bp, "load_perf_config", lambda *a, **k: None)
    monkeypatch.setattr(main, "_startup", lambda: None)
    import asyncio
    async def run():
        async with main.lifespan(main.app):
            assert main.get_active_layout()["m_pool"] == 3
    asyncio.run(run())
