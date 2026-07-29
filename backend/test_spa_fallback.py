"""SPA fallback: BrowserRouter deep links like /sources must serve index.html on
direct hit / refresh. Without a fallback, StaticFiles(html=True) 404s any path
that isn't a real file (e.g. /sources), so opening or refreshing the Sources
page at /sources breaks with 404."""
from fastapi.testclient import TestClient

import main


def test_client_route_deep_link_serves_index_html():
    client = TestClient(main.app)
    resp = client.get("/sources")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    assert '<div id="root">' in resp.text


def test_unknown_api_route_still_404s():
    """SPA fallback must not swallow unknown /api/* paths — API clients expect
    a 404, not index.html."""
    client = TestClient(main.app)
    resp = client.get("/api/does-not-exist")
    assert resp.status_code == 404


def test_real_static_file_served_as_file():
    """Real files (assets, favicon) must still be served with their own
    content type, not collapsed to index.html."""
    client = TestClient(main.app)
    resp = client.get("/favicon.svg")
    assert resp.status_code == 200
    assert not resp.headers["content-type"].startswith("text/html")

