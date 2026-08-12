import json

from ipdb._sources.cdn_edges import CdnEdgesSource, _parse

# Combined-intermediate fixture (cidr,provider) — exactly what download() writes.
_FIXTURE = """\
13.32.0.0/15,CloudFront
52.84.0.0/15,CloudFront
173.245.48.0/20,Cloudflare
103.21.244.0/22,Cloudflare
151.101.0.0/16,Fastly
"""


def test_cdn_edges_loads_and_routes(tmp_path):
    (tmp_path / "cdn_edges.csv").write_text(_FIXTURE)
    s = CdnEdgesSource(data_dir=tmp_path)
    assert s.rebuild() == 5
    # CloudFront edge range
    r = s.query("13.32.10.20")[0]
    assert r["service"] == "cdn"
    assert r["_native_types"] == {"service": "CloudFront"}
    # Cloudflare
    assert s.query("173.245.48.5")[0]["_native_types"] == {"service": "Cloudflare"}
    # Fastly
    assert s.query("151.101.5.5")[0]["_native_types"] == {"service": "Fastly"}
    # not in feed
    assert s.query("8.8.8.8") == {}
    # asset-only source: the "malicious" default verdict must NOT leak
    assert "verdict" not in r


def test_cdn_edges_health_loaded_not_stale(tmp_path):
    (tmp_path / "cdn_edges.csv").write_text(_FIXTURE)
    s = CdnEdgesSource(data_dir=tmp_path)
    s.rebuild()
    h = s.health()
    assert h.loaded is True
    assert h.record_count == 5
    assert h.is_stale is False      # stale_days=7; fixture just written


def test_parse_aws_cloudfront_only():
    data = json.dumps({
        "prefixes": [
            {"ip_prefix": "13.32.0.0/15", "service": "CLOUDFRONT"},
            {"ip_prefix": "52.94.0.0/20", "service": "EC2"},   # not CloudFront → drop
        ],
        "ipv6_prefixes": [
            {"ipv6_prefix": "2600:1f18:4000::/40", "service": "CLOUDFRONT"},  # v6 list → never read
        ],
    }).encode()
    assert list(_parse(data, "aws")) == ["13.32.0.0/15"]


def test_parse_cloudflare_strips_blanks_and_garbage():
    data = b"173.245.48.0/20\n103.21.244.0/22\n\n<html>oops\n"
    assert list(_parse(data, "cloudflare")) == ["173.245.48.0/20", "103.21.244.0/22"]


def test_parse_fastly_v4_only():
    data = json.dumps({
        "addresses": ["151.101.0.0/16", "199.232.0.0/16"],
        "ipv6_addresses": ["::/0"],   # v6 list → never read
    }).encode()
    assert list(_parse(data, "fastly")) == ["151.101.0.0/16", "199.232.0.0/16"]
