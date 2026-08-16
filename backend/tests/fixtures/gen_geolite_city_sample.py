"""Regenerate geolite_city_sample.mmdb — one-off, NOT a project dependency.

Run in a throwaway venv (never the project's):
    python3 -m venv /tmp/mmdbgen
    /tmp/mmdbgen/bin/pip install mmdb_writer==0.2.7 netaddr
    /tmp/mmdbgen/bin/python gen_geolite_city_sample.py

Fixture semantics (must not drift — tests assert on them):
  1.0.0.0/24    city Hangzhou(en)+杭州(zh-CN), country CN
  2.0.0.0/24    city Lyon(en, no zh), country FR
  3.0.0.0/24    country US only
  4.0.0.0/24    empty record {} (skip branch)
  2001:db8::/32 city Testville, country US (IPv6 skip branch)
"""
from pathlib import Path

from mmdb_writer import MMDBWriter
from netaddr import IPSet

RECORDS = [
    ("1.0.0.0/24", {"city": {"names": {"en": "Hangzhou", "zh-CN": "杭州"}},
                    "country": {"iso_code": "CN"}}),
    ("2.0.0.0/24", {"city": {"names": {"en": "Lyon"}},
                    "country": {"iso_code": "FR"}}),
    ("3.0.0.0/24", {"country": {"iso_code": "US"}}),
    ("4.0.0.0/24", {}),
    ("2001:db8::/32", {"city": {"names": {"en": "Testville"}},
                       "country": {"iso_code": "US"}}),
]

w = MMDBWriter(ip_version=6, ipv4_compatible=True,
               database_type="GeoLite2-City", languages=["en", "zh-CN"],
               description="Tiny fixture mirroring GeoLite2-City shape")
for cidr, rec in RECORDS:
    w.insert_network(IPSet([cidr]), rec)
w.to_db_file(Path(__file__).parent / "geolite_city_sample.mmdb")
print("written")
