"""全部 rebuild 覆写接受 progress 形参;list/dict 路径发 (0,total),生成器发 (n,0)。"""
import inspect

from ipdb._source_base import Source as SourceV2
from ipdb._sources._base import IpListSource, CsvSource
from ipdb._sources.tor_exits import TorExitSource
from ipdb._sources.cn_isp import ChineseISPSource
from ipdb._sources.firehol import FireholBlocklistSource
from ipdb._sources.spamhaus import SpamhausSource
from ipdb._sources.blocklist_de import BlocklistDeSource
from ipdb._sources.ipinfo_lite import IPinfoLiteSource
from ipdb._sources.abuseipdb import AbuseIPDBSource
from ipdb._sources.infra_services import InfraServicesSource

WIRED = [SourceV2, IpListSource, CsvSource, TorExitSource, ChineseISPSource,
         FireholBlocklistSource, SpamhausSource, BlocklistDeSource,
         IPinfoLiteSource, AbuseIPDBSource, InfraServicesSource]


def test_all_rebuild_overrides_accept_progress():
    for cls in WIRED:
        assert "progress" in inspect.signature(cls.rebuild).parameters, cls.__name__


def _run_ip_list_source(data_dir, lines):
    """IpListSource 子类最小实例:写入数据文件,rebuild 收集 progress。"""
    class T(IpListSource):
        name, filename = "t", "t.txt"
        fields = ("is_malicious",)

    src = T(data_dir)
    src._path.write_text("\n".join(lines) + "\n")
    calls = []
    src.rebuild(progress=lambda n, t: calls.append((n, t)))
    return calls


def test_iplist_source_emits_known_total(tmp_path):
    lines = [f"10.{i // 256 % 256}.{i % 256}.1" for i in range(30)]
    calls = _run_ip_list_source(tmp_path, lines)
    assert calls == [(0, 30), (30, 30)]   # <BATCH_SIZE:首跳+终值,无中跳
