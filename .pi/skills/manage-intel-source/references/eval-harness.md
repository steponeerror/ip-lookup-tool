# Eval Harness 用法

## download 前置(eval 保持纯)

`load_db()` 只 load 已有数据文件,**不 download**。新源第一次必须显式 download,否则候选采样为空 → INSUFFICIENT-SAMPLE(假象)。

```python
from ipdb._registry import _sources
s = next(x for x in _sources if x.name == "<source>")
s.download()        # 显式前置
s.rebuild()         # LMDB 唯一写入口(load 此时无 env 只会返回 0)
print(s.health())   # 确认 record_count > 0、is_stale=False
```

大源(数百万 CIDR)rebuild 前留意 RSS:单证据 geo/asset 源已走 `single_evidence` 流式;若新增累积型大源,在 WSL 内单进程 rebuild 仍可能吃数百 MB。

然后 eval:`python -m ipdb._eval <source>`(从 `backend/` cwd)。

**为什么不放进 eval 自动 download**:eval 的设计基石是 reproducible seeded sampling(确定性)。混入网络 side-effect 会:(a) 首次慢、(b) 下载失败时 eval 挂而非给 verdict、(c) CI/批量评估抖动。download 是"准备数据",eval 是"评估",职责分离。

## metrics 解读

| metric | 含义 | 高= |
|---|---|---|
| MC | 去掉该源丢多少 (ip,type) | 贡献大 |
| CG | 独立源佐证数 | 可信(VERIFIED 门槛) |
| OC | 与其他源重叠率 | 高=冗余 |
| fp | benign IP 误伤率 | 高=误报(MIXED 的 cost lever) |
| other | 分类映射到 `other` 的比例 | 高=分类膨胀(收紧 `_MAP`) |
| dead_slot_fill | 填补的空分类槽 | 该源独占某分类 |
| confidence_uplift | 带来的置信度提升 | 贡献 |

## INSUFFICIENT-SAMPLE 别误判

多为 corpus 偏向(geo/asn 源 IP 不在威胁 corpus),不是源差。例:cn_isp/iptoasn/ipinfo_lite(geo)、ip2proxy/stopforumspam(数据少或 IP 不在样本)。处理:补样本 / 换 corpus / 接受(geo 源本就不靠威胁 corpus 评估)。
