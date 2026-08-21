# Source Archetypes — 选择器 + 范例索引

原型选择靠判据，代码事实靠现场发现。本文件不复述代码——每个原型给：
判据（什么格式选它）+ 该读的真实范例（1-2 个锚点文件）+ 该 grep 的钩子。
写源之前把范例文件**通读**，抄真实代码，不抄记忆中的骨架。

基类现场发现（不要背清单）：

```bash
grep "^class" backend/ipdb/_sources/_base.py     # 简单基类（IpListSource, CsvSource）
grep "^class" backend/ipdb/_source_base.py       # 统一 Source 基类
grep "def " backend/ipdb/_sources/_base.py       # 可覆写钩子全录（parse_raw/get_insert_data/…）
grep "def " backend/ipdb/_source_base.py         # 生命周期钩子（download/harvest/rebuild/load/query/health）
ls backend/ipdb/_sources/                        # 全部真实范例
```

> **例外：** `ipinfo_lite` 是无基类独立类（load-bearing 遗留 geo/ASN 骨干，
> 返回非 Evidence dict）。不是模板——新源一律用 `Source` 子类。

## 1. IpListSource — 纯 IP/CIDR 列表

**判据：** 每行一个 IP 或 CIDR（可有 `#` 注释 / `CIDR ; note` 尾注），
无每行元数据。多数封禁列表即此。
**锚点范例：** 通读 `binarydefense.py`（20 行，最小完整源）；带 auth 头
`download()` 覆写 + JSON 空数据守卫看 `abuseipdb.py`。
**覆写面（按需）：** `grep "def " backend/ipdb/_sources/_base.py` 查看
`parse_raw`（正则提取行）/ `get_insert_data`（非标准存储形状，罕见）/
`download`（auth/解压/内容校验——200-OK 空载荷必须当失败，否则下次
rebuild 静默清空该源）。
**非威胁列表：** 去掉 `classification_type`/`verdict`，落回 legacy
`{fields[0]: True}` 形状。

## 2. CsvSource — 定形 CSV/TSV 行

**判据：** 固定列形状 + 每行少量元数据（时间戳/计数/标签），无行级
控制流。你只实现 `parse_row(row) -> dict | None`，读文件/IP 归一/
按 CIDR 累积 + 全证据去重（convention 3）全由基类 `rebuild()` 做。
**锚点范例：** 通读 `ipsum.py`（37 行，最小 CsvSource + reporter_count
+ 阈值过滤行）；富行路由（city/asn → canonical、anonymity → extra）
看 `proxyscrape.py`。行内 per-row 分类（threat 列）目前无 CsvSource
范例，活范例是 harvest 系的 `threatfox.py` / `urlhaus.py`。
**返回 dict 的合法键：** `_ip`（缺省取 `row[0]`）、`_cidr`、
`classification_type`、`verdict`、核心元数据（`malware_name`/
`first_seen`/`confidence`）、任何 canonical 槽（现场读
`_evidence.py` 的 frozensets——`CORE_FIELDS`/`SCALAR_SLOTS`/
`RICH_SLOTS`/`ASSET_SLOTS`/`ALL_KNOWN`，名字稳定、内容以代码为准）、
`extra` dict。
**`rebuild()` 去重语义：** 按**全证据相等**（不是 3 元组）——同
classification/verdict/malware 但不同 confidence/first_seen/last_seen/
comment 的两行是两条独立证据，都必须存活（convention 3）。

## 3. Source subclass — 定制格式（harvest 模式）

**判据（灰区表，任一命中即弃简单基类）：**

| 触发 | 锚点范例 |
|---|---|
| 行过滤（按值/阈值丢弃） | `ip2proxy.py`（SES/WEB 丢弃） |
| 条件字段路由 | `reportedip.py`（per-code 分组） |
| 1→多：一行 → 多 CIDR | `iptoasn.py`、`ip2proxy.py` |
| 嵌套归档（ZIP/gzip） | `threatfox.py`、`stopforumspam.py` |
| REST 状态机（游标/分页） | `otx.py` |
| 多文件加载（一个源多文件） | `cn_isp.py` |
| 每行 Evidence（时间戳/计数） | `otx.py`、`reportedip.py` |
| `.mmdb` 二进制输入 | `geolite_city.py`（maxminddb>=2.0 只读依赖，mmap 迭代） |

无任何命中 → 留在 IpListSource / CsvSource。
**实现面：** 覆写 `download()` + `harvest()`（yield `(cidr_str, Evidence)`），
继承其余。**写之前通读 `iptoasn.py` 全文**——canonical 最小模板。
**继承表（不要重实现）：** `grep "def " backend/ipdb/_source_base.py`
逐个看：`load()` 纯 mmap、`rebuild()` 唯一写路径（分组/流式 +
`rebuild_lmdb` + `reader_setter`/**必须带 `flag_setter`**——漏了会在
disjoint→nested 翻转时静默漏父覆盖命中）、`query()` 关闭-env 重开重试、
`health()` mtime 计算 stale、`_http_get()`（GET-only，重试+UA+auth 头；
POST/JSON-body 需手写 HTTP）。
**`single_evidence`：** 类属性（默认 False）。True 时 `rebuild()` 流式
直写 `rebuild_lmdb()` 而非累积全量 dict——geo/asset 大源（每 CIDR 至多
一条证据）用它（ip2proxy 曾因无此标志冲到 686 MB RSS）。**多证据威胁源
必须保持 False**——它们靠累积器聚合。语义以
`grep -A5 "single_evidence" backend/ipdb/_source_base.py` 为准。

## 3b. rebuild override — 升级既有 IpListSource

**定位：升级路径，非首选。** 新源带每行值 → 直接 §3 `Source` 子类。
仅当给既有 `IpListSource` 加每行字段且不想换基类时覆写 `rebuild()`
（先例：`spamhaus.py` 保 `; SBL-id` 尾注、`tor_exits.py` 保 `ip,ts` 行）。
覆写即手工重实现基类解析环，因此**独占四件事**：每行 Evidence 构造、
`rebuild_lmdb()` 的 records 列表、finally 里关旧 reader、
`flag_setter=lambda v: setattr(self, "_disjoint", v)`（与
`reader_setter` 并排，缺即重现 stale-flag 静默漏命中缺陷）。
**抄真实实现：** 通读 `spamhaus.py` 的 `rebuild()`——四件事的完整活例。
多文件变体（mtime 门控跨文件 rebuild）看 `cn_isp.py`。

## 3c. directory source — 一个发布方多子列表

**判据：** 一个发布方多个相关列表（firehol ipsets、blocklist.de 攻击型
子表），一个源订阅一个目录：`filename` 即目录名；`download()` 循环各表；
`rebuild()` 跨文件累积并裁决；`health()` 取跨文件 **max** mtime
（convention 4）。历史布局是单文件时必须带 `_cleanup_legacy`（旧文件+
LMDB sidecar 两形态：epoch 目录 rmtree、ptr/count/cov 文件 unlink）。
**锚点范例：** 通读 `blocklist_de.py`（优先级裁决分类 + native_categories
并集）；per-list tags 归属 + mtime 门控看 `firehol.py`。
**实现后必跑：** `python scripts/audit_lmdb_invariants.py`（**从仓库根**，
脚本在 `scripts/` 不在 `backend/`；目录源是 same-start/nested CIDR 冲突
的已知高发面）。

## 5. `field_map`（声明式列→槽路由）

> **实验性——当前 0 源使用。** `_validate.py` 认识 `field_map` 但无源声明。
优先 `harvest()`/`parse_row()` 内显式路由；把 `field_map` 当前瞻声明。
规则（`_validate.validate_source` 载入时校验，warn-only）：目标必须在
`ALL_KNOWN` 内或以 `extra` 开头；多列同槽记碰撞。
**`field_map` ≠ `_MAP`：** 前者路由"列 → Evidence 槽"（类属性），后者
映射"原生类别 → 受控词表项"（`_classification.py` 里的 dict）。见
`classification.md`。
