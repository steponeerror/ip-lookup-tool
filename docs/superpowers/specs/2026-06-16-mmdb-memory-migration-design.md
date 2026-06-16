# 内存优化：pytricia → MMDB（mmap）迁移设计

日期: 2026-06-16

## 目标

把 `ipdb` 的离线数据源从「pytricia 基数树 + 全量物化进 RAM」迁移到「MaxMind MMDB + mmap」，使**内存占用不再随数据量线性增长**，同时保持查询速度（亚微秒~微秒级）和现有 `OfflineSource` 契约不变。这是一次为「后续源数量爆炸增长」做的前瞻性架构升级。

## 背景

### 当前根因（不是 pytricia 的锅，是 value 模型的锅）

启动时 `main.py` 的 FastAPI `lifespan` → `_registry.refresh_stale()` → `_registry.load_db()`，把**每个源全量物化进内存**：

```python
def load_db() -> None:
    for source in _sources:
        source.load()   # 每个源 build 一棵 pytricia 树，常驻 RAM
```

内存模型问题出在**每个 CIDR 挂一个完整 Python dict 作为 value**。百万级 CIDR × 每个 dict ~232 字节头 = 数 GB。pytricia 的**树本身**（C 基数树）很紧凑；膨胀的是挂在上面的 Python dict value。

数据规模（`backend/data/`，与 `release/data/` 重复一份）：

| 文件 | 大小 |
|---|---|
| ipinfo_lite.csv | 288 MB |
| misp.json | 48 MB |
| threatfox.csv | 31 MB |
| ip-to-asn.tsv | 45 MB |
| ip2proxy_px2.zip | 15 MB |
| ipsum.txt | 2 MB |

`load_db()` 后 RSS ≈ Σ 所有源数据量，**随数据线性增长**。加源必然撞墙——这正是用户的核心顾虑。

### 为什么选 MMDB

- **为这个问题而生的事实标准**：MaxMind、IPinfo、DB-IP 三家主流 geo DB 厂商**全部用 MMDB 格式**。用户最大的源（IPinfo）的提供方自己就发 MMDB。

### MMDB 的容量边界与缓解

**格式上限**：MMDB 数据部分指针为 32 位，单文件最大 ≈ 4GB（数据段）+ 搜索树 + 元数据。写入器（`mmdb-writer`）在构建期也将整个树 + 数据字典放在内存中。

**对本项目的实际影响**（这是「每源一文件」设计的关键理由）：

| 约束 | 本项目情况 | 结论 |
|---|---|---|
| 单文件 4GB 上限 | 每源各一个 `.mmdb`，当前最大源 ipinfo_lite CSV 288MB → MMDB 只会更小（指针复用压缩 string value） | 不构成风险 |
| 写入器构建期 RAM | 只发生在 raw→MMDB 一次转换时（cached 后只 mmap 不构建）。ipinfo_lite 3-4M 行可能耗尽内存，但分两步缓解：(a) IPinfo 若原生 MMDB 则免转换；(b) 转换失败可回到 pytricia | 记录为风险（风险表已有） |
| 源数增长 | 每加一个源就多一个 `.mmdb` 文件 + 一个 mmap fd。普通 Linux/macOS fd 上限 256-∞，Windows 有限。几百个源之前不会触发 fd 问题 | 可接受 |
| 多 reader 查询性能 | 每次 lookup 遍历所有源、调每个 reader.get()。与当前模型一致（遍历所有 pytricia tree） | 不变 |
- **mmap 内存模型对症**：每个源 = 一个 mmap 文件 + 一个 reader，RSS ≈ **工作集**（最近查过的页），OS 在内存紧张时自动换出冷页。**数据涨 10×、RSS 不涨 10×**。
- **成熟工具链**：`maxminddb`（reader，mmap，μs 级，纯 Python + 可选 C 扩展）+ `mmdb-writer`（写自定义 MMDB）。
- **value 表达力够**：MMDB 支持 map / array / 嵌套对象，能表达威胁源「一个 CIDR 多条证据」的数组语义。
- **原生支持 IPv6 + 最长前缀匹配**，与 pytricia 能力对齐。

### 技术尽调结论（核心事实点）

| 事实点 | 结论 | 复验状态 |
|---|---|---|
| `maxminddb` 成熟度 | 成熟，mmap 读取，μs 级，可选 C 扩展 | 高可信 |
| 能否写自定义 MMDB | `mmdb-writer`（IPinfo 维护，活跃） | 高可信 |
| IPinfo 是否原生 MMDB | 便宜模型称 `?format=mmdb` 支持 | **实现期必须实测** |
| MMDB value 结构 | 支持 map/array/嵌套 | 高可信 |
| mmap 内存行为 | RSS ≪ 文件大小，OS 自动换出冷页 | 高可信 |
| IPv6 + 最长前缀匹配 | 原生支持 | 高可信 |

「MMDB 之外是否有更新的技术」已尽调：周边（PyRadix、marisa-trie、Rust-trie-via-PyO3、poptrie/DXR/SAIL）要么是同一思想的实现变体、要么无 Python 绑定/不适合多源场景。**没有成熟、Python 可用、能在本项目约束下明显超过 MMDB 的新技术。** MMDB 是正确终局。

## 设计

### 核心洞察：契约不变，风险隔离

`OfflineSource` 协议（`download / load / query / health`）**完全不变**。改的只是每个源的**内部实现**：

| 方法 | 现在 | 之后 |
|---|---|---|
| `load()` | 建 pytricia 树，全量进 RAM | raw→mmdb 转换（按 mtime 缓存）+ 打开 mmap reader |
| `query(ip)` | `tree[ip]` | `reader.get(ip)` |
| `download()` | 下原始 CSV/JSON | （多数不变）原生 MMDB 源改下 `.mmdb` |
| `health()` | 查树/文件 | 查 reader/文件 |

**`_registry.py` 的 `load_db / lookup / get_status` 一行不动。** 所有合并 / 打分 / 分类逻辑原封不动。迁移可逐源进行、任意时刻暂停。

### 两类源

| 类别 | 源 | load() 行为 |
|---|---|---|
| **原生 MMDB**（最佳） | ipinfo_lite | 直接下 `.mmdb` → mmap（若 IPinfo 提供；否则走转换）。最大源零转换。 |
| **转换源** | ip-to-asn, cn_isp, misp, threatfox, otx, abuseipdb, firehol, ipsum, blocklist_de, emerging_threats, spamhaus, tor_exits, x4bnet_vpn, ip2proxy | 用 `mmdb-writer` 把原始下载转成 `.mmdb` → mmap |

### value schema（复用现有 query() 输出形状）

`_registry.lookup()` 已兼容两种 query 返回：

```python
raw = source.query(ip)
items = raw if isinstance(raw, list) else [raw]   # 兼容单 dict 与 list[dict]
```

故 MMDB value 直接镜像现有 query 输出形状：

| 源类别 | MMDB value 类型 | query() 返回 | 示例 |
|---|---|---|---|
| **标量源** | map（单 map/CIDR） | dict | `{country_code, asn, as_name, has_asn}` |
| **威胁源** | array of map（数组/CIDR） | list[dict] | `[{classification_type, verdict, extra:{native_type}}, ...]` |
| **资产源** | map | dict | `{is_proxy, is_tor, is_vpn, carrier}` |

威胁源的「同一 CIDR 多条证据」正好对应 MMDB 数组 value，与现有 per-CIDR 累积成 list 的语义（如 `misp.py` 的 `acc: dict[str, list[dict]]`）直接平移。

### 转换缓存（保启动快）

转换源 `load()` 流程：

```python
def load(self) -> int:
    mmdb_path = self._data_dir / f"{self.name}.mmdb"
    if not (mmdb_path.exists() and mmdb_path.stat().st_mtime >= self._path.stat().st_mtime):
        _convert(self._path, mmdb_path, parse_fn=self._parse)   # mmdb-writer
    self._reader = maxminddb.open_database(mmdb_path)            # mmap
    return self._count
```

raw 文件未变（mtime 比较）就复用已转好的 `.mmdb`，重启只 mmap、不转换。沿用 `refresh_stale`「新鲜就不重下」的思路。

### 文件结构变更

```
backend/ipdb/_sources/
  _mmdb.py                   # 新增：convert() helper + open_reader() + 两种 value_builder
  _base.py                   # 移除 IpListSource/CsvSource 建树逻辑（Phase 4）
  ipinfo_lite.py             # load/query 改 MMDB；download 视实测改下 .mmdb
  iptoasn.py / cn_isp.py     # 转换源：标量 map value
  misp.py / threatfox.py / otx.py / abuseipdb.py / firehol.py
  ipsum.py / blocklist_de.py / emerging_threats.py / spamhaus.py   # 转换源：array value
  ip2proxy.py / tor_exits.py / x4bnet_vpn.py                        # 资产源
```

`_registry.py`、`_merge.py`、`_types.py`、`main.py` 不变。

### `_mmdb.py` 公共 helper（草案）

```python
def convert(raw_path: Path, mmdb_path: Path,
            parse_fn: Callable[[Path], Iterator[tuple[str, Any]]]) -> int:
    """调 parse_fn 迭代 raw，产出 (cidr_str, value) 流，用 mmdb-writer 写 .mmdb。
    各源只提供自己的 parse_fn（迁移自现有 load() 的解析循环，去掉 tree.insert）；
    转换流程（建树/插入/写文件）共用。返回记录数。"""

def open_reader(mmdb_path: Path) -> maxminddb.Reader:
    """mmap 打开，返回 reader。"""
```

`parse_fn` 让每个源只声明「如何从自己的 raw 格式产出 (cidr, value)」，屏蔽 CSV/JSON/TSV/TXT 的异构性；转换与写盘逻辑统一。

## 迁移阶段（风险递增、收益前置）

- **Phase 0 — MMDB 基础设施**：新增 `_mmdb.py`（convert / open_reader / parse_fn 约定）。不动现有源。
- **Phase 1 — 端到端验证**：迁移 1–2 个**小**源（如 `ipsum`、`tor_exits`）全链路跑通，验证契约与 registry/lookup 不受影响。小源转换快、测试快。
- **Phase 2 — 内存大头**：`ipinfo_lite`（先实测 IPinfo 是否原生 MMDB；有则免转换）→ `ip-to-asn`、`cn_isp`（标量 map value）→ 威胁源（验证 array value schema）。
- **Phase 3 — 资产源**：`ip2proxy / tor_exits / x4bnet_vpn`（map value）。
- **Phase 4 — 收尾**：移除 pytricia 依赖 + `_base.py` 建树代码；清理为 pytricia Windows wheel 折腾的 CI（近期提交）。

## 测试策略

- **契约层（最大保护伞）**：`registry.lookup()` 流水线测试（merge / classification / verdict / confidence 等）走 source 的 `query()` 输出形状——query 输出形状不变，**应原样通过**。这是迁移安全的根基。
- **逐源测试**（test_threatfox / test_misp / test_otx / test_ip2proxy …）：凡断言 source 内部 `_tree` 的，改为断言 `query()` 输出（测契约，不测内部）。
- **新增**：每个转换源一个转换测试（小 fixture raw → mmdb → query 得预期）+ 一个缓存测试（raw 未变则复用 mmdb，不重转）。

## 风险与应对

| 风险 | 应对 |
|---|---|
| `mmdb-writer` 写 288MB CSV 性能可能慢；ipinfo_lite 3-4M 行写入器可能 OOM | 转换缓存（一次性）；若 IPinfo 原生 MMDB 则 ipinfo_lite 免转换；最坏方案：ipinfo_lite 保留 pytricia 不迁移。Phase 2 实测。 |
| Windows wheel：`mmdb-writer` 是否纯 Python | `maxminddb` 有官方 wheel；`mmdb-writer` 纯 Python + `netaddr` 纯 Python = Windows 无 C 编译需求（比 pytricia 省事太多）。 |
| 冷区域首查有缺页延迟（μs–ms） | 交互式查询工具完全可接受；热区后常驻变快。诚实边界，非阻塞。 |
| 威胁源多证据数组累积语义 | 现有 per-CIDR 累积模式直接平移；转换测试覆盖多证据场景。 |
| 便宜模型「IPinfo 原生 MMDB」结论 | 实现期用真实 token 实测；不成立则走 mmdb-writer 转换，方案仍有效。 |
| **MMDB 单文件 4GB 上限 + 写入器构建期高内存**（本次新增） | **每源各一文件**天然不触及 4GB。写入器 RAM 峰值仅发生在首次转换，cached 后消失。预计最大源 ipinfo_lite (3-4M 行) 构建 RAM 可能偏高，归入上方 mmdb-writer 性能风险一并实测。ip2proxy/cn_isp/misp/threatfox 等行数少 1-2 个量级，无风险。 |

## 验收标准（goal-driven，可独立循环验证）

1. **内存**：全量加载后 backend 进程 RSS，迁移前后实测对比。核心指标——**RSS 不再随总数据量线性增长**，实测 RSS ≈ 工作集而非 Σ 数据；加源时 RSS 不爆。
2. **速度**：`maxminddb.get()` 与 pytricia 同量级（μs），实测查询延迟对比。
3. **正确性**：所有 registry/lookup 流水线测试通过。

## 范围

- 新增 `_sources/_mmdb.py`（convert / open_reader / value_builder 约定）
- 所有离线源 `load()` / `query()` 迁移到 MMDB
- 转换结果按 mtime 缓存
- 移除 pytricia 依赖 + `_base.py` 建树代码
- 逐源测试改为测 `query()` 契约 + 新增转换/缓存测试

## 不在范围内

- IPv6（MMDB 原生支持，但本次不新增 IPv6 数据源）
- 自研紧凑二进制格式（评估后确认 MMDB 优于自研，不另造轮子）
- Rust-trie / PyO3 路线（同属自研，工程量与 Windows 分发复杂度更高，不采用）
- 在线 enricher（ip-api / ipapi.is）改造（它们不走 mmap，与本设计无关）
- 磁盘层去重（`backend/data` 与 `release/data` 各一份，是打包问题，非运行时内存问题）
