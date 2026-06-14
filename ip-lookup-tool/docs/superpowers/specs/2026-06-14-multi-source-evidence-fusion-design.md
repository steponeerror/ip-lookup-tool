# 多源证据融合设计（Multi-Source Evidence Fusion）

**日期**: 2026-06-14
**状态**: 设计待评审（已整合 4+1 轮并行 agent 评审）
**分支**: `feat/source-registry`

## 背景（Context）

当前每个源只把数据"压扁"成一两个布尔（threatfox 只吐 `is_malicious=True`），而 malware 家族/置信度/first_seen、ip2proxy `proxy_type`、spamhaus SBL、OTX pulse 数等富信息全部丢弃。`SourceAttribution` 每源每字段只带一个标量，`LookupResult` 固定 schema，`lookup()` 只消费 `THREAT_BOOLS` + 4 标量。后果：无法跨源复核、STIX 导出贫瘠、`is_malicious` 把 C2/暴力破解/黑名单混为一谈。

本设计借鉴 MISP（证据/Sighting/Warninglist）、IntelMQ（Harmonization 规范字段）、OpenCTI/STIX 2.1（聚合 Sighting）三者之长，且经多轮并行 agent 评审修正。

### Scope Guard（防类比蔓延）
> 这是**单 IP 富化查询工具**，不是 MISP 多租户共享平台。只采用 MISP 的 per-attribute 证据丰富度 + Sighting 复核。**不建模 Event 容器、不建跨 Event 相关性图、不做 sharing/distribution/ACL。**

## 目标 / 非目标

**目标**
- 保留每源富证据，不静默丢字段。
- 用 IntelMQ `classification.type` 作复核主轴 + `verdict` 第二轴，取代 6 布尔。
- 单 IP 复核（多独立源同意 → 加权置信度）+ 时间衰减。
- STIX 2.1 导出忠实于证据（malware SDO + 聚合 Sighting + Identity + `x_*` 扩展）。
- **源无关引擎**：接新源零碰公共代码；支持离线 IP/CIDR、在线 API、域名/URL 三类源原型。
- 性能：内存可控、查询亚毫秒、启动不阻塞、在线源配额受控。

**非目标**
- 不做全量相关性图 / Event / 多租户。
- 不手搓 malware 家族归一（等第二个 malware 源再上 MISP Galaxy）。

## 数据模型变更

### 替换：`THREAT_BOOLS` → `classification.type` + `verdict`
6 个布尔换成 IntelMQ `classification.type` **完整受控词表**（44 值，IP 相关子集优先用），**不用窄子集**（窄子集接 AbuseIPDB/GreyNoise/Shodan 当场不够）。新源按需扩展，遵循 IntelMQ enum。

`verdict` 第二轴（泛化一位的 `is_whitelisted`）：`malicious | suspicious | benign | informational`。让 GreyNoise-benign / Shodan-exposed 不被当威胁投票。

| 源 | classification.type | verdict |
|---|---|---|
| threatfox | `c2-server` | malicious |
| otx | `c2-server`（或 pulse threat_type） | malicious |
| spamhaus/emerging/blocklist/ipsum/firehol | `blacklist` | malicious |
| ip2proxy VPN/PUB/SES/WEB | `proxy` | suspicious |
| ip2proxy TOR / tor_exits | `tor` | suspicious |
| x4bnet_vpn | `proxy` | suspicious |
| abuseipdb（规划） | `abuse-reports`（词表新增） | malicious/suspicious（按 score） |
| greynoise（规划） | `scanner` | malicious/benign（按 classification） |
| urlhaus（规划） | `malware-distribution` | malicious |
| shodan（规划） | `vulnerable-system`/`misconfiguration` | informational |

### `EvidenceObservation`（typed 核心 + 开放 `extra`，采纳 IntelMQ `extra` 模式）
```python
@dataclass
class EvidenceObservation:
    # ── typed 核心（合并/复核引擎只读这些）──
    source: str
    classification_type: str          # 完整 IntelMQ enum
    verdict: str = "malicious"        # malicious|suspicious|benign|informational
    reliability: float = 0.5
    first_seen: Optional[str] = None  # ISO-8601 +00:00，ordinal 跨源当排序
    confidence: Optional[int] = None  # 源自带置信度（threatfox conf / abuseipdb score）
    malware_name: Optional[str] = None  # 原始小写，不归一
    comment: Optional[str] = None
    reporter_count: Optional[int] = None  # 源内上报者数（abuseipdb numDistinctUsers）
    # ── 开放袋（引擎不透明，原样流向 STIX）──
    tags: list[str] = field(default_factory=list)   # GreyNoise tags / abuseipdb categories / shodan ports
    source_refs: dict[str, str] = field(default_factory=dict)  # 仅标量引用 {"sbl":"SBL256894","otx_pulse_id":...}
    extra: dict = field(default_factory=dict)       # 任意结构化（shodan vulns{}/greynoise metadata{}），STIX → x_<source>_<key>
```
**关键**：`tags`/`extra` 保留完整原生信号（type 只是投票投影）；新源带来的未知字段进 `extra`，**不丢、不需加 typed 字段**（解决 Shodan `vulns{}`、GreyNoise `metadata{}`、AbuseIPDB `usageType` 无槽位的问题）。

### `ClassificationAssessment`
```python
@dataclass
class ClassificationAssessment:
    type: str
    verdict: str
    detected: bool
    confidence: int            # 0-100，复核 + 衰减后
    algorithm: str
    sources: list[SourceAttribution]
    corroborated: bool         # ≥2 独立源同意同 type+verdict
    reporter_total: int        # 跨源 reporter_count 之和（abuseipdb 类）
```

### `LookupResult` 改
- 删 `threats: dict[str, ThreatAssessment]`（旧 6 布尔）。
- 加 `classifications: dict[str, ClassificationAssessment]`（key=type，值含 verdict）。
- 加 `is_whitelisted: bool` + `whitelist_notes: list[str]`（MISP Warninglist 软标记）。
- 保留 `country/asn/as_name/ip_range/is_isp` 标量合并。

### 三类源原型（base class）
1. **`IpListSource`/`CsvSource`**（离线 IP/CIDR，现有）：`query()` 返回证据袋。pytricia 折叠 CIDR → 大范围源（firehol_level1 611M IP / 3,841 网段）几乎免费。
2. **`OnlineEnricher`**（在线 API，AbuseIPDB/GreyNoise）：`enrich_batch(ips)` → **接入复核引擎**（投影成 `EvidenceObservation`，与离线源同路径）。不再走独立的标量合并。
3. **`DomainSource`**（域名/URL 源，URLhaus）：带**可插拔解析器 hook**（`resolver`），域名→IP；或维持独立的非-trie 域名索引，IP 命中时跨查。

### 源 cost/quota 描述符（在线源必需）
```python
class SourceCost:
    max_qps: Optional[int] = None
    daily_cap: Optional[int] = None      # abuseipdb 1000/day
    weekly_cap: Optional[int] = None     # greynoise 50/week
    interactive_only: bool = False       # greynoise：仅单 IP UI 查询，排除批量
```
批量分发前按 budget 跳过/限流；`interactive_only` 源在批量路径静默跳过。

## 合并/复核引擎（层 C，源无关）

**强制：删除 `_merge.py` 中央 `SOURCE_RELIABILITY`/`AUTHORITATIVE_SOURCES`，改读源对象的 `reliability`/`authoritative_for` 类属性**（源类现在**已声明**但被忽略）。否则"源无关"是空话。

仅对被查单 IP 计算（不建相关性图）：
1. 收集所有命中源的 `EvidenceObservation`（离线 `query()` + 在线 `enrich_batch()` 统一投影）。
2. 按 `classification_type` + `verdict` 分组。
3. 每 type：独立源 ≥2 → `corroborated=True`，confidence 按 `reliability` 加权推到 80-100（STIX Admiralty「Confirmed」=90）。`reporter_count` 累加为 `reporter_total`。
4. **decay 线性衰减**：`first_seen`（缺则 `stale_days` 推算），`≤90d` 不降、`90-365d` 线性降到 50%、`>365d` 降到 20%。
5. **Warninglist 软标记**：命中 → `is_whitelisted=True`，保留检测、附说明（MISP 原意）。

## STIX 2.1 导出（层 D，修订）

per-IP bundle：
1. `ipv4-addr` SCO。
2. 每参与源一个 `identity`（`identity_class="system"`，保留 `x_reliability`/`x_authoritative`）。
3. 一个 `indicator`（`pattern=[ipv4-addr:value='...']`，`indicator_types` 由 classification.type 映射，`confidence`）。
4. 每复核 malware 家族一个 `malware` SDO（`is_family=True`，`malware_types` 映得上才填）。
5. `Relationship(relationship_type="indicates", indicator→malware)`。
6. **一个聚合 `sighting`**：`sighting_of_ref=indicator.id`（**非** ipv4-addr SCO）、`where_sighted_refs=[全部同意源 identity]`、`count=N`、`first_seen`/`last_seen`、`summary=True`。
7. `EvidenceObservation.extra` → 扁平化为 `x_<source>_<key>` props（`allow_custom=True`，单一 `toplevel-property-extension`）；`tags` → `x_tags`。**零 per-source 导出代码**。

要点：`source_count`（非标）→ 用规范 `count`；confidence 复核≥2→80-100，clamp 0-100，不当可靠性代理。

## 性能（层 E）

1. **后台构建 + 503 门**：lifespan 里 `asyncio.create_task(asyncio.to_thread(load_db))`，`app.state.db_ready=False`，立即 `yield`；未就绪 `/api/*` 返 **HTTP 503**（非 502）。
2. **`freeze()`+pickle 冷启动**：pytricia `freeze()` 转只读可序列化；构建一次 pickle 落盘，后续启动秒级加载。
3. **合并重叠 trie**：ipinfo_lite/iptoasn/cn_isp 合成一个 trie + 合并 value，省 ~30% RAM（3.5-4.5GB 地板主优化）。
4. **修批量阻塞 event loop**（既有 bug）：`main.py:198` 的 `[lookup(ip) for ip in ips]`（最多 10 万 IP→10-50s）改 `asyncio.to_thread` 或分块 `await asyncio.sleep(0)`。
5. **在线源批量成本**：`OnlineEnricher.enrich_batch` 按 `SourceCost` 配额 gate（daily_cap/weekly_cap/max_qps/interactive_only），批量路径跳过 `interactive_only`。
6. RAM 地板 3.5-4.5GB（笔记本 OK，4GB Windows VM 紧张）。

## 新增源清单（Adding a source — 接源模板）

接一个新源（**不碰 `_merge.py`/`_types.py`/`_stix_export.py`**）：
```python
class NewSource(IpListSource):                # 或 CsvSource / OnlineEnricher / DomainSource
    name = "newsrc"
    classification_type = "c2-server"         # 必填：IntelMQ enum 值（新值加进词表）
    verdict = "malicious"                      # 必填：第二轴
    reliability = 0.8                          # 必填：原 SOURCE_RELIABILITY，现读这里
    authoritative_for = []                     # 可选
    # cost = SourceCost(daily_cap=1000)        # 在线源必填
    def query(self, ip):                        # 返回 EvidenceObservation 载荷（最小化只给 type/verdict）
        ... return {"malware_name":..., "first_seen":..., "tags":[...], "extra":{...}}
```
新源若是**全新** classification.type：加一行 `stix_export` 的 type→indicator_type 映射。tokenized 源：加一个 `_instantiate_source` 分支。其余零改动。

## 分期实施（每期独立可验证，TDD）

1. **数据模型 + 投影**：`EvidenceObservation`（typed 核心 + extra/tags/source_refs/reporter_count）；`project()` 纯函数；威胁源 `query()` 发证据袋；ip2proxy 留 proxy_type。
2. **classification.type + verdict 替换布尔**：源→type/verdict 映射；`LookupResult.classifications`；`lookup()` 重写；删 `THREAT_BOOLS`。
3. **删中央字典，读源属性**：`SOURCE_RELIABILITY`/`AUTHORITATIVE_SOURCES` 删除，改读 `source.reliability`/`authoritative_for`。
4. **复核引擎 + decay**：单 IP 按 type+verdict 分组 + 独立源计数 + `reporter_total` + 时间衰减。
5. **Warninglist 软标记**：119 良性列表 → pytricia；接入设 `is_whitelisted`。
6. **STIX 导出重写**：聚合 Sighting + malware SDO + Relationship + identity + `extra→x_*`。
7. **在线源进复核 + 配额**：`OnlineEnricher.enrich_batch` → `EvidenceObservation` 投影进复核；`SourceCost` gate；`interactive_only`。
8. **DomainSource + 解析器 hook**：URLhaus 类源，可插拔 resolver 或独立域名索引。
9. **性能改造**：后台构建 + pickle + 503 门 + 合并 trie + 修批量阻塞。
10. **前端/API 适配**：badge 从布尔改 classification.type + verdict；STIX 按钮消费新 bundle。

## 验证（端到端）

- 单元：`project()` 纯函数、复核计数、decay 曲线、STIX 合规（`stix2.parse`）、`extra→x_*` 往返。
- 集成：查 `162.243.103.246` → `classifications={c2-server: corroborated(threatfox+otx), blacklist: ...}`，置信度 80-100。
- 在线源：AbuseIPDB/GreyNoise 投影进复核；批量路径跳过 `interactive_only` 的 GreyNoise；daily_cap 触发限流。
- 域名源：URLhaus 域名行经 resolver 入索引或独立域名索引。
- 性能：pickle 冷启动 <2s；单 IP lookup <1ms；10k IP 批量不阻塞 event loop。
- 真实：所有威胁源数据加载后，恶意 IP 检测带源级证据 + STIX 含 malware SDO + 聚合 Sighting + `x_*` 扩展。

## 参考证据（agent 评审 + 规范）
- MISP 核心/Sighting/Warninglist/Decay（Agent A）
- IntelMQ Harmonization spec + classification.type **完整 44 值 enum** + `extra` JSONDict 模式（Agent B/C）
- STIX 2.1 OS §Sighting/Malware/Common Properties + App.A 置信尺度 + `toplevel-property-extension`（Agent C）
- pytricia README（freeze/pickle/CIDR 折叠/无 values）+ FastAPI lifespan/503（Agent D）
- 源无关解耦（IntelMQ 无中央 feed-reliability 表）/ 接源模板（Agent 1）
- 在线/域名/上报计数源缺口（Agent 4）
