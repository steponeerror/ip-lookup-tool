# 源开发契约重构设计 — 开放证据记录 + 无损失管线 + map-first 适配模板

**日期**: 2026-07-21（v2，纳入多角度审核修订）
**范围**: `backend/ipdb/` 源系统 + `.claude/skills/add-intel-source/`

> v2 变更要点：B1（MMDB typed/dict 缺口，重写不变式）、B2（STIX 走 extension-definition 而非 x_）、B3（复杂源改为 download/harvest/normalize 三钩子）、M4（补第 6 个丢字段点）、M1/M2/M3/M7/M8 落入；M5 namespace 化暂缓、M6 schema 版本号 YAGNI。

---

## 1. 问题与目标

加一个新威胁情报源的成本过高、且容易出错。根因不是缺少模板，而是**源开发契约本身没有被当作一等公民对待**：开放证据模型其实已存在（`EvidenceObservation`），但全管线没有遵守它——源头用自由 dict 凑、下游用硬编码白名单挑字段。

**四条硬约束**（用户确认）：

1. **加源快** — 低 boilerplate；简单源声明式配置，复杂源只写 parse 逻辑。
2. **不出错** — 6 条约定从 prose 变成加载期/测试期可执行校验。
3. **良好字段映射** — 能映射到已知槽位的字段就映射，不让 `extra` 沦为垃圾场。
4. **无字段损失** — 对**每一个新源的适配**都成立：源 emit 进记录的字段必须出现在最终 API payload 里。

**一条根本约束**：没有任何闭合模型能包住所有源。因此记录必须是**开放的**（固定小内核 + 可扩展规范槽位 + 开放 extra 袋），而"良好映射 + 无损失"必须对每次新源适配都成立——**适配机制本身是设计的一等公民**。

---

## 2. 现状 — 字段损失地图（已对照代码核实）

当前管线有 **6 个丢字段点**，"无字段损失"按设计就是违反的：

| # | 位置 | 现状 | 后果 |
|---|---|---|---|
| 1 | `_merge.py:25` `to_observation` | 注释原文 "Unknown keys are ignored." | 源 dict 里不在固定字段表、又没手动塞进 `extra` 的 key **静默丢弃** |
| 2 | `_merge.py:331-343` `_assess_classification.details` | 只浮现 `{source, reliability, malware_name, native_confidence, first_seen, native_type}` | `comment`/`tags`/`source_refs`/`reporter_count`/`extra`（除 native_type）**全部丢** |
| 3 | `_registry.py:340` `lookup()` | 标量硬编码 `("country_code","asn","as_name","ip_range","is_isp")` | 别的标量（port/protocol/...）直接丢 |
| 4 | `_registry.py:118` `_ASSET_KEYS` | 资产硬编码 `("is_proxy","is_hosting","is_tor","is_vpn","carrier")` | 别的资产字段丢 |
| 5 | `_stix_export.py:99-128` | 只导出 classification 级字段 + sources | `malware_names`/`details`/`extra`/`verdict_conflict` 完全不导出；`_types.py` "extra→STIX x_*" 注释是**未实现愿景** |
| 6 | `_base.py:206-218` `CsvSource.load` dedup | dedup key 仅 `(classification_type, verdict, malware_name, extra.native_type)` | 两行 4-tuple 相同但 `comment`/`confidence`/`first_seen` 不同 → **第二行静默丢弃**（ThreatFox 真实损失） |

**附带偏差**：skill 的 `references/source-archetypes.md` 第 3 节"自定义源骨架"已过时——还在写 `import pytricia` / `pytricia.PyTricia(32)`，但它点名的 `iptoasn.py`/`cn_isp.py`/`ipinfo_lite.py` 实际早已改用 MMDB（pytricia 已从 `backend/ipdb/` 彻底移除）。

**关键发现**：第 3、4 个白名单 + `to_observation` 的固定字段表，**合起来其实已经隐式定义了"规范字段集"**——只是散落三处、无类型、不可扩展。重构 = 把这套隐式白名单**提升为一个显式、类型化、可扩展的 schema**，并按 schema 路由。

---

## 3. 设计

### §A 开放证据记录：三层 + map-first（写时 typed / 读时 dict）

`EvidenceObservation`（`_types.py:60`）是**源端写作契约**，分三层：

| 层 | 字段（初始集合，从现有 15 源 emit 的真实 key 归纳） | 治理 |
|---|---|---|
| **融合内核**（固定，~6） | `classification_type`, `verdict`, `reliability`, `malware_name`, `first_seen`, `confidence`（`comment`/`tags` 紧邻，见规范槽位） | corroboration 推理必需，极少变动 |
| **规范槽位**（可扩展，约 15） | 标量：`country_code`, `asn`, `as_name`, `ip_range`, `isp`；威胁富信息：`native_type`, `comment`, `tags`, `reporter_count`, `last_seen`；资产：`is_proxy`, `is_hosting`, `is_tor`, `is_vpn`, `carrier` | 跨源反复出现；当第 2 个源需要某新字段时，提升为规范槽位（IntelMQ harmonization 治理） |
| **extra 袋**（开放） | 真正异质的长尾（中国运营商细分 cernet/cmcc/...、MISP `to_ids`/`threat_level`、未来 port/protocol/sample_hash） | 无损兜底 |

**map-first 默认**：源 emit 一个字段时，引擎**先查它能否映射到内核或某规范槽位**；能→映射；确实不能→才落 `extra`。`extra` 只剩真正的长尾，不再当垃圾场。

**`native_type` 特殊地位**：7 个源共用，是最高频字段——它是"原始未归一化类别"的唯一存活处，规范槽位里必须有它，fusion 与前端都读它。

**写时 typed / 读时 dict（B1 修订）**：源在**写入边界**直接构造类型化 `Evidence`，但 Evidence **不会原样穿过 MMDB 往返**——`load()` 把它序列化成 dict 写进 MMDB（`_base.py:113`），`query()` 读回的是 dict（`_base.py:125`、`iptoasn.py:107`、`cn_isp.py:104`）。因此"消除未知键"只在写路径成立；**查询路径的丢字段点（#3/#4）靠 §B 的 schema 路由解决，不靠 typed Evidence 穿透**。不在热路径加 dict→Evidence 重建层（会回退上次 MMDB 降 RSS 的成果）。

### §B 无损失管线不变式（B1 重写）

**不变式（修订）**：源在写入边界 emit 进 `Evidence` 的字段，经 MMDB dict 存储 + 查询期 schema 路由后，必须出现在最终 API payload 里。**管线保的是 schema + 袋子，不是 typed 对象的逐跳穿透。** 堵 6 个丢字段点：

| # | 改法 |
|---|---|
| 1 | 写入边界构造 `Evidence`（消除"未知键"于源头）；MMDB 存其 dict 形态 |
| 2 | `details` 浮现**完整记录**：`comment`/`tags`/`source_refs`/`reporter_count`/`extra` 全集（不只 native_type——它们是 EvidenceObservation 一级字段，不在 extra 里） |
| 3 | `lookup()` 按 schema 路由：规范标量进 fusion，其余随记录携带（取代硬编码 5 元组） |
| 4 | `_ASSET_KEYS` 改为 schema 驱动（规范资产槽位集合，取代硬编码 5 元组） |
| 5 | STIX 把 `extra`/`details`/`malware_names`/`verdict_conflict` 走 **`extension-definition` + `toplevel-property-extension`** 袋（`_stix_export.py:112-126` 已有该机制），**不走 ad-hoc `x_*`**；仅承诺**管线内无损**，不承诺 STIX 互操作无损 |
| 6 | `CsvSource.load` dedup key 扩成**完整 evidence 哈希**（含 comment/confidence/first_seen），或两行 4-tuple 相同时合并而非丢弃 |

因管线保的是**袋子 + schema 路由**而非枚举白名单，新源加新字段**自动无损**。

### §C 适配契约（一等公民）— skill 产出映射，模板编码，validator 校验

**三段式契约**：

**① skill 产出映射** — `add-intel-source` 的 Phase 1 加一步**逐字段路由判定**：对 feed 的每个字段，判定属于「融合内核 / 某规范槽位 / extra」，记下决策与理由。人工+agent 判断，per-feed。

**② 模板编码映射** — `SourceSpec`（**Pydantic 模型**，对标 OpenCTI 的 config 契约）带 `field_map` 段。`field_map` 只覆盖**单列→单槽位**映射，**列名优先、列索引降级**（对 feed schema 变更更鲁棒）。引擎按它构造 `Evidence`。示意（非最终 API）：

```python
class ThreatfoxSpec(SourceSpec):
    name = "threatfox"; url = "..."; format = "csv_zip"
    stale_days = 1; reliability = 0.85
    field_map = {
        "ip": "_ip",
        "threat_type": ("classification_type", "THREATFOX_MAP"),  # 归一化
        "malware": "malware_name",
        "confidence_pct": "confidence",
        # 含过滤/条件/1→多/嵌套的源不在此声明，改写 Source 子类
    }
```

**③ validator 校验（M1 修订）** — 只做**可机械执行**的：`classification_type` ∈ 词表或 `other`；内核字段类型正确；`field_map` 引用的规范槽位存在；命名碰撞告警。**"能映射就映射"是 skill 的语义判断，validator 不试图强制**（"port 该不该进 extra 槽"是循环论证，不可自动判定）。

**写作形态（决策 = A，M2 修订为单一基类 + 配置载体）**：**一个 `Source` 基类**，`SourceSpec`（Pydantic）作其配置载体。简单源 = 纯 `SourceSpec` 配置；含过滤/条件/1→多/嵌套的源（threatfox、ip2proxy、misp 等**灰区**）与复杂源（otx、iptoasn、cn_isp）= `Source` 子类，按需重写以下钩子（基类给默认实现，共享 health/MMDB/auth/原子写/重试）：

- `download()` — 默认简单 GET；otx 需重写（cursor 持久化 + modified_since 增量 + 时间预算 + 后台线程 + 退避，`otx.py:100-190`）；iptoasn 需重写（gzip + 原子 tmp 改名，`iptoasn.py:30-56`）；cn_isp 需重写（10 文件拉取，`cn_isp.py:37-59`）。
- `harvest() -> Iterator[(cidr, Evidence)]` — **解析/结构变换钩子，返回 (cidr, Evidence) 序对**，使 range→CIDR 展开（iptoasn `:87-97` 一条区间→多条 CIDR）与 per-row 发射都能表达。
- `normalize()` — 可选，per-source 分类/字段归一化（skill 驱动）。

> 灰区源数量比初稿的"~12 简单源"少：threatfox（ZIP + 行过滤 + 容错）、ip2proxy（1 个 proxy_type 驱动 is_proxy/is_hosting/is_tor + 条件 drop）、misp（嵌套字段 + Tag 扫描 + 组合判定 verdict）都含 field_map 表达不了的逻辑，必须走 `Source` 子类。

### §D "不出错" — 可执行校验

- **加载期 `validate()`**：registry 断言每个源 emit 的 `Evidence` 合规（见 §C ③）。
- **约定 pytest**：native_type 保字、未映射→`other`、staleness 看 mtime（非 `_loaded_at`）、稳定 verdict、per-row classification、读自己的 env——从 skill prose 变成强制测试。
- **无损往返测试**：给一个源 emit 带新奇 `extra.port`，断言它一路到 API `details[].extra.port`；断言规范槽位字段进 fusion 而非 extra；断言 CsvSource dedup 不再丢 comment/confidence。

---

## 4. 参考实现（"对齐最佳实践"，外部对标核实）

| 项目 | 对应本设计 |
|---|---|
| **IntelMQ** | harmonized event（固定字段 + `extra`）= 三层记录；**4 类 bot**（Collector/Parser/Expert/**Output**，导出对应 Output）；**Shadowserver parser** 的 `required/optional/constant_fields` + `(intelmqkey, shadowkey, conversion_fn)` 元组 + "optional 解析失败→自动落 extra" = **map-first 的工业先例**（强引用，非泛泛对标）；其 `extra` 文档明确"不用于扩展 harmonization"，**支持 map-first**；`modify` expert bot（声明式 regex 改写）= 映射可观测性可借鉴 |
| **OpenCTI** | connector 用 **Pydantic config 模型**作契约、manifest 自动生成 = 本设计 `SourceSpec`（Pydantic）；**5 种 connector 类型**（EXTERNAL_IMPORT/INTERNAL_ENRICHMENT/INTERNAL_IMPORT_FILE/INTERNAL_EXPORT_FILE/STREAM）= 提示本设计单一 `Source` 基类长期可能拆"周期拉取 vs 被动查询" |
| **STIX 2.1** | `extension-definition` + `toplevel-property-extension` 是自定义字段首选机制；`x_` 自定义属性仍合法但批量 extra 不互操作 → §B #5 走 extension 袋 |
| **MISP** | 修正：MISP 是**结构化 Object templates + Galaxy**，非无结构袋子——佐证"extra 应有治理"而非"开放=无结构" |

共同点：**少量固定基类 + 声明式配置 + 一套归一化内部事件模型 + 开放扩展袋**。没有成熟项目用闭合模型——印证用户"没有闭合模型能包住所有源"。

---

## 5. 迁移与范围（M7/M8 修订：分阶段，去掉"机械"措辞）

**工作项**（非"包一层构造器"——offline 牵动序列化 + 查询路由）：
- 定义类型化 `Evidence` + 写入边界构造；MMDB 序列化契约（Evidence→dict）。
- 查询期 schema 路由（取代 `lookup()`/`_ASSET_KEYS` 硬编码白名单）。
- 修 `CsvSource` dedup（#6）、`details` 全字段（#2）、STIX extension 袋（#5）。
- 新增 `Source` 基类 + Pydantic `SourceSpec`。
- 迁移 15 源（offline 12 + online/enricher 分开估算）。
- 修 skill 过时骨架（pytricia→MMDB）+ 更新 SKILL.md 到新契约。
- 加 `validate()` + 约定 pytest + 无损往返测试。

**分 ≥4 阶段**（writing-plans 强制拆分）：
1. 类型化 `Evidence` + 查询 schema 路由 + dedup 修复，单源 PoC（spamhaus）。
2. 批量迁简单源 + validator 上线 + 约定 pytest。
3. `Source` 基类 + 灰区源（threatfox/ip2proxy/misp）。
4. 复杂源（otx/iptoasn/cn_isp）+ skill 更新 + 无损往返测试 + STIX extension 接线。

**明确不在范围**：
- 融合算法本身（corroboration 不动；PCR6 死代码清理单独）。
- enricher 接线（`IPApiEnricher`/`IPApiIsEnricher` 目前未接入 `lookup()`，单独延期工作）。
- 前端泛化渲染新字段（数据先到位；前端按需跟进，非阻塞）。
- 字段 namespace 化（M5，暂缓——单工具内部 schema，全量改名侵入大、收益边际；仅 `extra.*` 内部加轻量前缀）。
- schema 版本号（M6，YAGNI——直到出现第二个需要版本信号的消费方）。

---

## 6. 决策记录

- **写作形态 = A**：单一 `Source` 基类 + Pydantic `SourceSpec` 配置载体（M2）。
- **B1 不变式重写**：写时 typed / 读时 dict / 查询按 schema 路由；不加重建层（保 RSS）。
- **B2 STIX**：extra 走 `extension-definition` 袋，不走 ad-hoc `x_*`（x_ 仍合法，非被禁）。
- **B3 复杂源钩子**：`download()`/`harvest()->(cidr,Evidence)`/`normalize()` 三钩子；harvest 返回序对以支持 range→CIDR。
- **M4 第 6 丢字段点**：CsvSource dedup 进 §2 地图与 §B 修法。
- **M1 validator**：语法校验 + 碰撞告警；语义映射归 skill，不"强制"。
- **M3 field_map**：仅单列→单槽；灰区源走 `Source` 子类。
- **规范槽位初始集合 = 约 15 字段**（§A 表），可扩展。
- **map-first 默认**：能映射就映射，extra 仅兜底。
- **M5 namespace / M6 版本号**：暂缓 / YAGNI（见 §5 非目标）。

---

## 7. 待办与开放问题

- `field_map` 列名映射的精确语法 + 列索引降级规则，留给实现计划阶段。
- 规范槽位提升治理：倾向"第 2 个源需要时提升 + 加注释"（YAGNI，同 `_classification.py` 现有治理）。
- 迁移顺序按 §5 四阶段。
- M5（namespace）/ M6（版本号）作为后续独立提案，不在本次重构内。

---

**下一步**：本 spec 经用户审阅后，转 `writing-plans` skill 产出 ≥4 阶段实现计划。
