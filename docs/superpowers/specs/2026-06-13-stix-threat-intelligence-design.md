# STIX 2.1 威胁情报聚合系统设计规格

> 日期: 2026-06-13
> 状态: 设计完成，待实施
> 分支: feat/source-registry

---

## 1. 概述

### 1.1 目标

将 IP Radar 的数据管道从自定义格式迁移到 STIX 2.1 (Structured Threat Information Expression) 标准，实现：

1. **统一情报格式** — 所有数据源输出 STIX 2.1 对象，merge 引擎统一处理
2. **聚合更多威胁情报源** — 从 8 个扩展到 16+ 个数据源
3. **多源置信度聚合** — 基于开源算法的冲突解决和置信度计算

### 1.2 实施策略

分层渐进，三阶段实施：

```
Phase 1: STIX 基础设施
  ├── python-stix2 集成
  ├── STIX 对象工厂和 Bundle 构建
  ├── _export.py (STIX → 扁平化 JSON)
  └── 现有 8 个源适配为 STIX 输出

Phase 2: 新增数据源
  ├── ThreatFox, OTX, Blocklist.de, Spamhaus
  ├── Cybercrime Tracker, Shadowserver
  ├── CIRCL OSINT, MISP OSINT Feeds
  └── MISP Warning Lists (误报过滤)

Phase 3: 置信度算法
  ├── 源可靠性权重体系
  ├── 级联权威加权决策树 (Layer 1)
  ├── PCR6 证据融合 (Layer 2)
  ├── 指数衰减模型
  └── 前端动态字段选择
```

### 1.3 核心决策记录

| 决策项 | 选择 | 理由 |
|--------|------|------|
| STIX 定位 | 作为内部格式 | 统一管道，消除自定义合并逻辑 |
| 架构方案 | 全 STIX (所有源输出 STIX 对象) | merge 引擎只处理 STIX，无需格式判断 |
| API 返回格式 | 内部 STIX + API 扁平化 JSON | 前端不直接消费 STIX |
| STIX 输出粒度 | 综合 Indicator + Extensions | 保留各威胁独立置信度 |
| 前端字段选择 | 全部可选 + 源明细展开 | 灵活的 API 参数控制 |
| 置信度范围 | 0-100 整数 | STIX 2.1 规范要求 |
| 冲突解决 | 两层架构 (级联决策树 + PCR6) | 快速路径 + 高冲突升级 |

---

## 2. STIX 2.1 内部数据模型

### 2.1 依赖

```
stix2>=3.0.1          # STIX 2.1 对象构建 (必选)
OTXv2                 # AlienVault OTX SDK (可选, Phase 2)
shadowserver-api      # Shadowserver API (可选, Phase 2)
misp-stix             # MISP → STIX 转换 (可选, Phase 2)
pytricia              # 已有, CIDR 前缀树
```

### 2.2 STIX 对象类型

#### 2.2.1 SCO: ipv4-addr

```python
import stix2

ip = stix2.IPv4Address(value="1.2.3.4")
# ID 自动生成确定性 UUIDv5
# 命名空间: 00abedb4-aa42-466c-9c01-fed23315a9b7
# 同 IP 永远同 ID → 跨源自动去重
```

可选嵌入式关系: `belongs_to_refs` → autonomous-system (无需独立 SRO)。

#### 2.2.2 SCO: autonomous-system

```python
as_obj = stix2.AutonomousSystem(
    number=13335,
    name="Cloudflare, Inc.",
    rir="ARIN"  # 可选, 区域互联网注册机构
)
```

ID 基于 `number` 属性自动生成确定性 UUIDv5。

#### 2.2.3 SDO: location

```python
loc = stix2.Location(country="US")  # ISO 3166-1 alpha-2
```

Location 是 SDO，ID 为随机 UUIDv4（非确定性）。
规范要求至少提供 `region` 或 `country` 或 (`latitude` + `longitude`) 之一。

#### 2.2.4 SDO: indicator (综合威胁指标)

```python
indicator = stix2.Indicator(
    name="IP 1.2.3.4 - Threat Assessment",
    pattern="[ipv4-addr:value = '1.2.3.4']",
    pattern_type="stix",
    indicator_types=["anomalous-activity"],
    confidence=75,  # 全局置信度 (0-100 整数)
    valid_from="2026-06-13T00:00:00Z",  # 必填
    # Per-threat 置信度放在 extension 中
    extensions={
        THREAT_EXT_ID: {
            "extension_type": "property-extension",
            "threat_scores": {
                "proxy":     {"detected": True,  "confidence": 85},
                "tor":       {"detected": True,  "confidence": 95},
                "vpn":       {"detected": False, "confidence": 72},
                "malicious": {"detected": True,  "confidence": 60},
                "hosting":   {"detected": True,  "confidence": 88},
                "mobile":    {"detected": False, "confidence": 90},
            }
        }
    }
)
```

**必填字段**: `pattern`, `pattern_type`, `valid_from`。
`confidence` 是全局属性（0-100 整数），per-threat 细分置信度通过 extension 存储。

#### 2.2.5 SDO: identity (数据源身份)

```python
identity = stix2.Identity(
    name="IPinfo Lite",
    identity_class="system",  # 数据源用 "system" (非 "organization")
    custom_properties={
        "x_reliability": 0.95,   # 自定义属性必须 x_ 前缀
        "x_source_url": "https://ipinfo.io/",
    }
)
```

**注意**: `identity_class` 用 `"system"` 而非 `"organization"`，因为数据源是自动化系统。
自定义属性必须以 `x_` 前缀命名。

#### 2.2.6 SRO: relationship

```python
# belongs-to: ipv4-addr → autonomous-system (合规)
rel_asn = stix2.Relationship(ipv4_addr, "belongs-to", as_obj)

# related-to: ipv4-addr → location (规范中 located-at 不支持 ipv4-addr)
rel_loc = stix2.Relationship(ipv4_addr, "related-to", location)

# 或者: 使用 belongs_to_refs 嵌入式关系 (无需独立 SRO)
ip = stix2.IPv4Address(value="1.2.3.4", belongs_to_refs=[as_obj.id])
```

**注意**: `ipv4-addr → located-at → location` 不在 STIX 2.1 规范的关系定义表中。
使用 `related-to` 替代（规范的通用关系类型）。

#### 2.2.7 SMO: extension-definition

```python
THREAT_EXT_ID = "extension-definition--<project-deterministic-uuid>"

ext_def = stix2.ExtensionDefinition(
    id=THREAT_EXT_ID,
    name="IP Radar Threat Confidence",
    description="Per-threat-type confidence scores for IP indicators",
    created_by_ref=identity.id,
    schema="https://ip-radar.local/schemas/threat-confidence.json",
    version="1.0.0",
    extension_types=["property-extension"],
)
```

**必须**: extension-definition SDO 包含在每个使用了该扩展的 Bundle 中一起传输。
不需要中心注册，但消费者通过 extension-definition 的 ID 识别扩展属性含义。

### 2.3 STIX Bundle 结构

```python
bundle = stix2.Bundle(
    ext_def,        # extension-definition (必须包含)
    ipv4_addr,      # ipv4-addr SCO
    as_obj,         # autonomous-system SCO
    loc,            # location SDO
    indicator,      # indicator SDO (含 threat_scores extension)
    identity,       # identity SDO (数据源)
    rel_asn,        # relationship: belongs-to
    rel_loc,        # relationship: related-to
)
json_str = bundle.serialize(pretty=True)
```

### 2.4 UUIDv5 去重机制

| 对象类型 | ID 生成方式 | 去重 Key |
|----------|------------|----------|
| ipv4-addr | UUIDv5 (确定性) | `value` 属性 |
| autonomous-system | UUIDv5 (确定性) | `number` 属性 |
| location | UUIDv4 (随机) | 不去重 (每次查询新建) |
| indicator | UUIDv4 (随机) | 不去重 (每次查询新建) |
| identity | UUIDv4 (随机) | 初始化时创建一次，缓存复用 |
| relationship | UUIDv4 (随机) | 不去重 |

同一 IP 地址无论由哪个源生成，ipv4-addr 的 ID 始终相同 → Bundle 自动去重。

### 2.5 indicator_types 映射

```python
THREAT_TO_INDICATOR_TYPE = {
    "proxy":     "anomalous-activity",    # 代理/VPN
    "tor":       "anomalous-activity",    # Tor 出口
    "vpn":       "anomalous-activity",    # VPN 出口
    "malicious": "malicious-activity",    # 恶意 IP
    "hosting":   "anomalous-activity",    # 数据中心/托管
    "mobile":    "benign",                # 移动网络 (非恶意)
}
```

所有值均在 STIX 2.1 `indicator-type-ov` 开放词汇中。

---

## 3. 数据源适配器

### 3.1 现有数据源 (8 个)

| # | 源名称 | 格式 | 输出 STIX 对象 | 权威领域 |
|---|--------|------|---------------|---------|
| 1 | IPinfo Lite | MMDB | ipv4-addr, autonomous-system, location, indicator | hosting, mobile, country, ASN |
| 2 | IPtoASN | TSV | autonomous-system, location | ASN, AS name |
| 3 | Chinese ISP | 自定义 | ipv4-addr, indicator (x-chinese-isp extension) | 中国 ISP |
| 4 | IP2Proxy | PX8 | ipv4-addr, indicator | proxy, vpn (权威) |
| 5 | IPsum | CSV | ipv4-addr, indicator | malicious |
| 6 | Firehol Blocklist | IPSet | ipv4-addr, indicator | malicious |
| 7 | Tor Exit Nodes | 文本列表 | ipv4-addr, indicator | tor (权威) |
| 8 | X4BNet VPN | 文本列表 | ipv4-addr, indicator | vpn (权威) |

### 3.2 新增数据源 (9 个)

| # | 源名称 | 格式 | 可靠性 | 解析方式 | STIX 对象 |
|---|--------|------|--------|---------|----------|
| 9 | Abuse.ch ThreatFox | JSON API / CSV | 0.85 | requests + JSON POST | ipv4-addr, indicator, malware |
| 10 | AlienVault OTX | REST API | 0.75 | OTXv2 SDK (`pip install OTXv2`) | ipv4-addr, indicator, malware, report |
| 11 | Blocklist.de | IP 文本列表 | 0.65 | urllib 预下载 → pytricia | ipv4-addr, indicator |
| 12 | Spamhaus DROP | CIDR 文本列表 | 0.90 | urllib 预下载 → pytricia | ipv4-addr, indicator |
| 13 | Cybercrime Tracker | CSV | 0.75 | urllib 预下载 → pytricia | ipv4-addr, indicator, malware |
| 14 | Shadowserver | REST API | 0.90 | shadowserver-api (`pip install shadowserver-api`) | ipv4-addr, indicator, malware, report |
| 15 | CIRCL OSINT Feed | JSON 目录 | — | requests + misp-stix 转换 | 全部 SCO/SDO 类型 |
| 16 | MISP OSINT Feeds | JSON (51 feed) | — | pymisp + misp-stix 转换 | 全部 SCO/SDO 类型 |
| 17 | MISP Warning Lists | JSON (119 列表) | — | urllib 下载 → pytricia | 不产生 STIX 对象 (过滤器) |

### 3.3 数据源字段映射

#### IP2Proxy proxy_type → indicator_types + confidence

```python
PROXY_TYPE_TO_INDICATOR = {
    "VPN": {"indicator_types": ["anomalous-activity"], "confidence": 85},
    "PUB": {"indicator_types": ["anomalous-activity"], "confidence": 80},
    "TOR": {"indicator_types": ["anomalous-activity"], "confidence": 95},
    "WEB": {"indicator_types": ["anomalous-activity"], "confidence": 70},
    "DCH": {"indicator_types": ["benign"],              "confidence": 60},
    "SES": {"indicator_types": ["benign"],              "confidence": 90},
}
```

#### IPsum 出现次数 → confidence

```python
def ipsum_confidence(appearances: int, min_count: int = 3) -> int:
    if appearances < min_count:
        return 0
    return min(95, 30 + (appearances - min_count) * 5)
    # 3 次 → 40, 5 次 → 55, 10+ 次 → 80+
```

#### Firehol blocklist level → severity + confidence

```python
FIREHOL_LEVEL_MAPPING = {
    "firehol_level1": {"indicator_types": ["malicious-activity"], "confidence": 90},
    "firehol_level2": {"indicator_types": ["suspicious-activity"], "confidence": 70},
}
```

#### ThreatFox threat_type → indicator_types

```python
THREATFOX_TYPE_MAP = {
    "botnet_cc":       "malicious-activity",
    "payload_delivery": "malicious-activity",
    "cc_skimming":     "malicious-activity",
    "c2":              "malicious-activity",
}
# ThreatFox 自带 confidence_level (0-100)，直接使用
```

### 3.4 权威源映射表

```python
AUTHORITATIVE_SOURCES = {
    "is_proxy":     ["ip2proxy"],
    "is_tor":       ["tor_exits"],
    "is_vpn":       ["x4bnet_vpn"],
    "is_malicious": ["threatfox", "shadowserver"],
    "is_hosting":   ["ipinfo_lite"],
    "is_mobile":    ["ipinfo_lite"],
    "country":      ["ipinfo_lite"],
    "asn":          ["iptoasn"],
    "as_name":      ["cn_isp"],       # 中国 IP 时
}
```

### 3.5 MISP Warning Lists 过滤

MISP Warning Lists 提供 119 个已知良性 IP 列表（CDN、公共 DNS、云服务等），
作为**误报过滤器**在 STIX 构建之前执行。

```
查询所有源 → MISP Warning Lists 过滤 → 构建 STIX Bundle
                  ↑
            良性 IP → 清除恶意 indicator,
                      indicator_types 改为 ["benign"],
                      confidence 设为 0
```

### 3.6 查询架构

```
IP 输入
  │
  ├── 1. 本地源查询 (全部 pytricia, < 1ms)
  │     8 现有 + ThreatFox CSV + Blocklist.de + Spamhaus
  │     + Cybercrime Tracker + CIRCL/MISP 缓存
  │
  ├── 2. 在线源并行查询 (asyncio, ≈ 3s)
  │     ThreatFox API, OTX API, Shadowserver API
  │
  ├── 3. MISP Warning Lists 过滤
  │
  ├── 4. 构建 STIX Bundle
  │     SCO → SDO → SRO → Bundle
  │
  └── 5. API 扁平化输出
        Bundle → 字段筛选 → JSON
```

---

## 4. 置信度聚合算法

### 4.1 源可靠性权重

```python
SOURCE_RELIABILITY = {
    # 现有源
    "ipinfo_lite":   0.95,
    "iptoasn":       0.90,
    "cn_isp":        0.85,
    "ip2proxy":      0.80,
    "tor_exits":     0.95,
    "x4bnet_vpn":    0.70,
    "ipsum":         0.55,
    "firehol":       0.50,
    # 新增源
    "threatfox":     0.85,
    "otx":           0.75,
    "blocklist_de":  0.65,
    "spamhaus":      0.90,
    "cybercrime":    0.75,
    "shadowserver":  0.90,
}
```

### 4.2 两层冲突解决架构

#### Layer 1: 级联权威加权决策树 (快速路径)

```
Stage 1: 权威源否决
  ├── 该领域有权威源吗？
  ├── 权威源报告 True → True, confidence = 权威源 confidence
  └── 权威源报告 False → 继续到 Stage 2

Stage 2: 加权投票
  ├── 参与源 reliability 加权
  ├── Σ(reliability × vote) / Σ(reliability) → 加权分数
  └── 分数 > 阈值 → True, 否则 → False

Stage 3: 非对称阈值
  ├── True 触发阈值: 35% (容易标记)
  └── False 确认阈值: 65% (需要强共识)

Stage 4: 置信度计算
  ├── True: confidence = min(100, Σ(true_reliability) / Σ(all_reliability) × 100)
  ├── False: confidence = min(100, Σ(false_reliability) / Σ(all_reliability) × 100)
  └── 覆盖率惩罚: 实际参与源数 / 期望源数 < 50% → confidence × 0.7

Stage 5: 冲突升级检查
  ├── True/False 投票差距 < 20% → 升级到 Layer 2 (PCR6)
  └── 差距 >= 20% → 使用 Layer 1 结果
```

#### Layer 2: PCR6 证据融合 (高冲突升级)

当投票差距 < 20% 时自动升级，使用 `evidencelib` 库实现 PCR6 (Proportional Conflict Redistribution Rule 6)。

```python
# 证据融合伪代码
# 每个 src 提供一个 Basic Belief Assignment (BBA)
# BBA = {True: reliability, False: (1-reliability), Uncertain: 剩余}

from evidencelib import Evidence, combine

def pcr6_fuse(source_votes: dict[str, tuple[bool, float]]) -> tuple[bool, int]:
    bbas = []
    for src, (vote, reliability) in source_votes.items():
        bba = Evidence()
        if vote:
            bba["true"] = reliability
            bba["false"] = (1 - reliability) * 0.1
            bba["uncertain"] = 1 - reliability - (1 - reliability) * 0.1
        else:
            bba["false"] = reliability
            bba["true"] = (1 - reliability) * 0.1
            bba["uncertain"] = 1 - reliability - (1 - reliability) * 0.1
        bbas.append(bba)

    fused = combine(*bbas, method="pcr6")
    is_true = fused["true"] > fused["false"]
    confidence = max(0, min(100, round(max(fused["true"], fused["false"]) * 100)))
    return is_true, confidence
```

### 4.3 指数衰减模型

```python
import math

def decay_confidence(base_confidence: int, hours_since_update: float,
                     decay_rate: float = 0.005) -> int:
    """MISP 指数衰减模型"""
    decayed = base_confidence * math.exp(-decay_rate * hours_since_update)
    return max(0, min(100, round(decayed)))
    # decay_rate=0.005: 24h → ×0.89, 7d → ×0.43, 30d → ×0.03
```

衰减影响 `confidence` 字段值。
`valid_until` 提供硬过期时间（confidence < 10 时设置）。
两者互补不冲突。

### 4.4 置信度输出规范

STIX 2.1 `confidence` 字段值域为 0-100 整数。
与旧版 low/medium/high 的映射 (STIX Appendix A)：

| 旧等级 | STIX 值 | 范围 |
|--------|---------|------|
| None | 0 | 0 |
| Low | 15 | 1-29 |
| Medium | 50 | 30-69 |
| High | 85 | 70-100 |

---

## 5. API 设计

### 5.1 查询接口

```
GET /api/lookup/{ip}?fields=country,asn,proxy,tor,malicious&expand=sources
```

**参数**:

| 参数 | 说明 | 示例 |
|------|------|------|
| `fields` | 逗号分隔，选择返回哪些字段 | `country,asn,proxy,tor,malicious` |
| `expand` | `sources` = 展开源明细和置信度 | `expand=sources` |

**可选字段**:

```
基础信息:   country, asn, as_name, ip_range, is_isp
威胁检测:   proxy, tor, vpn, malicious, hosting, mobile
```

不传 `fields` 时返回所有字段（向后兼容）。

### 5.2 扁平化 JSON 输出

```python
# GET /api/lookup/1.2.3.4?fields=country,asn,proxy,tor&expand=sources

{
  "ip": "1.2.3.4",

  "country": {
    "value": "US",
    "confidence": 92,
    "sources": {
      "ipinfo_lite": {"value": "US", "reliability": 0.95},
      "iptoasn":     {"value": "US", "reliability": 0.90},
      "cn_isp":      {"value": "US", "reliability": 0.85}
    }
  },

  "asn": {
    "value": 13335,
    "confidence": 95,
    "sources": {
      "ipinfo_lite": {"value": 13335, "reliability": 0.95},
      "iptoasn":     {"value": 13335, "reliability": 0.90}
    }
  },

  "threats": {
    "proxy": {
      "value": true,
      "confidence": 65,
      "algorithm": "pcr6",
      "sources": {
        "ip2proxy":    {"value": true,  "reliability": 0.80, "authoritative": true},
        "ipinfo_lite": {"value": false, "reliability": 0.95},
        "ipsum":       {"value": true,  "reliability": 0.55}
      }
    },
    "tor": {
      "value": true,
      "confidence": 95,
      "algorithm": "cascade",
      "sources": {
        "tor_exits": {"value": true, "reliability": 0.95, "authoritative": true}
      }
    }
  }
}
```

### 5.3 STIX Bundle 导出接口

```
GET /api/lookup/{ip}/stix
```

返回完整的 STIX 2.1 Bundle JSON（包含所有对象，不受 `fields` 参数限制）。

---

## 6. 前端交互设计

### 6.1 动态字段选择器

```
┌─────────────────────────────────────────────┐
│  字段选择器 (可折叠面板)                       │
│                                             │
│  ▸ 基础信息                                  │
│    [x] country   [x] ASN   [ ] AS名称       │
│    [x] IP范围    [ ] 是否ISP                 │
│                                             │
│  ▸ 威胁检测                                  │
│    [x] Proxy    [x] Tor    [ ] VPN           │
│    [x] Malicious [ ] Hosting [ ] Mobile      │
│                                             │
│  [x] 显示源明细和置信度                        │
└─────────────────────────────────────────────┘
```

### 6.2 结果展示 (源明细展开)

```
┌─────────────────────────────────────────────┐
│  IP: 1.2.3.4                                │
│                                             │
│  Country: US          ████████░░ 92/100     │
│    sources: ipinfo_lite(US), iptoasn(US)    │
│                                             │
│  ASN: 13335          █████████░ 95/100      │
│    sources: ipinfo_lite(13335), iptoasn(...) │
│                                             │
│  ▸ Proxy: TRUE       ██████░░░░ 65/100  ⚠PCR│
│    ├ ip2proxy     TRUE   (0.80) 🔑权威       │
│    ├ ipinfo_lite  FALSE  (0.95)              │
│    └ ipsum        TRUE   (0.55)              │
│    算法: PCR6 (投票接近, 自动升级)             │
│                                             │
│  ▸ Tor: TRUE         █████████░ 95/100      │
│    └ tor_exits   TRUE   (0.95) 🔑权威        │
│    算法: 级联决策 (权威源否决)                  │
│                                             │
│  [导出 STIX Bundle]                          │
└─────────────────────────────────────────────┘
```

---

## 7. 目录结构

```
backend/ipdb/
  _stix/                 # 新增: STIX 工具模块
    __init__.py          # STIX 对象工厂函数
    types.py             # 项目特定 STIX 类型定义
    bundle.py            # Bundle 构建/导出
    confidence.py        # 置信度计算引擎
    extension.py         # extension-definition 定义
  _sources/              # 改造: 每个源输出 STIX 对象
    __init__.py
    ipinfo_lite.py
    iptoasn.py
    cn_isp.py
    ip2proxy.py
    ipsum.py
    firehol.py
    tor_exits.py
    x4bnet_vpn.py
    threatfox.py         # 新增
    otx.py               # 新增
    blocklist_de.py      # 新增
    spamhaus.py          # 新增
    cybercrime.py        # 新增
    shadowserver.py      # 新增
    circl_osint.py       # 新增
    misp_osint.py        # 新增
    misp_warninglists.py # 新增 (过滤器)
  _enrichers/            # 保持
    ip_api.py
    ipapi_is.py
  _merge.py              # 重写: STIX 对象合并引擎
  _registry.py           # 改造: lookup 内部使用 STIX
  _export.py             # 新增: STIX Bundle → 扁平化 JSON
  _types.py              # 改造: SourceProtocol 增加 STIX 方法
```

---

## 8. python-stix2 技术要点

### 8.1 对象不可变

python-stix2 创建的对象是 frozen dict，修改属性会抛 `ImmutableError`。
需要用 `new_version()` 创建新版本：

```python
# 修改 confidence
updated_indicator = indicator.new_version(confidence=80)
```

### 8.2 自定义属性规则

- SDO 自定义属性必须以 `x_` 前缀命名
- 通过 `custom_properties` 字典或 `allow_custom=True` 传递
- Extension 通过 `@CustomExtension` 装饰器注册

### 8.3 关系类型

- `belongs-to`: ipv4-addr → autonomous-system ✅ 合规
- `located-at`: ipv4-addr → location ❌ 不合规，用 `related-to` 替代
- `related-to`: 任何对象间 ✅ 通用关系类型
- 嵌入式关系: `belongs_to_refs` 可直接在 ipv4-addr 上使用

### 8.4 STIX Pattern 语法

```
IPv4 地址:  [ipv4-addr:value = '1.2.3.4']
CIDR 范围:  [ipv4-addr:value = '1.2.3.0/24']
```

---

## 9. STIX 2.1 规范验证结果

### 9.1 验证方法

通过 4 个并行 agent 独立验证：
1. STIX 规范映射 (SCO/SDO/SRO 合规性)
2. python-stix2 库兼容性 (代码可行性)
3. 置信度模型兼容性 (confidence 语义)
4. 数据源适配可行性 (16+ 源映射)

### 9.2 已修正的问题

| 问题 | 修正 |
|------|------|
| Identity `identity_class` 用 `"organization"` | 改为 `"system"` |
| 自定义属性无前缀 | 添加 `x_` 前缀 (如 `x_reliability`) |
| `located-at` 用于 ipv4-addr → location | 改为 `related-to` |
| Per-threat 置信度放在 Indicator 顶层 | 放入 extension `threat_scores` |
| extension-definition 未包含在 Bundle 中 | 每个 Bundle 必须包含 |

### 9.3 确认合规项

- confidence 0-100 整数 ✅
- STIX 无内置置信度聚合，自定义设计自由 ✅
- 源可靠性权重是内部概念，不导出到 STIX ✅
- PCR6 输出 round 到 0-100 即可 ✅
- 衰减模型与 valid_from/valid_until 互补 ✅
- UUIDv5 去重机制足够 ✅
- 所有 indicator_types 值在规范开放词汇中 ✅

---

## 10. 性能预估

| 查询类型 | 延迟 | 说明 |
|----------|------|------|
| 纯本地 (8 现有源) | ~5ms | pytricia 微秒级 |
| 本地 + 预下载新增源 | ~10ms | pytricia 微秒级 |
| 本地 + 在线 API 并行 | ~3s | 受限于最慢的 Shadowserver |
| 批量 100 IP (本地) | ~500ms | |
| 批量 100 IP (含在线) | ~30s | |

新增源建议全部采用**预下载 + 本地 pytricia** 模式。
仅 ThreatFox 和 OTX 的按需搜索保持在线查询。
