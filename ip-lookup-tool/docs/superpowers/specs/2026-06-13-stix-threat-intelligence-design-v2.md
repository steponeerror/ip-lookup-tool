# STIX 2.1 威胁情报聚合系统设计规格 (修订版)

> 日期: 2026-06-13
> 状态: 设计完成，待实施
> 分支: feat/source-registry

---

## 1. 概述

### 1.1 目标

将 IP Radar 的数据管道升级为支持多源情报聚合和 STIX 2.1 导出：

1. **类型化内部模型** — 用 dataclass 定义强类型结果，confidence 从 string 升级为 0-100 整数
2. **智能合并引擎** — 权威源否决 + 加权投票 + PCR6 证据融合
3. **频繁加源架构** — 基类消除样板 + 自动注册，加一个新源只需 10-50 行
4. **STIX 2.1 导出** — 按需生成 STIX Bundle，STIX 只在边界出现

### 1.2 核心架构决策

```
源 → 简单 dict → 类型化内部模型 merge → LookupResult
                                            ├→ 扁平化 JSON (API)
                                            └→ STIX Bundle 导出 (可选)
```

STIX 作为**输出格式**而非内部格式。内部管道操作 dataclass，简单高效。

| 决策项 | 选择 | 理由 |
|--------|------|------|
| STIX 定位 | 导出格式（非内部格式） | 避免复杂性渗透到每个源 |
| 源的职责 | 只返回简单 dict | 源保持简单，STIX 转换由适配器处理 |
| confidence | 0-100 整数 | 更精细的置信度表达，STIX 兼容 |
| 冲突解决 | 权威否决 → 加权投票 → PCR6 升级 | 三层渐进，覆盖 95%+ 场景 |
| PCR6 实现 | 自实现 (~50 行) | 零外部依赖，可控 |
| 源注册 | 自动发现 `_sources/` 目录 | 加源不需要改其他文件 |
| STIX 依赖 | 仅 `_stix_export.py` import | 未安装不影响核心功能 |

---

## 2. 内部数据模型

### 2.1 数据类型 (`_types.py` 新增)

```python
from dataclasses import dataclass, field
from typing import Any

@dataclass
class SourceAttribution:
    """单个源对一个字段的贡献"""
    source: str
    value: Any
    reliability: float = 0.0         # 0.0 - 1.0
    authoritative: bool = False       # 该源是否此领域的权威

@dataclass
class MergedField:
    """单个字段的合并结果"""
    value: Any
    confidence: int                   # 0-100 整数
    algorithm: str = "voting"         # "cascade" | "voting" | "pcr6" | "authority" | "specificity"
    sources: list[SourceAttribution] = field(default_factory=list)

@dataclass
class ThreatAssessment:
    """单个威胁类型的评估结果"""
    detected: bool
    confidence: int
    algorithm: str
    sources: list[SourceAttribution]

@dataclass
class LookupResult:
    """完整 IP 查询结果"""
    ip: str
    country: MergedField
    asn: MergedField
    as_name: MergedField
    ip_range: MergedField
    is_isp: bool
    threats: dict[str, ThreatAssessment]   # key = "proxy", "tor", "vpn"...
                                            # 注意: 不带 "is_" 前缀
    error: str | None = None
```

### 2.2 序列化

```python
# LookupResult.to_dict() — 转换为 API JSON
def to_dict(self) -> dict:
    return {
        "ip": self.ip,
        "country": _field_to_dict(self.country),
        "asn": _field_to_dict(self.asn),
        "as_name": _field_to_dict(self.as_name),
        "ip_range": _field_to_dict(self.ip_range),
        "is_isp": self.is_isp,
        "threats": {
            name: {
                "detected": t.detected,
                "confidence": t.confidence,
                "algorithm": t.algorithm,
                "sources": [
                    {"source": s.source, "value": s.value,
                     "reliability": s.reliability, "authoritative": s.authoritative}
                    for s in t.sources
                ],
            }
            for name, t in self.threats.items()
        },
        **({"error": self.error} if self.error else {}),
    }
```

### 2.3 保留的现有类型

`OfflineSource`, `OnlineEnricher`, `SourceHealth`, `MergeStrategy` 保留不变。
`MergeStrategy.merge()` 返回类型从 `tuple[Any, str]` 改为 `MergedField`。

---

## 3. 源框架设计

### 3.1 基类 (`_sources/_base.py`)

**设计原则**：消除 8 个源之间 ~70% 的重复代码，让加新源变成声明式操作。

#### IpListSource — IP/CIDR 列表源基类

```python
class IpListSource:
    """IP/CIDR 列表源基类 — 覆盖 tor_exits/x4bnet/firehol/spamhaus/blocklist_de 等场景"""

    name: str
    url: str
    filename: str
    fields: tuple[str, ...]
    stale_days: int = 7
    reliability: float = 0.5
    authoritative_for: list[str] = []

    def parse_raw(self, raw: bytes) -> list[str]:
        """解析下载内容为 IP/CIDR 列表。大多数源不需要 override。"""
        return [l.strip() for l in raw.decode(errors="ignore").splitlines()
                if l.strip() and not l.startswith("#")]

    def get_insert_data(self) -> dict:
        """pytricia 中每条记录存的值。"""
        return {self.fields[0]: True}

    # download(), load(), query(), health() — 全部继承
```

#### CsvSource — CSV 格式源基类

```python
class CsvSource(IpListSource):
    """CSV 源 — 下载 CSV 文件，逐行解析为 dict"""

    skip_lines: int = 0
    delimiter: str = ","

    def parse_row(self, row: list[str]) -> dict | None:
        """CSV 每行 → dict, 返回 None 跳过。子类必须实现。"""
        raise NotImplementedError
```

#### ApiSource — 在线 API 源基类

```python
class ApiSource:
    """在线 API 源 — 按需查询，不预下载"""

    name: str
    fields: tuple[str, ...]
    reliability: float = 0.5
    authoritative_for: list[str] = []

    def query_api(self, ip: str) -> dict:
        """按需查询 API。子类必须实现。"""
        raise NotImplementedError
```

### 3.2 新源示例

**IP 列表源 — 6-10 行：**

```python
class SpamhausSource(IpListSource):
    name = "spamhaus"
    url = "https://www.spamhaus.org/drop/drop.txt"
    filename = "spamhaus_drop.txt"
    fields = ("is_malicious",)
    stale_days = 1
    reliability = 0.90
    authoritative_for = ["is_malicious"]
```

**CSV 源 — ~30 行：**

```python
class ThreatFoxSource(CsvSource):
    name = "threatfox"
    url = "https://threatfox.abuse.ch/export/csv/full/"
    filename = "threatfox.csv"
    fields = ("is_malicious",)
    reliability = 0.85
    authoritative_for = ["is_malicious"]
    skip_lines = 9

    def parse_row(self, row: list[str]) -> dict | None:
        if len(row) < 6 or row[5] != "ip:port":
            return None
        return {"is_malicious": True, "_threatfox_confidence": int(row[8])}
```

### 3.3 现有源重构

| 源 | 现有行数 | 重构后 | 方式 |
|----|---------|--------|------|
| tor_exits | 105 | ~20 | IpListSource + 自定义 parse_raw (正则提取) |
| x4bnet_vpn | 93 | ~10 | IpListSource (直接继承) |
| firehol | 111 | ~20 | IpListSource + 自定义 parse_raw |
| ipsum | ~90 | ~25 | CsvSource + 自定义 parse_row |
| ip2proxy | ~120 | ~35 | CsvSource + 自定义 parse_row |
| ipinfo_lite | ~120 | 保留独立 | 复杂 MMDB 解析，不强套基类 |
| iptoasn | ~100 | 保留独立 | TSV 格式 + 多字段 |
| cn_isp | ~100 | 保留独立 | 自定义目录结构 |

### 3.4 自动注册

```python
# _registry.py — 自动发现 _sources/ 下所有源类

def _discover_sources(data_dir: Path) -> list:
    sources = []
    for module in sorted(Path(__file__).parent.glob("_sources/*.py")):
        if module.name.startswith("_"):
            continue
        mod = importlib.import_module(f"._sources.{module.stem}", __package__)
        for attr_name in dir(mod):
            obj = getattr(mod, attr_name)
            if (isinstance(obj, type)
                and hasattr(obj, "name") and hasattr(obj, "fields")
                and obj.__module__ == mod.__name__):
                sources.append(obj(data_dir=data_dir))
    return sources
```

加一个源 = 在 `_sources/` 下放一个文件。不需要改 `_registry.py` 或任何其他文件。

### 3.5 源可靠性权重

```python
SOURCE_RELIABILITY = {
    "ipinfo_lite":   0.95,
    "iptoasn":       0.90,
    "cn_isp":        0.85,
    "ip2proxy":      0.80,
    "tor_exits":     0.95,
    "x4bnet_vpn":    0.70,
    "ipsum":         0.55,
    "firehol":       0.50,
    # Phase 4 新增源
    "spamhaus":      0.90,
    "threatfox":     0.85,
    "blocklist_de":  0.65,
    "shadowserver":  0.90,
}
```

权重声明在源的 `reliability` 类属性上，`SOURCE_RELIABILITY` 字典由自动注册收集。

### 3.6 权威源映射

```python
AUTHORITATIVE_SOURCES = {
    "is_proxy":     ["ip2proxy"],
    "is_tor":       ["tor_exits"],
    "is_vpn":       ["x4bnet_vpn"],
    "is_malicious": ["threatfox", "shadowserver", "spamhaus"],
    "is_hosting":   ["ipinfo_lite"],
    "is_mobile":    ["ipinfo_lite"],
}
```

---

## 4. 置信度聚合算法

### 4.1 三层决策架构

```
Stage 1: 权威源否决
  ├── 该领域有权威源吗？
  ├── 权威源报告 True → True, confidence = 权威源加权置信度
  └── 权威源报告 False / 无权威源 → 继续到 Stage 2

Stage 2: 加权投票
  ├── true_weight = Σ(reliability, 源报告 True)
  ├── false_weight = Σ(reliability, 源报告 False)
  ├── margin = |tw - fw| / (tw + fw)
  └── margin ≥ 20% → 使用投票结果
                        margin < 20% → 升级到 Stage 3

Stage 3: PCR6 证据融合 (高冲突升级)
  ├── 每个源 → Basic Belief Assignment (BBA)
  ├── 成对 PCR6 组合
  └── fused["true"] > fused["false"] → True
```

### 4.2 PCR6 证据融合 (自实现, 零依赖)

```python
def _build_bba(vote: bool | None, reliability: float) -> dict[str, float]:
    """源投票 + 可靠性 → Basic Belief Assignment"""
    if vote is None:
        return {"true": 0.0, "false": 0.0, "uncertain": 1.0}
    if vote:
        return {"true": reliability, "false": 0.0, "uncertain": 1.0 - reliability}
    return {"true": 0.0, "false": reliability, "uncertain": 1.0 - reliability}


def _pcr6_pair(a: dict, b: dict) -> dict:
    """两个 BBA 的 PCR6 组合"""
    # 合取部分
    m_t = a["true"]*b["true"] + a["true"]*b["uncertain"] + a["uncertain"]*b["true"]
    m_f = a["false"]*b["false"] + a["false"]*b["uncertain"] + a["uncertain"]*b["false"]
    m_u = a["uncertain"] * b["uncertain"]

    # 冲突质量 → PCR6 按原始信度比例重新分配
    dt = a["true"] + b["true"]
    df = a["false"] + b["false"]
    if dt > 0:
        m_t += a["true"]**2 * b["false"] / dt + b["true"]**2 * a["false"] / dt
    if df > 0:
        m_f += a["false"]**2 * b["true"] / df + b["false"]**2 * a["true"] / df

    return {"true": m_t, "false": m_f, "uncertain": m_u}


def pcr6_combine(bbas: list[dict]) -> dict:
    """N 个 BBA 的迭代成对 PCR6 融合"""
    result = bbas[0]
    for bba in bbas[1:]:
        result = _pcr6_pair(result, bba)
    return result
```

### 4.3 置信度计算辅助函数

```python
def _weighted_confidence(true_sources: list[SourceAttribution],
                          all_sources: list[SourceAttribution]) -> int:
    """权威源否决时的置信度计算"""
    tw = sum(s.reliability for s in true_sources)
    total = sum(s.reliability for s in all_sources if s.value is not None)
    if total == 0:
        return 0
    return min(100, round(tw / total * 100))

# 覆盖率惩罚: 参与源数 < 期望源数 * 50% 时 confidence * 0.7
def _apply_coverage_penalty(confidence: int, participating: int, expected: int) -> int:
    if expected > 0 and participating / expected < 0.5:
        return round(confidence * 0.7)
    return confidence
```

### 4.4 BooleanUnion 策略 (含 PCR6)

```python
class BooleanUnion:
    field: str

    def merge(self, source_values: dict, context: dict) -> MergedField:
        sources = []
        for src, value in source_values.items():
            rel = SOURCE_RELIABILITY.get(src, 0.5)
            auth = src in AUTHORITATIVE_SOURCES.get(self.field, [])
            sources.append(SourceAttribution(src, value, rel, auth))

        # Stage 1: 权威源否决
        auth_true = [s for s in sources if s.authoritative and s.value is True]
        if auth_true:
            conf = _weighted_confidence(auth_true, sources)
            return MergedField(True, conf, "cascade", sources)

        # Stage 2: 加权投票
        tw = sum(s.reliability for s in sources if s.value is True)
        fw = sum(s.reliability for s in sources if s.value is False)
        total = tw + fw
        if total == 0:
            return MergedField(False, 0, "voting", sources)

        margin = abs(tw - fw) / total

        # Stage 3: 投票接近 → PCR6 升级
        if margin < 0.20 and len(sources) >= 2:
            bbas = [_build_bba(s.value, s.reliability) for s in sources]
            fused = pcr6_combine(bbas)
            detected = fused["true"] > fused["false"]
            conf = round(max(fused["true"], fused["false"]) * 100)
            return MergedField(detected, conf, "pcr6", sources)

        # Stage 4: 投票结果明确
        detected = tw > fw
        conf = round(max(tw, fw) / total * 100)
        return MergedField(detected, conf, "voting", sources)
```

### 4.5 其他策略升级

| 策略 | 字段 | 升级逻辑 |
|------|------|---------|
| FactualVoting | country, asn | 0 valid→0, 1源→50, 全一致→85+共识加成, 多数→50-70 |
| NamingAuthority | as_name | 权威源→90, 单源→50, 无→0 |
| RangeSpecificity | ip_range | 1 range→50, 多个→85 (最具体) |

### 4.6 confidence 与旧版映射

| 旧等级 | 旧值 | 新范围 | 新默认 |
|--------|------|--------|--------|
| None | — | 0 | 0 |
| Low | "low" | 1-29 | 20 |
| Medium | "medium" | 30-69 | 50 |
| High | "high" | 70-100 | 85 |

---

## 5. API 设计

### 5.1 查询接口

```
GET /api/lookup/{ip}
POST /api/query/stream
POST /api/upload/stream
```

接口路径不变，响应格式升级。

### 5.2 响应格式

```json
{
  "ip": "1.2.3.4",
  "country": {
    "value": "US",
    "confidence": 85,
    "algorithm": "voting",
    "sources": [
      {"source": "ipinfo_lite", "value": "US", "reliability": 0.95, "authoritative": false},
      {"source": "iptoasn", "value": "US", "reliability": 0.90, "authoritative": false}
    ]
  },
  "asn": {"value": 13335, "confidence": 90, "algorithm": "voting", "sources": [...]},
  "as_name": {"value": "Cloudflare", "confidence": 95, "algorithm": "authority", "sources": [...]},
  "ip_range": {"value": "1.2.3.0/24", "confidence": 50, "algorithm": "specificity", "sources": [...]},
  "is_isp": false,
  "threats": {
    "proxy": {
      "detected": true,
      "confidence": 80,
      "algorithm": "cascade",
      "sources": [
        {"source": "ip2proxy", "value": true, "reliability": 0.80, "authoritative": true},
        {"source": "ipinfo_lite", "value": false, "reliability": 0.95, "authoritative": false},
        {"source": "ipsum", "value": true, "reliability": 0.55, "authoritative": false}
      ]
    },
    "tor": {
      "detected": true,
      "confidence": 95,
      "algorithm": "cascade",
      "sources": [
        {"source": "tor_exits", "value": true, "reliability": 0.95, "authoritative": true}
      ]
    },
    "vpn": {"detected": false, "confidence": 0, "algorithm": "voting", "sources": [...]},
    "malicious": {"detected": false, "confidence": 0, "algorithm": "voting", "sources": [...]},
    "hosting": {"detected": true, "confidence": 85, "algorithm": "voting", "sources": [...]},
    "mobile": {"detected": false, "confidence": 90, "algorithm": "voting", "sources": [...]}
  }
}
```

### 5.3 STIX Bundle 导出端点

```
GET /api/lookup/{ip}/stix
```

返回完整的 STIX 2.1 Bundle JSON。stix2 未安装时返回 501。

---

## 6. STIX 2.1 导出适配器

### 6.1 设计原则

- STIX 只在导出时出现，不渗透到内部管道
- `_stix_export.py` 是唯一 import stix2 的文件
- `stix2` 为可选依赖，未安装不影响核心功能

### 6.2 STIX 对象映射

| 内部模型 | STIX 对象 | 说明 |
|----------|----------|------|
| LookupResult.ip | ipv4-addr SCO | UUIDv5 确定性，同 IP 同 ID |
| LookupResult.asn | autonomous-system SCO | 嵌入式 belongs_to_refs |
| LookupResult.country | location SDO | related-to 关系 |
| LookupResult.threats | indicator SDO + extension | 威胁评估放在 extension |
| 每个参与源 | identity SDO | x_reliability, x_authoritative |

### 6.3 STIX 2.1 规范合规项

- `confidence` 0-100 整数 ✅
- `belongs_to_refs` 嵌入式关系 ✅
- ipv4-addr → location 用 `related-to` (located-at 不支持 SCO) ✅
- `identity_class="system"` (自动化数据源) ✅
- `x_` 前缀自定义属性 ✅
- extension-definition 包含在每个 Bundle 中 ✅
- `indicator_types` 值在规范开放词汇中 ✅

---

## 7. 前端迁移

### 7.1 类型定义 (`api.ts`)

```typescript
export interface SourceAttribution {
  source: string;
  value: any;
  reliability: number;
  authoritative: boolean;
}

export interface MergedField<T = any> {
  value: T;
  confidence: number;
  algorithm: string;
  sources: SourceAttribution[];
}

export interface ThreatAssessment {
  detected: boolean;
  confidence: number;
  algorithm: string;
  sources: SourceAttribution[];
}

export interface LookupResult {
  ip: string;
  country: MergedField<string>;
  asn: MergedField<number | string>;
  as_name: MergedField<string>;
  ip_range: MergedField<string>;
  is_isp: boolean;
  threats: Record<string, ThreatAssessment>;
  error?: string;
}
```

### 7.2 组件改动

**ResultTable.tsx：**
- 置信度渲染：`conf ≥ 70 ? emerald : conf ≥ 30 ? amber : red`（连续色）
- 威胁数据访问：`threat.value.is_proxy` → `threats.proxy.detected`
- 源明细：`threat.sources[src].is_proxy` → `threats.proxy.sources[idx]`
- 新增：algorithm 标记（cascade🔑/voting📊/pcr6⚠️）

**ExportCsv.tsx：**
- confidence 列从 string 改 number
- 新增 algorithm 列

### 7.3 新增：STIX 导出按钮

在结果面板中添加「导出 STIX Bundle」按钮，调用 `/api/lookup/{ip}/stix`。

---

## 8. 目录结构

```
backend/ipdb/
  _stix_export.py       # 新增: STIX 导出适配器 (唯一 import stix2)
  _sources/
    _base.py            # 新增: IpListSource/CsvSource/ApiSource 基类
    tor_exits.py        # 重构: IpListSource 子类 (105→~20 行)
    x4bnet_vpn.py       # 重构: IpListSource 子类 (93→~10 行)
    firehol.py          # 重构: IpListSource 子类 (~40 行)
    ipsum.py            # 重构: CsvSource 子类 (~25 行)
    ip2proxy.py         # 重构: CsvSource 子类 (~35 行)
    ipinfo_lite.py      # 保留: 独立实现
    iptoasn.py          # 保留: 独立实现
    cn_isp.py           # 保留: 独立实现
    spamhaus.py         # Phase 4: 新增 (~10 行)
    threatfox.py        # Phase 4: 新增 (~30 行)
    blocklist_de.py     # Phase 4: 新增 (~10 行)
    shadowserver.py     # Phase 4: 新增 (~50 行)
  _types.py             # 改造: 新增 dataclass, 保留现有 Protocol
  _merge.py             # 重写: 策略返回 MergedField + PCR6
  _registry.py          # 改造: 自动注册 + lookup() 返回 LookupResult
```

---

## 9. 实施阶段

### Phase 1: 内部模型 + Merge 引擎 (1-2 天)

**改动文件** (8 个)：`_types.py`, `_merge.py`, `_registry.py`, `main.py`, `api.ts`, `ResultTable.tsx`, `ExportCsv.tsx`, 测试文件 ×4

**验证标准**：
- 所有现有测试通过
- 单 IP 查询延迟 ≤ 8ms
- 批量 100 IP ≤ 600ms
- 前端正确渲染所有字段

### Phase 2: 源框架重构 (1 天)

**改动文件**：新增 `_base.py`，重构 5 个源，改造 `_registry.py` 自动注册

**验证标准**：
- 所有 8 个源行为不变
- `_registry.py` 不再硬编码源列表
- 新增测试源文件后自动被发现

### Phase 3: STIX 导出 (0.5 天)

**改动文件**：新增 `_stix_export.py`，`main.py` 新端点，`requirements.txt`，前端按钮

**验证标准**：
- STIX Bundle 包含正确的 SCO/SDO/SRO/SMO
- 同一 IP 的 ipv4-addr ID 跨请求一致
- stix2 未安装时核心功能不受影响

### Phase 4: 新源接入 (每源 0.5-1 天)

| 批次 | 源 | 类型 | 代码量 |
|------|-----|------|--------|
| 4a | Spamhaus DROP, Blocklist.de | IpListSource | ~10 行/源 |
| 4b | ThreatFox, Shadowserver | CsvSource/ApiSource | ~35-50 行/源 |
| 4c | CIRCL/MISP OSINT, MISP Warning Lists | 自定义 | ~30-60 行/源 |

### Phase 5: UI 增强 (1 天)

- 算法标签（cascade/voting/pcr6 图标）
- 置信度连续色进度条
- 源可靠性展示
- 权威源标记

---

## 10. 性能预估

| 操作 | 现有 | Phase 1 后 | Phase 4 后 |
|------|------|-----------|-----------|
| 单 IP 查询 (本地) | ~5ms | ~6ms | ~8ms |
| 批量 100 IP (本地) | ~500ms | ~550ms | ~800ms |
| STIX Bundle 生成 | — | ~2ms | ~3ms |

PCR6 仅在投票差距 < 20% 时触发，计算开销可忽略。

---

## 11. 依赖

| 包 | 版本 | 阶段 | 必选 |
|----|------|------|------|
| fastapi | ≥0.115 | 已有 | 是 |
| uvicorn[standard] | ≥0.34 | 已有 | 是 |
| pytricia | ≥1.0 | 已有 | 是 |
| python-multipart | ≥0.0.20 | 已有 | 是 |
| python-dotenv | ≥1.1 | 已有 | 是 |
| stix2 | ≥3.0.1 | Phase 3 | 否（STIX 导出可选） |

总依赖从 5 个增加到 6 个，其中 stix2 为可选。
