# 多类别源逐条分类设计（Per-Entry Classification for Multi-Category Sources）

**日期**: 2026-06-14
**状态**: 设计待评审
**分支**: `feat/source-registry`
**范围**: 窄（仅"逐条分类 + 新源友好"），不含复核算法 / STIX / 性能（见"不在范围内"）

## 背景与问题

当前 fusion 架构把 `classification_type` 当作**源级类属性**（`otx.py:57`、`threatfox.py:30`、`blocklist_de.py:10` 等）。`IpListSource.get_insert_data()`（`_base.py:51-61`）在 `load()` 时算**一次**，然后对源里**每一个 IP** 都插入这同一个 dict。后果：

1. **多类别源被压扁**：ThreatFox 的 `threat_type` 列就在数据里（实测 67% `botnet_cc` / 27% `payload_delivery` / 6% `payload`），却全标成 `c2-server`，33% 标错。OTX 聚合数千社区 pulse（C2 / 恶意软件 / 扫描 / 钓鱼…），也全标成 `c2-server`。
2. **`CsvSource.query()` 丢逐条数据（真实 bug）**：`_base.py:116-123` 的 `query()` 做了 `self._tree[ip]` 后**丢弃返回值**，转而返回类级 `get_insert_data()`。`CsvSource.load()` 第 194 行确实把逐行 dict（含 `malware_name`/`confidence`/`first_seen`/`classification_type`）存进了 trie，但查询时全部被类级常量覆盖。ThreatFox 的富证据永远到不了引擎。
3. **加新源没有清晰的"多类别"路径**：`2026-06-14-multi-source-evidence-fusion-design.md` 的"接源模板"把 `classification_type` 写成类属性必填，新源默认就是单分类。

### Scope Guard
> 引擎侧其实**已经支持**逐条分类：`_merge.py:13-43` 的 `to_observation()` 第 32-33 行优先用 raw dict 里的 `classification_type` 覆盖类属性；`_registry.py:152-157` 的 `lookup()` 直接读 `raw["classification_type"]` 喂给引擎。**所以本设计主要改的是源层契约，引擎几乎不动。**

## 目标 / 非目标

**目标**
- 修 `query()` bug：返回 trie 存储的逐条值。
- 支持单源单 IP 多分类（证据源 trie 值 = `list[dict]`）。
- 多类别源逐条映射：ThreatFox（`threat_type` 列）、blocklist_de（按 attack-type 拉取）、OTX（pulse `threat_type`，gated on REST 改造）。
- 引入 `_classification.py`：IntelMQ `classification.type` 词表 + 原生→IntelMQ 映射帮手，让加新源变简单。
- 不破坏 API/前端 schema（`classifications` dict 结构不变）。

**非目标（本 spec 不做，另立跟踪）**
- 复核权重算法 / PCR6 接线（PCR6 已实现未调用，见 `_merge.py:46-83` 死代码）。
- STIX 导出边界（`x_*` 命名 / 冲突 / 可逆性）。
- 性能改造（freeze/pickle/批量非阻塞）。
- 在线源配额（目前无在线威胁源）。
- `extra` 字段安全白名单（目前无源填 `extra`，YAGNI）。

## 架构改动

### 1. 源契约盘点（修订：回应评审 Finding 1，避免"恰好能跑"的隐式依赖）

证据源 trie 值从"单个 dict"改为"`list[dict]`"。改动前**必须**逐一确认每个源的当前 trie/query 形状，因为部分源走自定义路径：

| 源 | 基类 | load 来源 | query 来源 | 当前 trie 值 | §1 动作 |
|---|---|---|---|---|---|
| ipinfo_lite | 自有类 | custom | custom | 标量 dict | **不动**（标量路径） |
| iptoasn | 自有类 | custom | custom | 标量 dict | **不动** |
| cn_isp | 自有类 | custom | custom | 标量 dict | **不动** |
| tor_exits | IpListSource | base（override `get_insert_data`） | base（bug） | evidence dict | 基类 load 改 list 自动覆盖 |
| x4bnet_vpn / spamhaus / emerging_threats / otx | IpListSource | base | base（bug） | evidence dict | 基类 load 改 list 自动覆盖 |
| blocklist_de | IpListSource | base | base（bug） | evidence dict | T4 重写 load 时原生产 list |
| ipsum / threatfox | CsvSource | base | base（bug） | 逐行 dict | 基类 load 改 list 自动覆盖 |
| **firehol** | IpListSource | **custom**（存 dict） | base（bug，继承） | evidence dict | **§1 显式改 firehol.load 存 `[dict]`** |
| **ip2proxy** | CsvSource | **custom** | **custom**（返 dict，仅为绕 bug） | per-range dict | **§1 删自定义 query + load 改存 `[dict]`**（基类 query 修复后 override 冗余） |

**基类改动**：
- **`IpListSource.load()`**：累积 `dict[cidr_str, list[dict]]`，每个 CIDR 存 `[self.get_insert_data()]`。
- **`CsvSource.load()`**：每行 `parse_row` 出的证据 dict 按规范化 CIDR 累积到 list，**带去重**（见 §2）；同 IP 多 `threat_type` → list 多元素。
- **`query()` 修复**（返回存储值，不再返回类级常量）：
  ```python
  def query(self, ip):
      if self._tree is None:
          return {}
      try:
          return self._tree[ip]   # 证据源 = list[dict]；标量源 = dict（未被本 spec 触及）
      except KeyError:
          return {}
  ```

**显式动作（必须在 T1 一并落地，否则契约不一致）**：
- `firehol.load()`：把 `tree.insert(net, {dict})` 改成 `tree.insert(net, [{dict}])`（它继承新 query，必须存 list）。
- `ip2proxy`：删 `query()` override（其注释 line 111-114 自陈 override 仅为绕 bug；基类修好后冗余），`load()` 改存 `[evidence]`。

**回归测试（新增）**：T1 后断言每个源 `query(ip)` 返回形状——证据源 `list[dict]`、标量源 `dict`，作为契约护栏。

**关于 ip2proxy 的 `is_proxy`/`is_hosting`**：其 evidence dict 仍带这俩键（retired 布尔），§2 归一化的取值键列表不含它们 → **被忽略**。当前无害，spec 明示此 drop。

### 2. `_registry.py:lookup()` 归一化

把标量源（dict）和证据源（list）归一成统一 items，标量取值 + 逐条 observation 都覆盖：

```python
raw = source.query(ip)
items = raw if isinstance(raw, list) else ([raw] if raw else [])
for item in items:
    for key in ("country_code","asn","as_name","ip_range","is_isp"):
        if key in item:
            field_values[key][source.name] = item[key]
    if "classification_type" in item:
        observations.append(to_observation(
            source.name, item,
            classification_type=item["classification_type"],
            verdict=item.get("verdict","malicious"),
            reliability=getattr(source,"reliability",0.5)))
```

引擎按 `classification_type` 分组的逻辑（`_registry.py:173-178`）不变——只是某源现在可能贡献多条 observation。

**同源去重（回应评审 Finding 3）**：`CsvSource.load()` 累积时按去重键 `(classification_type, verdict, malware_name)` 去重（source 由实例隐含）。这样 ThreatFox 对同一 IP 的重复行（相同 `threat_type`）合并成一条 observation，不同 `threat_type` 仍各自累积成多元素 list。去重在 load 阶段做（一次），不在每次 query 做。

### 3. `_classification.py`：词表 + 映射帮手

```python
# IntelMQ classification.type 子集（IP 威胁情报相关），可扩展。
# 治理：新增类型走 PR review + 在此注释里说明含义；不引入独立 YAML/版本号流程（YAGNI）。
CLASSIFICATION_TYPES = frozenset({
    "blacklist","c2-server","malware-distribution","malware",
    "scanner","brute-force","phishing","botnet","exploit",
    "proxy","tor","vulnerable-system","misconfiguration",
    "abuse-reports","spam","ddos","other",
})

THREATFOX_MAP = {
    "botnet_cc":"c2-server","payload_delivery":"malware-distribution",
    "payload":"malware","cc_skimming":"phishing",
}
BLOCKLIST_DE_MAP = {  # 实现时按 blocklist.de 官方 attack-type 码核实补全
    "ssh":"brute-force","mail":"spam","bots":"botnet",
    "bruteforcelogin":"brute-force","apache":"scanner",  # … 待核实
}
OTX_MAP: dict[str, str] = {}  # OTX pulse threat_type → IntelMQ；T5 据 REST 实际返回值补全

def normalize(raw_type: str, mapping: dict, default="blacklist") -> str:
    """原生类别 → IntelMQ classification.type；未知值回退 default，保证落在词表内。"""
    v = mapping.get((raw_type or "").strip().lower(), default)
    return v if v in CLASSIFICATION_TYPES else "other"
```

新源：声明一个 `{native:intelmq}` 映射表，`parse_row` 里一行 `normalize(raw, MAP)` 接入。

## 各源迁移

| 源 | 改动 | 分类来源 |
|---|---|---|
| **ThreatFox** | `parse_row` 用 `normalize(_clean(row[4]), THREATFOX_MAP)` 替代硬编码 `c2-server`；保留 `malware_name`/`confidence`/`first_seen` 逐行 | `threat_type` 列（已验证分布） |
| **blocklist_de** | 从 `lists/all.txt` 改为按 attack-type 拉多个 `lists/<type>.txt`，每类用 `normalize` 映射；多列表下载 + 去重 + 按 CIDR 累积 | attack-type 码（⚠️ **T4 前先核实**官网 export 页的类别码/URL，记录映射来源，加冒烟测试断言各类别覆盖率不下降） |
| **emerging_threats** | 仅契约升级（list-per-CIDR），逻辑不变 | 诚实单标签 `blacklist`（数据无类别） |
| **OTX** | **gated**：依赖 REST `/pulses/subscribed` 改造（见上轮调查）。改造后每个 pulse indicator 带 `threat_type`/`malware_family` → `normalize(., OTX_MAP)` | pulse 自带类别 |
| **firehol** | 契约适配：`load()` 改存 `[dict]`（继承新 query 必须 list） | 不变（`blacklist`） |
| **ip2proxy** | 契约适配：删 `query()` override + `load()` 改存 `[evidence]`（override 仅为绕 bug，基类修好后冗余）；`is_proxy`/`is_hosting` 被 §2 忽略（明示 drop） | 不变（`proxy`/`tor`） |

## verdict 分组决策（折入评审 #3）

当前 `_registry.py:173` 只按 `classification_type` 分组，`_assess_classification` 取 `obs[0].verdict`。若同 type 出现冲突 verdict（malicious vs benign），后者被静默覆盖。

**本 spec 范围内的源 verdict 是均匀的**（threat 类全 `malicious`，proxy 类全 `suspicious`），冲突**当前不会发生**。但评审 Finding 2 指出：保留 `obs[0].verdict` 的"首条赢 + 仅 warning"会留下**静默覆盖**——未来接入 benign 源会悄悄改变结果，warning 阻止不了数据丢失。因此改为**确定性 + 显式暴露**：

- 实现：分组仍按 `classification_type`（不改 schema 分键）。`_assess_classification` 内对同 type 的多条 observation，按**确定性优先级**选 verdict：`malicious > suspicious > benign > informational`（不再"首条赢"）。
- 暴露：`ClassificationAssessment` 新增 `verdict_conflict: bool = False`（默认 False，向后兼容）+ `to_dict()` 输出该字段。同 type 出现 ≥2 不同 verdict 时置 True。
- 不改 `classifications` dict 的 key（仍按 type），**无 API/前端破坏性变更**；新增字段为附加信息。
- 后续：真正的 `(type, verdict)` 双键分桶（让 malicious/benign 各成独立条目）仍**与 benign 在线源绑定**另立，不在本 spec 抢跑。

## 新源模板（更新 fusion 设计文档的"接源"章节）

```python
class NewSource(IpListSource):               # 或 CsvSource
    name = "newsrc"
    classification_type = "blacklist"         # 单类别源：类级默认即可
    verdict = "malicious"
    reliability = 0.8
    authoritative_for = []
    # 多类别源：override parse_row，逐条 normalize(raw, MAP) 发 classification_type
```

两条路：**单类别源**用类级默认；**多类别源**在 `parse_row` 逐条映射。新 classification 值加进 `CLASSIFICATION_TYPES` + `stix_export` 的 type→indicator_type 映射（沿用 fusion 设计既有规则）。

## 分期实施（TDD）

1. **T1 契约修复**：`_base.py` query/load 改 list-per-CIDR；`lookup()` 归一化；**`firehol.load` 改存 list + `ip2proxy` 删自定义 query 并 load 改 list**；新增 query 返回形状回归测试。
   - 验证：query 返回 list；CsvSource 同 IP 多 threat_type → list 多元素；标量源不受影响；firehol/ip2proxy 契约一致。
2. **T2 词表**：`_classification.py` + 各映射表 + `normalize()`。
   - 验证：映射正确；未知值回退 `blacklist`/`other`；非词表值不外泄。
3. **T3 ThreatFox 逐条**：`parse_row` 用 `threat_type` 映射。
   - 验证：botnet_cc→c2-server、payload_delivery→malware-distribution、同 IP 双类型 → 2 observations；malware_name/confidence/first_seen 到达引擎。
4. **T4 blocklist_de 逐类**：核实 attack-type 码 → 改下载为多列表 → 映射。
   - 验证：每类 IP 标注正确；多列表合并去重。
5. **T5 OTX 逐条**（gated on REST 改造）：pulse `threat_type` → `normalize(., OTX_MAP)`。
   - 验证：pulse 类别正确映射，不再全标 c2-server。
6. **T6 verdict 确定性选择 + 端到端**：`_assess_classification` 按 malicious>suspicious>benign>informational 选 verdict + `verdict_conflict` 标记；真实 IP 查询显示正确逐条分类；跨源复核产出多 type；单类别源/标量源回归正常。
   - 验证：同 type 冲突 verdict 时取恶意优先、`verdict_conflict=True`；无静默覆盖。
7. **T7 文档**：更新 fusion 设计"接源模板"章节 + README。

## 测试

- **单元**：`query()` 返回存储 list；`normalize` 映射 + 回退；同 CIDR 多类型 → list 多元素；`to_observation` 优先用 raw 的 classification_type。
- **集成**：已知 ThreatFox IP 不再被错误标 c2-server；blocklist_de 各类正确；跨源复核。
- **回归**：tor/vpn/ET 单类别源正常；标量字段（country/asn/as_name/ip_range）不受影响；`classifications` dict 结构不变 → API/前端无破坏。
- **T1 关键回归**：`test_base_sources.py` 当前断言 `query(...) == {"is_malicious": True}`，T1 后需更新为新契约。

## 风险与应对

| 风险 | 应对 |
|---|---|
| pytricia list 值 + freeze/pickle | list 可序列化；T6 验证冷启动（性能优化属 B 组，本 spec 只保证不破坏） |
| blocklist_de 类别码未知 | T4 实现时核实官网 export 页，映射表据实填 |
| OTX 依赖 REST 改造 | T5 gated，可独立后置 |
| list 包装内存（~8MB） | 相对几百 MB 数据可忽略 |
| verdict 冲突 | 改为确定性优先级（恶意优先）+ `verdict_conflict` 标记，消除静默覆盖；不改 dict 分键，无 schema 破坏 |
| API/前端破坏 | `classifications` 结构不变 |

## 评审反馈处理记录

针对 `2026-06-14-multi-source-evidence-fusion-design.md` 的整体评审报告，经核实代码后分类处理：

**折入本 spec**：#2 词表治理（轻量版，Python 模块 + 注释，不做 YAML 版本化）、#3 verdict 冲突（看门 + 跟踪）。

**另立跟踪（B 组，不纳入本 spec）**：#5 复核权重 + PCR6 死代码接线、#8 STIX 边界、#9 性能、#7 在线源配额。

**push back（C 组）**：
- #1 旧布尔兼容层：布尔已从 `lookup()` 移除，仅残留 `authoritative_for=["is_malicious"]` 字符串 + `_merge.py:111` 中央 `AUTHORITATIVE_SOURCES`（fusion 设计 T3 应删未删）。无数据库持久化，不加兼容层，除非确认有外部 API 消费者依赖旧布尔。
- #4 `extra` 安全白名单：grep 确认**无源填 `extra`**，YAGNI，等 Shodan/GreyNoise 源再说。
- #6 保留中央 reliability 配置：与 fusion 设计 T3"删中央字典读源属性"**直接矛盾**，不采纳。
- #11 Alembic schema 迁移：核实**无数据库 / 无 SQL / 无 Alembic**（flat files + pytricia 内存树），不适用。
- #12 日志合规：工具不持久化查询日志，超出本 spec 范围。

### Codex adversarial review（needs-attention，3 findings，均已折入）

- **F1（契约 vs 自定义源，严重）**：§1 新增**源契约盘点表**，逐一列出每个源的基类/load/query/trie 形状 + §1 动作；T1 显式改 `firehol.load` 存 list、删 `ip2proxy` 自定义 query 并 load 改 list；新增 query 返回形状回归测试。
- **F2（verdict 静默覆盖）**：由"看门 warning"改为**确定性优先级**（恶意优先）+ `ClassificationAssessment.verdict_conflict` 标记，消除静默覆盖。
- **F3（blocklist_de 未核实 + 同源去重）**：T4 前先核实 attack-type 码/URL + 加覆盖率冒烟测试；`CsvSource.load` 累积按 `(classification_type, verdict, malware_name)` 去重。

## 不在范围内（明确）

- 单 IP 全量相关性图 / Event / 多租户（fusion 设计 Scope Guard 已排除）。
- B/C 组各项（见上）。
- IPv6 支持。
