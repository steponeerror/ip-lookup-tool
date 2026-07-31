# manage-intel-source Skill Design

**Date:** 2026-07-31
**Status:** Approved (brainstorm + grill 完成,待 spec review → writing-plans)

## Goal

固化「加源 → 评估 → 调优」全闭环为可复现的 skill,让没有上下文的新会话(或别人)能照着走完整流程,且判断标准一致、可复现。

## 背景

2026-07-31 走完一遍闭环:加 ciarm/bruteforce/greensnow 三个新源,用 net-impact harness 评估全部 23 个源,优化 5 处权重。过程暴露多个坑(见 §决策记录)。现有 skill 覆盖了「发现」(`discover-intel-sources`)和「加源」(`add-intel-source` Phase 1-4),但缺「评估 + 调优」段,且 `add-intel-source` 的 Phase 4 目前只到「跑测试」,没接 eval 和权重决策。

## 动机

**标准化:新会话/别人可复现**(用户决策)。非自用(否则不必固化)、非通用化(绑定 ip-lookup-tool 的 harness/源系统,YAGNI)。

## 范围

**包含**:
1. 新 skill `manage-intel-source`(orchestration + eval + 调优决策)。
2. 一个 harness 修复:`verdict.assess` 识别 asset 源标 N/A(决策 1)。

**不包含**(非目标):
- 改 `discover-intel-sources` / `add-intel-source`(引用,不复述)。
- 修 corpus 偏向(geo 源 INSUFFICIENT 的根因,更大范围,另案)。
- 通用化到其他项目。

## skill 身份

- **名字**:`manage-intel-source`(与 discover-intel-sources / add-intel-source 同系列)
- **触发**:用户想加新源 / 评估某源净影响 / 优化源池权重
- **职责**:编排全闭环 + eval + 调优决策;**引用** discover-intel-sources(发现)/ add-intel-source(加源实现),不复述

## 编排流程(主 SKILL.md)

```
discover(发现候选)
  → 多维验活(三分类:真死/换URL/受限)
  → add(Phase 1-4 加源)
  → download + eval(harness 评估)
  → verdict 决策(全 lever 表)
  → 权威源第三方校准(权重依据)
  → 停止信号检查(到边际则转优化)
```

## references/

### `verdict-action.md`(决策 3 + 5)

**全 lever 表**(不只降权):

| verdict | action |
|---|---|
| POSITIVE-VERIFIED | 留,维持权重 |
| POSITIVE-UNVERIFIED | 降权(权威源例外,见分档表) |
| MIXED | 查 cost lever:conflict→查冲突源;fp→tighten load-time noise filter 或 disable;other 膨胀→收紧 `_MAP` |
| MARGINAL | 非权威→降权/精简;权威(is_malicious 等)→不动 |
| NEGATIVE | disable |
| INSUFFICIENT-SAMPLE | 补样本/换 corpus(别误判源差) |

**明示警告**:降权是 **weight-invariant** 的——只改 fusion 数值话语权 + STIX `x_reliability`,**不改 verdict、不改该源贡献的 IP**。想真正改变采用状态(misp 别再报 fp / 问题源别贡献)必须 disable / tighten / 精简数据。

**数值分档表**(决策 3,混合依据):
- 权威 curated(spamhaus/ET/abuseipdb/threatfox/feodo):0.85-0.90
- 社区聚合(otx/firehol/ipsum/blocklist_de/binarydefense/urlhaus/tweetfeed):0.50-0.70
- asset 权威(tor_exits/x4bnet_vpn):0.70-0.95
- UNVERIFIED 在所属档内 **-0.10~0.15**
- **权威源(abuseipdb 等)即使 UNVERIFIED 也保持中高(≥0.65),别深度降**——CG=0 对权威源是「独家发现」(独立 IP 池不被其他源覆盖)而非「不可信」;具体数值结合第三方校准 + 用户判断,**不只靠分档推算**(默认推算可能偏低)
- 权威源(影响大)额外查第三方实测校准(见 third-party-calibration.md)

**~~asset 源例外~~ 删除**——harness 修复后(决策 1)asset 源 verdict 是 N/A,不触发 UNVERIFIED 流程。

### `eval-harness.md`(决策 2)

- **eval 前先 `source.download()`**(显式前置步骤)。eval 保持纯计算(快/确定/reproducible),不引入网络 side-effect。download 失败在 download 步早发现,不污染 eval。
- metrics 解读:MC(去源丢多少)、CG(独立佐证)、OC(冗余)、fp(benign 误伤)、other(分类膨胀)、dead_slot_fill、confidence_uplift。
- INSUFFICIENT-SAMPLE 多为 corpus 偏向(geo/asn 源 IP 不在威胁 corpus),不是源差。

### `empirical-liveness.md`(决策 4)

- **验活流程**:curl 4 组合(直连/代理 × bot UA/浏览器 UA)→ 全 FAIL 则 jina reader 验站点(`r.jina.ai/URL`,绕本地网络)→ 三分类判定。
- **三分类**:
  - 真死(站点死/域名挂售/作者停更)→ 排除,附证据(firehol issue / GoDaddy 挂售 / 作者声明)
  - 换 URL(如 greensnow 旧 `/list` 404)→ Exa 搜新 URL,找到则正常加
  - 站点活但本地拉不到(403 / IPv6 / 需注册)→ 标「访问受限,不加」(download 会失败→INSUFFICIENT),记原因留待修
- **红线**:不凭一次 curl FAIL 判死(避免 greensnow 错判重演)。
- 受限源(如 bambenek)默认放弃 + 记录(修的 ROI 不确定,每个受限源都修会拖慢闭环)。

### `third-party-calibration.md`(决策 3)

- 工具:agent-reach(Exa search + jina reader + Reddit/gh CLI)。
- **触发**:权威源权重决策前(SOURCE_RELIABILITY 调整时)。
- 查 VBSpam 独立实测 / 学术横向(ACNS 等)/ Reddit 口碑;区分官方声称 vs 第三方实测。
- 案例:Spamhaus(VBSpam FP≤0.01% 支撑 0.90)/ ET(ACNS'20 timeliness 平庸 → 0.85)。

## 停止信号(主 SKILL.md 一段,决策 6)

满足任一 → skill 提示「加源到边际,建议转优化现有(降权/查 MIXED/权威源校准),ROI 更高」:
1. **候选池枯竭**:连续 N 个候选都是死源 / 受限 / 换链找不到。
2. **信号增益递减**:新增源 verdict 连续 NEGATIVE / MARGINAL / 高 OC 冗余。
3. **约束触顶**:剩余候选都要 key/付费,超出当前约束。

原则:硬凑数量 = 加噪音,违背 preserve signal/filter noise(项目主旨)。

## harness 修复(决策 1,独立小改)

`verdict.assess` 识别 asset 源(查 `AUTHORITATIVE_SOURCES` 的 is_tor/is_vpn/is_proxy/is_hosting/is_mobile 字段)→ 标 `N/A — asset 源不走 corroboration`,而非 UNVERIFIED。

理由:CG(独立 corroboration gain)对 asset 字段无意义(asset 是该源独占的 ground truth,不需佐证)→ asset 源必然 UNVERIFIED 是结构性 bug,不是真"不可信"。

验收:`tor_exits` / `x4bnet_vpn` eval 出 N/A(不是 UNVERIFIED);加单元测试覆盖 asset 源路径。

## 决策记录(6 个,含备选与理由)

| # | 决策点 | 选定 | 备选(未选理由) |
|---|---|---|---|
| 1 | asset 源 verdict 错位 | **修 harness**(asset 标 N/A) | skill 兜底例外(例外随 asset 源膨胀,harness bug 永存) |
| 2 | eval + download | **skill 编码前置**(eval 保持纯) | 修 harness 自动 download(破坏 eval 确定性,网络 side-effect 混入,CI 抖动) |
| 3 | 数值依据 | **混合**(分档表 + 权威源第三方校准) | 纯主观分档(无客观基准)/ 全第三方(每源查太贵,多数无公开实测) |
| 4 | 验活深度 | **多维 + 三分类** | 单维 curl(误判 greensnow)/ 只 jina(本地拉不到的加了也 INSUFFICIENT) |
| 5 | verdict→action | **全 lever 表** | 只降权(对 MIXED/NEGATIVE 无效,降权不改 verdict) |
| 6 | 停止加源 | **信号清单** | 不编码(新会话无限凑噪音)/ 数量阈值(武断,数量≠质量) |

## 测试 / 验收

- **harness 修复**:`tor_exits` / `x4bnet_vpn` eval 输出 N/A;asset 源路径单元测试。
- **skill**:新会话(或 grill 复盘)照 skill 能走完整闭环,判断标准可复现(同源同 verdict → 同 action,不依赖运行时手感)。

## 实现顺序建议(给 writing-plans)

1. harness 修复(决策 1)——独立小改,先落地,skill 的 asset 例外才能删。
2. skill 主 SKILL.md + 4 个 references。
3. 用 skill 跑一遍(加一个新源,验证流程)。
