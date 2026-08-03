# manage-intel-source Skill + Harness Asset-Verdict Fix — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 实现 `manage-intel-source` skill(编排加源→评估→调优全闭环,可复现)+ 修 harness 的 asset 源 verdict 错位(asset 源标 N/A 而非 UNVERIFIED)。

**Architecture:** 一个 harness 小改(`verdict.assess` 加 `source_category` 参数,caller 查 `SOURCE_CATEGORIES` 传入) + 一个项目级 skill(`.claude/skills/manage-intel-source/`:SKILL.md + 4 references)。skill 引用现有 `discover-intel-sources` / `add-intel-source`,不复述。

**Tech Stack:** Python 3.10+ / pytest(harness 修复);Markdown + YAML frontmatter(skill 文件)。

## Global Constraints

- skill 放 `.claude/skills/manage-intel-source/`(项目级,git tracked,正常 `git add`)。
- `verdict.assess` 加 `source_category: str = "threat"` 参数(默认值保证现有 caller 不传时行为不变)。
- **`verdict.py` 不能 import `ipdb._registry`**(循环依赖)——`source_category` 由 caller(`__main__.py:run_for_source`)查 `SOURCE_CATEGORIES` 后传入。
- 测试从 `backend/` cwd 跑(`cd backend && python -m pytest ...`)。
- 已知无关 flaky:`test_source_mgmt::test_refresh_stale`(异步 timing)、`test_quota_thread_safety`(quota 950-vs-1000 漂移)——别当回归。
- spec(source of truth):`docs/superpowers/specs/2026-07-31-manage-intel-source-design.md`。
- skill 文件内容以 spec 的 6 个决策为依据;本 plan 给关键骨架,实现时照 spec §references 补全细节。

---

### Task 1: harness 修复 — asset 源 verdict N/A

**Files:**
- Modify: `backend/ipdb/_eval/verdict.py`(`assess` 加 `source_category` 参数 + asset 早返回;`_ACTION` 加 `N/A-ASSET`)
- Modify: `backend/ipdb/_eval/__main__.py`(`run_for_source` 查 `SOURCE_CATEGORIES` 传入)
- Test: `backend/test_eval_verdict.py`(加 asset 测试)

**Interfaces:**
- Produces: `assess(metrics, candidate_touched_n, suspicion_flags, source_category="threat") -> Verdict`;新 `Verdict.state == "N/A-ASSET"`(asset 源路径)。

- [ ] **Step 1: 写失败测试**

在 `backend/test_eval_verdict.py` 末尾加:

```python
def test_asset_source_returns_na_verdict():
    # asset 源(is_tor/is_vpn/...)是独占 ground truth,CG(独立 corroboration)不适用
    # → verdict 应是 N/A-ASSET,不是 UNVERIFIED
    v = assess({}, candidate_touched_n=100, suspicion_flags=[], source_category="asset")
    assert v.state == "N/A-ASSET"
    assert v.insufficient is False
    assert v.verified is False
    assert "does not apply" in v.action
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cd backend && python -m pytest test_eval_verdict.py::test_asset_source_returns_na_verdict -v`
Expected: FAIL(`assess() got an unexpected keyword argument 'source_category'`,或 state 不匹配)

- [ ] **Step 3: 改 `verdict.py`**

`_ACTION` dict 加一条(在 `INSUFFICIENT-SAMPLE` 后):

```python
    "N/A-ASSET":            "Asset source (is_tor/is_vpn/is_proxy/is_hosting/is_mobile): these are this source's ground truth — CG (independent corroboration) does not apply. Weight via AUTHORITATIVE_SOURCES, not this verdict.",
```

`assess` 签名加参数 + asset 早返回(在 `candidate_touched_n < N_FLOOR` 判断**之前**):

```python
def assess(metrics: dict[str, Metric], candidate_touched_n: int,
           suspicion_flags: list, source_category: str = "threat") -> Verdict:
    if source_category == "asset":
        return Verdict(state="N/A-ASSET", benefit_high=False, cost_high=False,
                       verified=False, insufficient=False,
                       suspicion_flags=suspicion_flags,
                       action=_ACTION["N/A-ASSET"])

    if candidate_touched_n < config.N_FLOOR:
        ...  # 原逻辑不动
```

- [ ] **Step 4: 改 `__main__.py` 传 category**

`run_for_source` 里(`verdict = assess(metrics, candidate_touched, flags)` 那行,约 line 84)改为:

```python
    from ipdb._registry import SOURCE_CATEGORIES
    category = SOURCE_CATEGORIES.get(source_name, "other")
    verdict = assess(metrics, candidate_touched, flags, source_category=category)
```

(lazy import 避免模块加载副作用;`SOURCE_CATEGORIES` 已含 `"tor_exits"/"x4bnet_vpn"/"ip2proxy": "asset"`。)

- [ ] **Step 5: 跑测试 + 全 suite + 端到端验证**

Run:
```bash
cd backend
python -m pytest test_eval_verdict.py -q
python -m pytest -q 2>&1 | tail -5    # 全 suite,确认无新失败(允许已知 flaky)
python -m ipdb._eval tor_exits 2>&1 | grep -vE "INFO|WARNING" | tail -2   # 应输出 N/A-ASSET
```
Expected: asset test PASS;全 suite 仅已知 flaky;`tor_exits` eval 输出 `N/A-ASSET`(不再是 `POSITIVE-UNVERIFIED`)。

- [ ] **Step 6: Commit**

```bash
git add backend/ipdb/_eval/verdict.py backend/ipdb/_eval/__main__.py backend/test_eval_verdict.py
git commit -m "fix(eval): asset sources get N/A-ASSET verdict (CG doesn't apply)"
```

---

### Task 2: skill scaffold + SKILL.md

**Files:**
- Create: `.claude/skills/manage-intel-source/SKILL.md`

**Interfaces:**
- Produces: 可被 Skill 工具 invoke 的 `manage-intel-source` skill。

- [ ] **Step 1: 写 SKILL.md**

```markdown
---
name: manage-intel-source
description: Use when the user wants to add a new intel source AND evaluate its net impact on the fused intelligence, or to optimize the existing source pool's weights, or to run the full discover→add→evaluate→tune lifecycle for threat/asset/geo sources. Orchestrates discover-intel-sources (find candidates) + add-intel-source (implement) + the net-impact eval harness + weight tuning. NOT for implementing a single already-chosen source (use add-intel-source) or just listing candidates (use discover-intel-sources).
---

# Managing an Intelligence Source's Full Lifecycle

This skill orchestrates the full闭环: **discover → 验活 → add → evaluate → tune**.
It引用 `discover-intel-sources` / `add-intel-source`(不加源实现,不复述),
并补齐 harness 评估 + verdict 驱动的权重调优段。

## 5-minute mental model

1. **discover** — invoke `discover-intel-sources` 找候选。
2. **验活** — 多维验活(curl 4 组合 + jina),三分类(真死/换URL/受限)。见 `references/empirical-liveness.md`。
3. **add** — invoke `add-intel-source` Phase 1-4 加源。
4. **evaluate** — `download` 后 `python -m ipdb._eval <source>`。见 `references/eval-harness.md`。
5. **tune** — verdict → action(全 lever 表 + 数值分档)。见 `references/verdict-action.md`;权威源查第三方实测(见 `references/third-party-calibration.md`)。

## 停止加源信号(到边际则转优化)

满足任一,提示用户「加源到边际,建议转优化现有(降权/查 MIXED/权威源校准),ROI 更高」:
1. **候选池枯竭** — 连续几个候选都是死源/受限/换链找不到。
2. **信号增益递减** — 新增源 verdict 连续 NEGATIVE/MARGINAL/高 OC 冗余。
3. **约束触顶** — 剩余候选都要 key/付费。

原则:硬凑数量 = 加噪音,违背 preserve signal/filter noise。

## 边界

- `discover-intel-sources`:发现/比较候选(本 skill 调用,不改)。
- `add-intel-source`:加源实现 Phase 1-4(本 skill 调用,不改)。
- **本 skill**:编排 + eval + 调优决策(新增)。

## 详细参考

- `references/verdict-action.md` — verdict → action 全 lever 表 + 数值分档 + weight-invariant 警告
- `references/eval-harness.md` — download→eval 流程 + metrics 解读
- `references/empirical-liveness.md` — 多维验活 + 三分类
- `references/third-party-calibration.md` — 权威源权重前的第三方实测查证
```

- [ ] **Step 2: 验证关键内容**

Run: `grep -c "停止加源信号\|verdict-action\|discover-intel-sources" .claude/skills/manage-intel-source/SKILL.md`
Expected: ≥3(三处关键词都在)。

- [ ] **Step 3: Commit**

```bash
git add .claude/skills/manage-intel-source/SKILL.md
git commit -m "feat(skill): manage-intel-source SKILL.md (orchestrator + stop signals)"
```

---

### Task 3: `references/verdict-action.md`

**Files:**
- Create: `.claude/skills/manage-intel-source/references/verdict-action.md`

- [ ] **Step 1: 写文件**

内容(完整,照 spec §verdict-action.md):

```markdown
# Verdict → Action(全 lever 表)

## weight-invariant 警告(先读)

降 SOURCE_RELIABILITY **不改 verdict、不改该源贡献的 IP**,只改 fusion 数值话语权 + STIX `x_reliability`。
想真正改变采用状态(问题源别贡献 / misp 别报 fp)必须 **disable / tighten noise filter / 精简数据**,光降权对 MIXED/NEGATIVE 无效。

## 全 lever 表

| verdict | action |
|---|---|
| POSITIVE-VERIFIED | 留,维持权重 |
| POSITIVE-UNVERIFIED | 降权(权威源例外,见下) |
| MIXED | 查 cost lever:conflict→查冲突源;fp→tighten load-time noise filter 或 disable;other 膨胀→收紧 `_MAP` |
| MARGINAL | 非权威→降权/精简;权威(is_malicious 等)→不动 |
| NEGATIVE | disable |
| INSUFFICIENT-SAMPLE | 补样本/换 corpus(别误判源差;多为 corpus 偏向,geo 源 IP 不在威胁 corpus) |
| N/A-ASSET | asset 源(is_tor/is_vpn/...)——不走 corroboration,按 AUTHORITATIVE_SOURCES 权威加权,不降 |

## 数值分档表(混合依据:分档 + 权威源第三方校准)

| 类型 | 基线 | 例 |
|---|---|---|
| 权威 curated | 0.85–0.90 | spamhaus, emerging_threats, threatfox, feodo, abuseipdb |
| 社区聚合 | 0.50–0.70 | otx, firehol, ipsum, blocklist_de, binarydefense, urlhaus, tweetfeed |
| asset 权威 | 0.70–0.95 | tor_exits, x4bnet_vpn, ip2proxy |

- UNVERIFIED 在所属档内 **-0.10~0.15**。
- **权威源(abuseipdb 等)即使 UNVERIFIED 也保持中高(≥0.65),别深度降**——CG=0 对权威源是「独家发现」(独立 IP 池)而非「不可信」;具体数值结合第三方校准 + 用户判断,不只靠分档推算。
- 权威源(影响大)额外查第三方实测(见 `third-party-calibration.md`)。

## 案例(2026-07-31)

- abuseipdb UNVERIFIED CG=0 → 0.75→0.65(权威,用户判断,不深度降)
- otx UNVERIFIED CG=0 → 0.75→0.55(社区)
- emerging_threats VERIFIED 但 ACNS'20 实测平庸 → 0.90→0.85(第三方校准下调)
- spamhaus MARGINAL OC=1.0 但 is_malicious 权威 → 0.90 不动
- tor_exits/x4bnet_vpn → N/A-ASSET(harness 修复后)
```

- [ ] **Step 2: 验证 + Commit**

```bash
grep -c "weight-invariant\|全 lever\|分档" .claude/skills/manage-intel-source/references/verdict-action.md  # ≥3
git add .claude/skills/manage-intel-source/references/verdict-action.md
git commit -m "feat(skill): verdict-action reference (full lever + tiers + weight-invariant)"
```

---

### Task 4: `references/eval-harness.md`

**Files:**
- Create: `.claude/skills/manage-intel-source/references/eval-harness.md`

- [ ] **Step 1: 写文件**

```markdown
# Eval Harness 用法

## download 前置(eval 保持纯)

`load_db()` 只 load 已有数据文件,**不 download**。新源第一次必须显式 download,否则候选采样为空 → INSUFFICIENT-SAMPLE(假象)。

```python
from ipdb._registry import _sources
s = next(x for x in _sources if x.name == "<source>")
s.download()        # 显式前置
s.load()
print(s.health())   # 确认 record_count > 0、is_stale=False
```

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

多为 corpus 偏向(geo/asn 源 IP 不在威胁 corpus),不是源差。例:cn_isp/iptoasn/ipinfo_lite(geo)、feodo/ip2proxy/stopforumspam(数据少或 IP 不在样本)。处理:补样本 / 换 corpus / 接受(geo 源本就不靠威胁 corpus 评估)。
```

- [ ] **Step 2: 验证 + Commit**

```bash
grep -c "download 前置\|metrics 解读\|INSUFFICIENT" .claude/skills/manage-intel-source/references/eval-harness.md  # ≥3
git add .claude/skills/manage-intel-source/references/eval-harness.md
git commit -m "feat(skill): eval-harness reference (download-first + metrics + insufficient)"
```

---

### Task 5: `references/empirical-liveness.md`

**Files:**
- Create: `.claude/skills/manage-intel-source/references/empirical-liveness.md`

- [ ] **Step 1: 写文件**

```markdown
# 实证验活(排除死源 / 换链 / 受限)

## 红线:不凭一次 curl FAIL 判死

2026-07-31 教训:greensnow 旧 `/list` 返回 404,曾误判「停运」,实际是换链接了(blocklist.greensnow.co)。必须多维验活 + 分类。

## 验活流程

1. **curl 4 组合**(直连 / 代理 × bot UA / 浏览器 UA):

```bash
UA_BOT="ip-lookup-tool/0.1"; UA_REAL="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"; PX="http://127.0.0.1:10809"
probe() {
  name="$1"; u="$2"
  for ua in "$UA_BOT" "$UA_REAL"; do
    for px in "" "$PX"; do
      args=(-fsSL -m 10 -A "$ua"); [ -n "$px" ] && args+=(-x "$px")
      curl "${args[@]}" "$u" -o "/tmp/p_$name" 2>/dev/null && { echo "$name OK"; return 0; }
    done
  done
  echo "$name FAIL all 4"; return 1
}
```

2. **全 FAIL → jina reader 验站点是否真活**(绕本地网络):

```bash
curl -s -m 15 "https://r.jina.ai/<URL>" | head -10    # 看 Title / HTTP 状态 / 正文
```

3. **三分类判定**(见下表)。

## 三分类

| 分类 | 判据 | action | 证据 |
|---|---|---|---|
| **真死** | 站点死 / 域名挂售 / 作者声明停更 | 排除 | firehol issue / GoDaddy forsale / 作者首页声明 |
| **换 URL** | 站点活但旧路径 404 | Exa 搜新 URL,找到则正常加 | 新 URL 返回 200 + 数据 |
| **站点活但本地拉不到** | jina 通但本地 curl 4 组合全 FAIL(403 / IPv6 / 需注册) | 标「访问受限,不加」+ 记原因 | HTTP 403 / DNS 只解析 IPv6 / 401 missing_api_key |

## 工具

- Exa 搜新 URL:`mcporter call 'exa.web_search_exa(query: "...", numResults: 5)'`(agent-reach skill)
- jina 读:`curl -s "https://r.jina.ai/<URL>"`
- gh 搜社区证据:`gh search issues "<source> discontinued"`

## 案例(2026-07-31)

- cruzit:域名 GoDaddy 挂售 + firehol #304 站长停运声明 → **真死,排除**
- nothink:作者首页 "data is no longer shared" → **真死,排除**
- greensnow:旧 /list 404,Exa 找到 blocklist.greensnow.co/greensnow.txt(200,3677 IP) → **换 URL,加**
- bambenek:站点活但 403(本地 + 代理都拉不到) → **受限,放弃 + 记录**(顶级 C2,但修 ROI 不确定,每个受限源都修会拖慢闭环)
- sans:DNS 只解析 Cloudflare IPv6(WSL IPv6 不通)+ jina 空 → **受限,放弃**
```

- [ ] **Step 2: 验证 + Commit**

```bash
grep -c "三分类\|不凭一次\|jina" .claude/skills/manage-intel-source/references/empirical-liveness.md  # ≥3
git add .claude/skills/manage-intel-source/references/empirical-liveness.md
git commit -m "feat(skill): empirical-liveness reference (4-combo + 3-class + cases)"
```

---

### Task 6: `references/third-party-calibration.md`

**Files:**
- Create: `.claude/skills/manage-intel-source/references/third-party-calibration.md`

- [ ] **Step 1: 写文件**

```markdown
# 权威源权重的第三方实测校准

## 何时查

权威源(SOURCE_RELIABILITY 影响最大的:spamhaus/emerging_threats/threatfox/feodo/abuseipdb 等)在**调整权重前**,用第三方独立实测支撑/质疑数值。非权威/社区源不必(分档表够)。

## 工具(agent-reach skill)

- Exa 搜:`mcporter call 'exa.web_search_exa(query: "...", numResults: 5)'`
- jina 读全文:`curl -s "https://r.jina.ai/<URL>"`
- Reddit:`opencli reddit search "..." -f yaml` 或 `rdt search "..." --limit 10`
- gh 搜学术 repo:`gh search repos "threat intelligence benchmark"`

## 查什么

1. **独立实测**(非官方):FP 率、检测率、precision。关键查询:"Spamhaus false positive rate independent study" / "threat intelligence feed comparison benchmark"。
2. **学术横向**:多源对比论文(如 ACNS'20 feed quality、CAIDA PAM'22)。
3. **社区口碑**:Reddit r/netsec / r/sysadmin 实战评价。
4. **独立 tier list**:如 decryptiondigest(看是否在 Tier 1)。

## 红线

- **区分官方声称 vs 第三方实测**。Spamhaus 官网自称「FP 极低」不算第三方实证;VBSpam 独立实测 FP≤0.01% 才算。
- 某项找不到第三方实测就明说「无公开第三方实测」,别用官方数字冒充。

## 案例(2026-07-31)

- **Spamhaus** 维持 0.90:VBSpam 2013/2016 独立实测捕获 95%、FP 0.00-0.01%;CAIDA PAM'22 称「最受尊敬的封锁列表之一」;Reddit 实战阻断数与僵尸网络执法同步衰减。
- **Emerging Threats** 0.90→0.85:ACNS'20 学术横向(14 月 24 源)timeliness「意外平庸」,未进第一梯队;decryptiondigest 未列入 Tier 1;2022 有公开 FP 事故(规则 2014702/2014703)。0.90 与实测定位不匹配。

## 来源清单(可核实)

- VBSpam: https://www.virusbulletin.com/uploads/pdf/magazine/2016/201605-vbspam-comparative.pdf
- ACNS'20 feed 横向: https://www.cyber-threat-intelligence.com/publications/ACNS2019-feedtimelineness.pdf
- CAIDA PAM'22: https://www.caida.org/catalog/papers/2022_stop_drop_roa/stop_drop_roa.pdf
- decryptiondigest tier list: https://www.decryptiondigest.com/blog/free-threat-intelligence-sources-ranked
```

- [ ] **Step 2: 验证 + Commit**

```bash
grep -c "第三方实测\|官方声称\|VBSpam\|ACNS" .claude/skills/manage-intel-source/references/third-party-calibration.md  # ≥3
git add .claude/skills/manage-intel-source/references/third-party-calibration.md
git commit -m "feat(skill): third-party-calibration reference (authoritative weight evidence)"
```

---

### Task 7: 端到端验证(skill 跑一遍)

**Files:** 无(验证 only)

- [ ] **Step 1: 确认 skill 可被发现**

Run: `ls .claude/skills/manage-intel-source/ && ls .claude/skills/manage-intel-source/references/`
Expected: SKILL.md + 4 references 都在。

- [ ] **Step 2: invoke skill 走一遍(回顾这轮)**

在新会话(或当前)invoke `manage-intel-source`,对照这轮工作(加 ciarm/greensnow/bruteforce + 优化权重)验证:
- 编排流程(design→验活→add→eval→tune)清晰可循。
- verdict-action 表覆盖这轮所有决策(含 asset N/A、权威例外、MIXED lever)。
- 停止信号(候选枯竭 → 转优化)和这轮一致。
- eval-harness 的 download 前置、empirical-liveness 的三分类、third-party-calibration 的案例都对得上。

- [ ] **Step 3: 最终全 suite**

Run: `cd backend && python -m pytest -q 2>&1 | tail -5`
Expected: 仅已知 flaky(quota / test_refresh_stale),无新失败。

- [ ] **Step 4: 收尾 commit(若有散落改动)**

```bash
git status   # 确认 skill 文件都提交了
```

---

## Self-Review(plan 写完自检)

**1. Spec coverage**:
- 决策 1(asset N/A)→ Task 1 ✓
- 决策 2(download 前置)→ Task 4(eval-harness.md)✓
- 决策 3(混合分档+第三方)→ Task 3(verdict-action 分档)+ Task 6(third-party)✓
- 决策 4(多维验活三分类)→ Task 5 ✓
- 决策 5(全 lever + weight-invariant)→ Task 3 ✓
- 决策 6(停止信号)→ Task 2(SKILL.md)✓
- skill 身份/编排/边界 → Task 2 ✓
- 4 references → Task 3-6 ✓
- 验证 → Task 7 ✓

**2. Placeholder scan**: 无 TBD/TODO;代码 step 含实际 code;skill 文件 step 含实际 Markdown(从 spec 搬)。✓

**3. Type consistency**: `assess(..., source_category="threat")` 在 Task 1 定义、Task 1 测试用、__main__ 调用——签名一致 ✓;`Verdict.state == "N/A-ASSET"` 在 verdict.py、test、SKILL.md、verdict-action.md 一致 ✓。
