---
name: manage-intel-source
description: Use when the user wants to **add sources WITHOUT a specific one in mind** ("add some new sources", "find and wire up worthwhile feeds", "what should I add and plug in"), **optimize the existing source pool** (tune weights, demote noisy sources, calibrate authority sources), or **run a net-impact eval** on source(s) — standalone ("evaluate the source we just added") or as part of the full discover→add→evaluate lifecycle. NOT for implementing a specific named source (use add-intel-source directly) or for just listing/shortlisting candidates (use discover-intel-sources).
---

# Managing an Intelligence Source's Full Lifecycle

This skill orchestrates the **默认闭环: discover → 验活 → add**,然后**停下 offer** evaluate/tune(不自动跑).
It引用 `discover-intel-sources` / `add-intel-source`(不加源实现,不复述),
并补齐 harness 评估 + verdict 驱动的权重调优段(可选,用户要时才跑).

## 路由(先确认该不该进本 skill)

- 用户**点名了具体源**(「add AbuseIPDB」)→ 不是本 skill 的活,指向 `add-intel-source`。
- 用户**只想要候选短名单**(不想加)→ 指向 `discover-intel-sources`。
- 用户**没点名要加源 / 要优化池子 / 要评估影响 / 要全 lifecycle** → 进本 skill。

## 5-minute mental model

**默认闭环(到 add 即止):**

1. **discover** — invoke `discover-intel-sources` 找候选。
2. **验活** — 多维验活(curl 4 组合 + jina),四分类(真死/换URL/受限/免费key但bulk付费)。见 `references/empirical-liveness.md`。
3. **add** — invoke `add-intel-source` Phase 1-4 加源。

**到此处停下,offer 用户评估/调优**(eval 重且有 OOM 风险:全量 rebuild 大源 LMDB 同样吃 RSS——ip2proxy 累积模式峰值 686MB,WSL 内存约束不变,故默认不自动跑;用户要「评估影响 / 优化池子」时才进 4-5):

4. **evaluate**(可选)— `download` 后 `python -m ipdb._eval <source>`。见 `references/eval-harness.md`。
5. **tune**(可选)— verdict → action(全 lever 表 + 数值分档)。见 `references/verdict-action.md`;权威源查第三方实测(见 `references/third-party-calibration.md`)。

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
- `references/empirical-liveness.md` — 多维验活 + 四分类 + 免费 bulk pricing 验证
- `references/third-party-calibration.md` — 权威源权重前的第三方实测查证
