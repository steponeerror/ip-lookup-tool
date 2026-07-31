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
