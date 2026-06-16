# Classification 词表策略修订（Addendum）

**日期**: 2026-06-14
**状态**: 设计已确认，待实现
**修订对象**: `2026-06-14-multi-source-per-entry-classification-design.md` §3（`_classification.py`）及评审处理记录中 #2 词表治理
**起因**: Codex review P3 — ip2proxy `DCH`(数据中心/hosting)被映射成 `proxy`/`suspicious`，云厂商 IP 误报。复核后确立词表根本策略。

## 核心策略：复核轴优先

`classification_type` 的**首要职责是跨源复核主轴**（fusion 设计已定）。因此它必须是**受控 IntelMQ 词表**，不能让各源吐原生值（否则同概念不同原生串永不复核、`classifications` keys 被污染、STIX 映射失效）。

**未明确映射的值 → `other`**（不是 raw、不是 forced default）。`other` 是受控桶，仍参与复核（多源都标"未归类"会互相佐证），轴完整。

**原生值保留在 `extra["native_type"]`**（仅当未映射时）。不丢信息、不膨胀词表、不误标。复用既有 `extra` 字段 → 零 schema 变动 → STIX 走既有 `extra→x_*` 机制（无新 STIX 代码）。

## 取代先前的 raw-passthrough 提议

先前一度考虑"未映射按原样输出(raw passthrough)"以避免误标/膨胀。经复核确认：raw-passthrough **破坏复核轴**（同概念不同原生串不复核），**不可取**。本 addendum 取代该提议。

## `normalize()` 契约（修订）

```python
def normalize(raw_type, mapping: dict) -> str:
    """受控词表映射。映射命中且目标在 CLASSIFICATION_TYPES 内 → 用映射值；
    否则 → "other"。不 raw-passthrough、不强制 default。"""
    key = (raw_type or "").strip().lower()
    mapped = mapping.get(key)
    if mapped and mapped in CLASSIFICATION_TYPES:
        return mapped
    return "other"
```

- 去掉 `default` 参数（不再强制默认值）。
- 空输入 → `"other"`。
- 未映射/坏映射 → `"other"`。

## DCH 落地

`PROXY_MAP = {"vpn": "proxy", "pub": "proxy", "tor": "tor"}`（DCH 故意缺）。

`_proxy_evidence`：
- `classification_type = normalize(pt, PROXY_MAP)` → DCH 得 `"other"`（不再是 `"proxy"`）。
- 未映射时附 `extra={"native_type": pt}`（DCH → `"DCH"` 保留）。
- VPN/PUB → `proxy`、TOR → `tor` 不变。

## 未来升级路径（YAGNI 节奏）

词表只收录**多源会共有的概念**。单源特有的概念（当前仅 ip2proxy 的 hosting/DCH）走 `other` + extra，**不立即加进词表**。当**第二个源**也吐同一概念时，才把它提升进 `CLASSIFICATION_TYPES` 并补映射。因历史 raw 都存在 extra，回溯重映射无损。

## 已接受权衡

`other` 把各种未归类概念并到一个桶 → 有**轻微假复核风险**（如 ip2proxy DCH 与某源 scanner 都 → other 会互相佐证）。**有界、可接受**：优于 raw-passthrough 的零复核，优于给每个边缘值造词表的无限膨胀。

## 实施面

- 回滚已写的 raw-passthrough 改动（`_classification.py` normalize + PROXY_MAP、`ip2proxy.py` `_proxy_evidence`、两测试文件未提交版本）。
- 按本 addendum 重实现：`normalize()` 受控（unmapped→other）、`_proxy_evidence` DCH→other+extra、`PROXY_MAP` 不含 DCH。
- 更新 `test_classification.py`（unmapped→`other`，非 raw）、`test_ip2proxy_proxytype.py`（DCH→`other` 且 `extra["native_type"]=="DCH"`）。
- 不动 `_types.py`（`extra` 已存在）、不动 STIX 导出。

## 不在范围

- 给词表新增 `hosting`/`datacenter`（YAGNI，等第二个 hosting 源）。
- 前端适配（P1，另议）。
- OTX/blocklist_de 的 per-entry 映射（T7/T8，仍延后）。
