# native_type: Preserve Raw Source Classification in extra

**Date:** 2026-06-14
**Branch:** feat/source-registry

## Motivation

当前 `classification_type` 统一映射到 IntelMQ 受控词汇表，但映射过程中丢失了原始分类标签。例如 OTX 的 `mysql` protocol 被映射为 `scanner`，ip2proxy 的 `DCH` 被映射为 `other`——原始值不可恢复。

`EvidenceObservation.extra` 字段已存在，ip2proxy 已用它保留 DCH 的 `native_type`。本设计将此模式推广到所有 source。

## Design

### Rule

每个 source 在返回 evidence dict 时，统一填充 `extra.native_type`，值为**映射前最原始的分类标签**。无映射表的 source（如 tor_exits、spamhaus），`native_type` 与 `classification_type` 相同，保证前端字段统一存在。

`extra` 不参与 PCR6 融合，纯粹透传给前端/STIX。

### Per-Source Changes

| Source | native_type 值 | 改动点 |
|---|---|---|
| **ip2proxy** | proxy_type (VPN/PUB/DCH/TOR) | `_proxy_evidence()` 始终设 extra，不再仅 DCH |
| **threatfox** | threat_type 列原始值 | `parse_row()` 加 extra |
| **otx** | protocol 关键字 | CSV 加第三列，download() 写入，`parse_row()` 读回 |
| **ipsum** | `"blacklist"` | `parse_row()` 加 extra |
| **tor_exits** | `"tor"` | `get_insert_data()` 加 extra |
| **x4bnet_vpn** | `"proxy"` | 继承 `_base.get_insert_data()` 改动 |
| **blocklist_de** | `"blacklist"` | 同上 |
| **spamhaus** | `"blacklist"` | 同上 |
| **emerging_threats** | `"blacklist"` | 同上 |
| **firehol** | `"blacklist"` | `load()` 内联 dict 加 extra |

### Data Model (unchanged)

`EvidenceObservation.extra: dict` — already exists at `_types.py:73`, flows through `to_observation()` at `_merge.py:42`.

### OTX CSV Migration

OTX CSV 从 2 列变为 3 列: `[indicator, classification_type, protocol]`。已有 `otx_ips.csv` 下次 `download()` 自然刷新，无需迁移逻辑。
