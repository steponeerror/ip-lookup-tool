# 私有/保留地址短路标注 — 设计

日期：2026-07-22
状态：待实现

## 1. 问题

查询内网/私有 IP（如 `10.0.0.1`、`192.168.1.1`、`127.0.0.1`）时，结果被判为"恶意"。这是误报——这些地址不可在公网路由，不可能有真实的公网威胁情报。

## 2. 根因

`backend/ipdb/_registry.py` 的 `lookup(ip)` 只校验 IPv4 格式（`ipaddress.IPv4Address(ip)`），**不判断是否私有/保留地址**。于是保留 IP 照样被喂给所有离线 MMDB 源（`source.query(ip)`）。只要某个威胁源/封锁列表恰好收录了私有段（不少 blocklist 会把 `10.0.0.0/8`、`127.0.0.0/8` 当条目），`maxminddb.get(ip)` 就会命中 → 被判恶意。

误报 100% 来自离线 MMDB 威胁源。在线 enricher（`_enrich_results`）当前是空实现（`return None`，注释 "Plan 3 deferred"），未参与查询，无需处理。

## 3. 决策

| 决策点 | 选择 | 依据 |
|---|---|---|
| 处理方式 | **短路返回 + 标注**（不查询任何源） | 私有 IP 无真实公网威胁情报；短路彻底消除误报，也不对在线源发无意义请求 |
| 拦截范围 | **业界 bogon 标准**：`not addr.is_global or addr.is_multicast` | 等价于 IANA IPv4 Special-Purpose Registry（RFC 6890）中 "Globally Reachable = False" 的全部地址；`is_global` 自动跟进 IANA，比手写 CIDR 列表权威 |
| 标签粒度 | **统一一个标签"保留地址"**，不分子类型 | 避免过度设计（YAGNI） |
| 数据模型 | `LookupResult` 加一个 `is_reserved: bool` 字段 | 显式、类型安全、与现有 `error` 平行 |
| 短路位置 | `lookup()` 内，格式校验后、源循环前 | 四个端点（单查/批量/文件/两路 stream）都走 `lookup()`，一处覆盖全部 |

### 为何用 `is_global` 而非 `is_private`
Python 官方文档：`is_private` 对 CGNAT `100.64.0.0/10` 返回 **False**（CGNAT 是 `is_private` 与 `is_global` 同时为 False 的唯一例外）。用 `is_private` 会漏掉 CGNAT 段；`is_global` 覆盖全部非全局可达地址，含 CGNAT。

### 为何加 `or addr.is_multicast`
组播段 `224.0.0.0/4` 不在 IANA 特殊用途注册表的 "Globally Reachable" 列里，`is_global` 对它可能返回 True，会漏。组播地址是组地址非源地址，威胁源收录它是噪音，故显式并入。这与业界 bogon 定义（含 multicast）一致。

## 4. 设计

### 4.1 新模块 `backend/ipdb/_reserved.py`
纯函数，独立单测。

```python
import ipaddress

def is_reserved(ip: str) -> bool:
    """True if ip is non-globally-routable (bogon) per IANA RFC 6890 + multicast."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError, ValueError):
        return False
    return (not addr.is_global) or addr.is_multicast
```

覆盖范围（`not is_global`）：`0.0.0.0/8`、`10.0.0.0/8`、`100.64.0.0/10`(CGNAT)、`127.0.0.0/8`、`169.254.0.0/16`、`172.16.0.0/12`、`192.0.0.0/24`、`192.0.2.0/24`+`198.51.100.0/24`+`203.0.113.0/24`(文档)、`192.168.0.0/16`、`198.18.0.0/15`(基准)、`240.0.0.0/4`(保留)、`255.255.255.255/32`。外加 `224.0.0.0/4`(组播)。

### 4.2 `backend/ipdb/_types.py`
`LookupResult` 加字段，`to_dict()` 序列化。

```python
@dataclass
class LookupResult:
    ...
    error: str | None = None
    is_reserved: bool = False          # 新增
```

`to_dict()` 在返回 dict 里加 `"is_reserved": self.is_reserved`。

### 4.3 `backend/ipdb/_registry.py` 的 `lookup()`
在 db-loaded 守卫与格式校验通过之后、源循环之前插入短路（顺序见下方代码：db 守卫 → 格式 → 短路 → 源循环）。

```python
def lookup(ip: str) -> LookupResult:
    if not any(s.health().loaded for s in _enabled_sources()):
        raise RuntimeError("Database not loaded")
    try:
        ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError, ValueError):
        return _error_result(ip)
    if is_reserved(ip):                 # 新增短路
        return _reserved_result(ip)
    # ... 现有源循环不变
```

新增 `_reserved_result(ip)`，镜像现有 `_error_result`：N/A merged 字段、空 classifications/attributes、`is_isp=False`，但 `is_reserved=True`、**无** `error`。

### 4.4 前端 `frontend/src/api.ts`
`LookupResult` 加可选字段 `is_reserved?: boolean;`。

### 4.5 前端 `ResultTable.tsx` + `threatDisplay.ts`
- `threatSummary`：对 `r.is_reserved` 结果返回 verdict `"reserved"`。
- `VERDICT_RANK` 与 verdict 配色加 `"reserved"`（灰色/zinc）。
- `VerdictCell`：保留 IP 显示"保留地址"（灰底）。
- `ThreatTags`：保留 IP 为空（无 classifications）。
- IP 单元格：保留 IP 灰底/降饱和。
- 展开行：保留行展开时显示一行"保留地址 · 不可路由 · 未查询威胁情报"，替代正常源明细。

### 4.6 联动

- **`SummaryBar`**：保留 IP 计入独立桶"保留地址: N"，**不**计入 malicious/clean。
- **CSV 导出**：verdict 列对保留 IP 输出 `reserved`（由 `threatSummary` 驱动，自动跟随）。
- **STIX 端点** `/api/lookup/{ip}/stix`：当前 `if result.error: raise 400`，保留 IP 无 error 会走到 `to_stix_bundle` → None → 501。在 bundle 调用前加 `if result.is_reserved: raise HTTPException(400, "reserved address: no threat intel")`。

## 5. 数据流

```
请求 → lookup()
     → IPv4 格式校验
     → is_reserved(ip)?
        ├─ 是 → _reserved_result(ip)        # 不查询任何源
        └─ 否 → 源循环 + merge（现有逻辑）
     → to_dict()（含 is_reserved）
     → JSON → ResultTable(is_reserved 分支渲染)
```

## 6. 边界与错误处理

- **格式非法**：不变（`_error_result`，`error="invalid IP format"`）。
- **保留地址**：`_reserved_result`，正常 200 响应，无 error。
- **db 未加载守卫**：保持现状（保留判定在其之后）。保留 IP 在 db 未加载时仍 500——保留 IP 罕见，最小改动，可接受。
- **STIX 导出**：保留 IP → 400 明确提示。
- **IPv6**：`lookup()` 当前只接受 IPv4，IPv6 走"invalid IP format"。本次不动 IPv6；将来扩展时 `is_reserved` 同一 `is_global` 判断可平移。
- **在线 enricher（Plan 3）**：将来接入 `_enrich_results` 时，必须跳过 `result.is_reserved` 的 IP，避免对保留 IP 浪费配额、返回垃圾。在 `_reserved.py` 或 `lookup()` 留注释提示。

## 7. 测试（TDD）

遵循项目"前端上 vitest+RTL 组件测试"偏好。

### 后端 `pytest`
- `test_reserved.py`：
  - `is_reserved("10.0.0.1")` / `"192.168.1.1"` / `"172.16.0.1"` → True（RFC1918）
  - `"127.0.0.1"` → True（loopback）
  - `"169.254.1.1"` → True（link-local）
  - `"100.64.0.1"` → True（CGNAT，验证 is_private 漏洞已堵）
  - `"224.0.0.1"` → True（multicast）
  - `"240.0.0.1"` → True（reserved）
  - `"0.0.0.0"` → True（unspecified）
  - `"8.8.8.8"` / `"1.1.1.1"` → False（公网）
  - `"not-an-ip"` → False（格式非法不在此函数职责，返回 False）
- `test_lookup_reserved.py`：
  - `lookup("10.0.0.1")` → `is_reserved=True`、`classifications={}`、`error=None`。
  - patch 一个 source，断言保留 IP 查询时其 `.query` **未被调用**。
  - `to_dict()` 含 `"is_reserved": true`。
- STIX 端点：保留 IP → HTTP 400。

### 前端 `vitest` + RTL
- `threatDisplay`：`is_reserved` 结果 → verdict `"reserved"`。
- `ResultTable` 组件：保留行渲染"保留地址"灰底、威胁标签空。
- CSV 导出：保留结果 → verdict `reserved`。
- `SummaryBar`：保留 IP 独立计数，不计入 malicious/clean。

## 8. 不在范围内（YAGNI）

- 保留地址分子类型标签（私有/环回/CGNAT…）——统一"保留地址"。
- IPv6 支持。
- "隐藏保留地址"开关/筛选。
- 在线 enricher 接入（Plan 3 的事；仅留注释提醒跳过保留 IP）。
