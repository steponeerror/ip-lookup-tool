# 源更新 UX 重构设计

- **日期**：2026-07-29
- **状态**：待评审
- **分支**：`feat/feodo-source`（后续可续接到 master）
- **范围**：后端源更新的生命周期/任务模型 + 前端进度展示，统一单源与批量更新

---

## 1. 背景与问题

当前源更新机制存在 4 个相互关联的痛点：

1. **启动阻塞**。`main.py:84` 的 `lifespan` 同步调用 `refresh_stale()` + `load_db()`（`_registry.py:297`）。stale 源重新下载 + 全量磁盘加载期间，服务无法响应任何请求。开发时频繁重启 → 每次都要等数据刷新。
2. **单源更新无真进度条、不可中止/暂停**。`/api/sources/{name}/update/stream`（`_registry.py:231`）只发 `downloading→loading→complete` 阶段标签，且无任何取消通道。`download()` 是阻塞式 `urllib + shutil.copyfileobj`（如 `ipinfo_lite.py:48-50`），无法打断。
3. **批量更新是另一条独立代码路径**。`/api/update-db`（`main.py:187` `_stream_update_db`）**串行**跑 `get_download_steps()`（`_registry.py:476`），一次一个源。
4. **批量进度展示不统一**。`DbStatusBar`（底部全局状态栏）有整体 `%` 进度条；但 `SourcesPage` 的 "Refresh all" 调用 `updateDbStream(() => {})` 用了**空回调**，完全不显示每源进度，只一个 spinner。

根因：单源更新和批量更新是两套独立路径，**没有统一的"可追踪/可中止任务"模型**。

## 2. 目标 / 非目标

**目标**
- 启动与源更新解耦：服务立即可用，stale 源后台渐进刷新，查询期间优雅降级。
- 统一任务模型：单源/批量/后台启动刷新都走同一个 `UpdateManager`，每个源更新是一个可追踪、可中止的 `Task`。
- 每源独立进度条 + 批量整体进度，统一在底部 `DbStatusBar` 可展开面板。
- 中止（单源/整批）+ 暂停（批量）。
- 有界并发（默认 3）+ 防 provider 限流。

**非目标**
- 真实字节百分比进度（YAGNI，见决断 3）。
- 即时 socket 级中断（不重写 httpx，见决断 9/11）。
- 跨重启的任务持久化（任务内存态，见定义）。
- 自动重试失败源（见定义）。
- Windows 文件锁处理（服务跑 WSL/Linux，见定义）。

## 3. 决断汇总

> 设计阶段 5 个决断 + grill 两轮共 12 个 = 17 个决断 + 1 个已查证事实。每条的"问题/权衡/被排除项代价"见对话记录；本节给出结论与系统影响。

### A. 启动与可用性

| # | 决断 | 系统影响 |
|---|------|---------|
| 1 | **立即响应 + 渐进刷新**（暖启动） | lifespan 只 `load_db()`（磁盘 MMDB，快），stale 源后台入队逐个下载+重载，完成后 health 自动转 fresh。查询始终可用。 |
| 2 | **冷启动检测** | 检测无任何数据文件→首次走阻塞式全量（同现状）；有数据→决断 1。首次行为不变，只给热重启加速。 |

### B. 进度展示与传输

| # | 决断 | 系统影响 |
|---|------|---------|
| 3 | **阶段条 + 整体%** | 每源不确定动画条 + 阶段徽标；批量整体 `done/total` 算 %。无需字节%。 |
| 4 | **底部 DbStatusBar 可展开面板**（Layout B） | 全局面板：整体 % + 每源 mini 条 + 单源 ✕ + 全局 Pause/Abort。两个入口都喂同一管理器。 |
| 5 | **SSE 断线重连重取快照** | 连/重连先 `GET /api/tasks`，无 seq（SSE 单 TCP 流不静默丢包）。 |
| 6 | **asyncio.Queue + `call_soon_threadsafe`** 桥接 | worker 线程事件安全投递到 asyncio；有界 256、满丢最旧；不占 executor 线程。 |
| 7 | **task-done SSE → debounce 500ms 重取 `getSources`** | SourcesPage health 显示与实际一致，批量内合并为 1 次重取。 |
| 8 | **完成停 ~5s 展示终态再收起** | 面板常驻进行中；完成/中止后停 ~5s 显示 done/failed 计数再回 idle 条；失败计入 idle warnings。 |

### C. 中止 / 暂停 / 调度

| # | 决断 | 系统影响 |
|---|------|---------|
| 9 | **批量暂停 + 单源/批量协作中止** | 暂停作用于调度器（跑完当前、不发新源）；中止给 `download()` 加 `CancelToken`，分块循环检查、丢弃结果、跳过加载。 |
| 10 | **有界并发，默认 3**（可配置 `IP_RADAR_UPDATE_CONCURRENCY`） | 批量快很多；与单源已有的跨源并发一致。 |
| 11 | **短超时 + 分块检** | 共享 helper `connect 10s / read 30s` + 分块循环检令牌，中止延迟 ≤ 一次 read。 |
| 12 | **按 host 串行** | 全局 cap 3 + per-host 锁，同 host 源不并发（防 abuse.ch 等 429）。 |
| 13 | **三锁顺序 host→sem→source** | 无死锁、无槽浪费（同 host 串行在取 semaphore 槽之前）。 |

### D. 正确性与去重

| # | 决断 | 系统影响 |
|---|------|---------|
| 14 | MMDB 写入本就原子（`_mmdb.py:30-33` `.tmp`+`os.replace`）——**事实，无需改** | 后台重载不撕裂查询（旧 mmap reader 持旧 inode）。 |
| 15 | **原始文件原子写** | 共享 helper 统一 `path.tmp`+`os.replace`；`set_source_enabled` 的并发 `load()` 读到的永远是完整文件。 |
| 16 | **按源名去重** | manager 以源名 key 跟踪活跃任务；命中已 queued/running→返回现有 task_id（200 幂等）。批量幂等补齐缺口。 |
| 17 | **批量排除 online** | batch/enqueue 只含 offline 源；`ApiSource.download()` 是 no-op（`_base.py:240`），online 源不显示 Update 按钮。 |

### E. 前端架构

| # | 决断 | 系统影响 |
|---|------|---------|
| 18 | **TaskProvider context**（Layout 层） | 单 SSE 订阅 + 挂载/重连取快照；DbStatusBar 与 SourcesPage 共消费，单一数据源。 |

## 4. 架构

### 4.1 后端核心

**新增 `backend/ipdb/_tasks.py`** —— `UpdateManager` 单例 + 任务原语：

- `CancelToken`：包 `threading.Event`，`is_cancelled()` / `cancel()`。
- `Task`：状态机 `queued → running(downloading → loading) → done | failed | cancelled`，持有 `CancelToken` + 源名 + host。
- `UpdateManager`：
  - `Semaphore(N)`（默认 3）+ per-host `Lock` + 复用现有 `_update_lock_for(name)`（`_registry.py:93`）。
  - worker 取锁顺序：**host-lock → semaphore → source-lock**（决断 13）。
  - 事件总线：`subscribers: set[Subscriber]`（每订阅者 = asyncio.Queue + loop ref）；发事件用 `loop.call_soon_threadsafe(q.put_nowait, evt)`（决断 6）。
  - 公共方法：`enqueue_stale()` / `enqueue_batch()` / `enqueue_one(name)` / `cancel(task_id)` / `cancel_batch()` / `pause()` / `resume()` / `snapshot()` / `subscribe(loop)`。
  - 去重：`_active_by_source: dict[str, Task]`；enqueue 前查表，命中返回现有 task（决断 16）。
  - 过滤：`enqueue_batch`/`enqueue_stale` 仅含 `archetype == "offline"` 源（决断 17）。

**新增共享下载 helper**（`_sources/_download.py` 或并入 `_mmdb.py`）：

```
_download_file(url, dest, token, *, timeout=(10, 30), headers=None, gz=False)
  → 写 dest.tmp，分块 resp.read(CHUNK) 循环：
      每 chunk 检 token.is_cancelled() → 抛 CancelledError
      写 tmp
  → os.replace(dest.tmp, dest)   # 原子（决断 15）
  → 失败/取消：unlink(dest.tmp)
```

- 各**文件源** `download()` 改用此 helper（ipinfo_lite/firehol/ipsum/blocklist_de/emerging_threats/feodo/tor_exits/x4bnet/ip2proxy/iptoasn 等）。
- 各**分页 API 源**（otx/threatfox/abuseipdb/misp）在分页循环顶部检 `token.is_cancelled()`。
- `load()` 在重活前检令牌（MMDB 写入快，主防线在 download）。
- 各源暴露 `download_host`（从 `url`/`_url` 派生）用于 per-host 串行（决断 12）。

**`main.py:84` lifespan 改造**：

```
lifespan(app):
    offline = [s for s in _enabled_sources() if _archetype(s) == "offline"]
    cold = not any(s._path.exists() for s in offline)          # 决断 2
    if cold:
        await manager.run_batch_blocking(offline)              # 首次：阻塞到完成
    else:
        load_db()                                              # 磁盘快加载（决断 1）
        manager.enqueue_stale()                                # stale 源后台入队
    yield
```

- 移除 `refresh_stale()` 同步调用 + `async_refresh` 守护线程特例（仅 `otx.py:77` 用，统一接管）。

### 4.2 锁与并发模型

- **查询路径不持任何锁**：`load()` 末尾 `self._reader = open_reader(...)` 是 GIL 下原子赋值，maxminddb reader 只读不可变 → 并发查询只看到旧或新 reader、永不撕裂（决断 14 保证 MMDB 文件层也原子）。
- **worker 路径**：host-lock → semaphore → source-lock，一致顺序无死锁（决断 13）。
- **enable-toggle `load()`**（`_registry.py:210`）不持锁：靠原子文件写保证安全（决断 15）。

### 4.3 SSE 传输

- `GET /api/events` → `StreamingResponse(media_type="text/event-stream")`，响应头 `X-Accel-Buffering: no` + `Cache-Control: no-cache`（防 Vite/nginx 缓冲）。
- handler：`subscribe(loop)` 注册 asyncio.Queue → `finally` 注销（防泄漏）；`async for evt in q: yield f"data: {json}\n\n"`。
- manager 发事件：遍历订阅者 `loop.call_soon_threadsafe(q.put_nowait, evt)`；`put_nowait` 满则丢最旧（决断 6 背压）。
- 事件类型：`task`（task 状态变化）、`batch`（批量状态 + done/total）、`done`（批量结束）。

### 4.4 API 面

**新增 / 改造**
| 方法 | 路径 | 行为 |
|------|------|------|
| GET | `/api/tasks` | 全量快照（所有 task + batch 状态），重连重同步用 |
| GET | `/api/events` | SSE 流，所有 task/batch 状态变化 |
| POST | `/api/update-db` | 批量入队（幂等，跳过已 queued/running；仅 offline），返回 `{batch_id}` |
| POST | `/api/sources/{name}/update` | 单源入队（幂等，命中活跃返回现有 task），返回 `{task_id}` |
| POST | `/api/tasks/{id}/cancel` | 中止单源 |
| POST | `/api/update-db/cancel` | 中止整批（取消 queued + 信号 running） |
| POST | `/api/update-db/pause` `/resume` | 暂停/恢复调度器 |

**移除**
- `/api/sources/{name}/update/stream`（旧 NDJSON）
- 流式 `/api/update-db`（改为入队即返回）
- 后端 `update_source_streaming` / `_stream_update_db` / `get_download_steps` / `refresh_stale` / `reload_db`（`reload_db` 仅导出无调用方）
- 前端 `updateDbStream` / `updateSourceStream`
- `_archetype` 的 `async_refresh` 分支

> 迁移面已查证无隐藏调用方（`__init__.py` 导出需同步更新）。

### 4.5 前端

- **新增 `TaskProvider`**（挂在 `Layout`，包住 `<Outlet/>` 与 `<DbStatusBar/>`）：单 SSE 订阅 + 挂载/重连取 `/api/tasks` 快照；context 暴露 `tasks`/`batch` + 控制动作（enqueue/cancel/pause/resume）。
- **`DbStatusBar` 重写**（消费 TaskProvider）：
  - 空闲 → 现有记录数条 + "Update DB" 按钮。
  - 活跃 → 整体 `done/total · X%` + ▾ 展开 + Pause/Abort。
  - 展开面板 → 每源行（name + 状态徽标 + mini 不确定阶段条 + 单源 ✕）。
  - 完成 → 停 ~5s 展示终态再收起（决断 8）。
- **`SourcesPage`**：`handleUpdate` → POST 单源；`handleRefreshAll` → POST 批量；行阶段标签改读 TaskProvider context；online 源隐藏 Update 按钮、显示 on-demand 徽标（决断 17）；收到 task-done → debounce 500ms 重取 `getSources`（决断 7）。
- **`api.ts`**：`updateDbStream`/`updateSourceStream` → `enqueueBatch`/`enqueueSingle`/`cancelTask`/`cancelBatch`/`pauseBatch`/`resumeBatch`/`getTasks` + SSE helper。

## 5. 数据流

**暖启动**：`load_db()`（磁盘）→ `enqueue_stale()`（后台）→ `yield`。查询立即用磁盘数据；stale 源后台刷新，完成自动换 reader、health 转 fresh。

**冷启动**：`run_batch_blocking()` 阻塞到全量完成 → `yield`。无前端连接，期间 task 事件丢弃；启动后前端取快照看终态。

**单源更新**：`POST /api/sources/{name}/update` → 入队（命中活跃返回现有）→ worker host→sem→source 取锁 → download（原子写 + 检令牌）→ load（换 reader）→ task `done` → SSE 推送 → 前端 debounce 重取 `getSources` + 面板停 ~5s 收起。

**批量更新**：`POST /api/update-db` → 仅 offline 源去重入队 → 调度器有界并发（同 host 串行）→ 各源同上 → `batch` 事件持续推 done/total → 全部结束发 `done`。

**中止（单源）**：`POST /api/tasks/{id}/cancel` → 置令牌 → worker 下一个 chunk 抛 `CancelledError` → 清理 tmp、跳过 load → task `cancelled`。

**中止（整批）**：`POST /api/update-db/cancel` → 所有 queued 标 cancelled + 所有 running 置令牌；已完成源保持 done。

**暂停/恢复**：`pause()` → 调度器停止取新任务（running 跑完）；`resume()` → 续发。

**SSE 断线**：前端检测断开 → 重连 → 先 `GET /api/tasks` 快照重同步 → 续订 SSE。

## 6. 边界与定义（非决策）

- **失败/重试**：后台刷新失败的源 → 任务 `failed` + 计入 DbStatusBar warnings，保留旧数据，**无自动重试**，可手动单源重试。
- **批量无单独"Loading DB"步骤**：新模型每 task 自带 download→load，旧 `_stream_update_db` 末尾的全局 load 步骤消失。
- **任务生命周期**：内存态，**重启即清空**（已落盘数据保留）；重启后 stale 源被 `enqueue_stale` 重新挑出。
- **暂停的批量**：服务器端持久，关标签页不丢；SSE 快照显示 paused，可恢复/中止，不自动恢复。
- **pause/cancel 无活跃批量** → 200 no-op；**abort 在 paused 批量上**照常生效。
- **batch_id**：每次 enqueue 新 id；幂等性靠"已 queued/running 不重复入队"。
- **SSE 订阅者清理**：generator `finally` 注销订阅者 + loop ref，否则断连泄漏。
- **Windows 文件锁**：服务跑 WSL/Linux，`os.replace` 对已 mmap 文件安全（旧 inode 保留）；Windows 桌面包是离线 zip 不跑服务，不处理。
- **进度事件频率**：阶段级，每源每批 ~3-5 事件，16 源 ~80 事件，SSE 足够。
- **MISP 长刷新**：57 feeds 慢，后台刷新长时间占一个槽 + host-lock(localhost)，可接受、不影响其他 host。
- **`download_host` 回退**：从源主 URL 派生；无单一 URL 的源（多端点）给唯一 host（不参与串行，等价于全局并发）。localhost（MISP docker）按 host 分组。
- **`_download_file` 边界**：helper 只负责"URL → 原子写本地文件 + 取消令牌 + 超时"；解压/解析（如 ipinfo_lite 的 gzip 解压）仍是各源 `download()` 的后置步骤，不在 helper 内。

## 7. 测试计划

### 后端（pytest）
- **`UpdateManager`**：有界分发（≤3 并发）、per-host 串行（两同 host 源不重叠）、暂停停发+跑完当前、恢复续发、中止取消 queued+running、按源名去重（2nd enqueue 返回现有）、offline-only 过滤、完成触发 reader 重载 + health 翻 fresh。
- **`CancelToken` + `_download_file`**：分块写、中途置令牌 → `CancelledError` + tmp 清理、dest 无半成品（原子 replace）。
- **启动**：冷启动（无数据→阻塞路径，服务在完成前不响应）、暖重启（磁盘加载+后台入队，服务即时响应）。
- **SSE**：enqueue/phase/complete 事件序列；`snapshot()` 与实时态一致；订阅者断连后注销（无泄漏）。
- **原子写**：并发 `load()`（模拟 enable-toggle）期间 `download()` 写文件，load 只见完整文件。

### 前端（vitest + RTL）
- **`TaskProvider`**：挂载订阅、快照→state、SSE 事件→state、断线重连重取快照。
- **`DbStatusBar`**：空闲/活跃渲染、整体%、展开面板每源行、Pause/Abort/单源✕ 调对端点、完成 ~5s 收起。
- **`SourcesPage`**：单源/批量入队、online 源无 Update 按钮、行标签读 context、task-done 触发 debounce 重取。

## 8. 配置

- `IP_RADAR_UPDATE_CONCURRENCY`（默认 3）：批量并发上限。
- helper 超时固定 `connect=10s / read=30s`（可后续提为配置项）。
- SSE 订阅队列上限固定 256。

## 9. 实现顺序（建议）

1. `_download_file` helper + `CancelToken` + 改造各源 `download()`（原子写 + 取消 + host 暴露）。
2. `_tasks.py` `UpdateManager`（状态机 + 锁 + 事件总线 + 去重 + 过滤）。
3. lifespan 解耦（冷启动检测 + 暖启动后台）+ 移除旧路径。
4. API 面（SSE + 控制端点 + 快照）。
5. 前端 `TaskProvider` + `DbStatusBar` 面板 + `SourcesPage` 接入。
6. 测试（后端 + 前端）。
