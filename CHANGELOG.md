# Changelog

本项目的所有重要变更记录于此。自 v1.0.0 起按版本分节，格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## Unreleased

（暂无）

## v1.1.0 — 2026-08-21

### 新增 Added

- Fail2ban 集成：`scripts/fail2ban/ipradar.conf` —— ban 前先查本地裁决，确认恶意（conf ≥ 70 可调）记入长封名单，CDN/基础设施边缘跳过 ban 免误封
  - Fail2ban integration (`scripts/fail2ban/ipradar.conf`): pre-ban triage consults the local verdict — confirmed-malicious IPs (confidence ≥ 70, tunable) go to a long-ban list, CDN/infra edges are skipped to avoid false bans
- Graylog 集成：`integrations/graylog/` —— 可导入 content pack（Lookup Table + Pipeline）及 HTTP JSONPath 配置指南，日志富化一步到位
  - Graylog integration (`integrations/graylog/`): importable content pack (lookup tables + pipeline) with an HTTP JSONPath setup guide — one-stop log enrichment
- Wazuh 集成：`integrations/wazuh/custom-ipradar` —— 带 IP 告警自动富化为 ECS threat.indicator 跟进告警，本地替代 VirusTotal 集成
  - Wazuh integration (`integrations/wazuh/custom-ipradar`): enriches IP-bearing alerts into ECS threat.indicator follow-on alerts — a local drop-in replacement for the VirusTotal integration
- `/api/lookup` 新增顶层 `threat` 汇总字段（verdict/confidence/types/is_cdn），下游集成一句话拿裁决
  - Top-level `threat` summary field (verdict/confidence/types/is_cdn) in `/api/lookup` responses — integrations get the verdict in one field
- 新增 DShield top-attacker 源：免密钥源 24→25，总源数 28→29
  - New DShield top-attacker source: keyless sources 24→25, total 28→29
- `last_seen` 全管线接通：源采集 → 存储 → 查询 API → 详情面板
  - `last_seen` wired end-to-end: harvest → storage → lookup API → detail panel
- `as_domain` 资产域名槽位，机构行后缀展示
  - `as_domain` asset slot, displayed as a suffix on the org row
- CSV 导出新增 first_seen / last_seen / as_domain 三列
  - CSV export gains first_seen / last_seen / as_domain columns
- 详情面板 extra 值可点击：tweet_url、sbl_id 及裸 URL 自动 linkify
  - Extra values in the detail panel are linkified: tweet_url, sbl_id, and bare URLs become clickable links
- 重建进度升级：加载阶段也有进度信号，终态冻结不再回跳，状态条分段渲染百分比/行数
  - Rebuild progress overhaul: loading phase now emits progress, final-state fractions freeze instead of snapping back, and the status bar renders per-phase percentages and row counts

### 变更 Changed

- 后台自动刷新改为每源固定错峰时刻：日更源每天 2 次、周更源每周期 1 次（此前 30 分钟扫描、过期即拉，全源同刻聚集；AbuseIPDB 等配额源被动挨挤）；调度器状态新增每源 `next_refresh_at`
  - Background refresh moved to fixed per-source staggered slots: daily sources twice a day, weekly sources once per staleness window (previously a 30-minute scan pulled every stale source at the same moment, crowding quota'd feeds like AbuseIPDB); scheduler status now exposes per-source `next_refresh_at`
- stopforumspam 换用 listed_ip_365_all 数据：带走 total（出现次数）与 last_seen
  - StopForumSpam switches to the listed_ip_365_all feed, carrying total (hit count) and last_seen
- proxyscrape 改发 carrier 字段，僵尸 isp 槽位删除
  - ProxyScrape now emits carrier; the zombie isp slot is removed
- 死代码清除：ApiSource 基类、在线富化（enricher）链、enrichError/phase 死契约
  - Dead code removed: the ApiSource base class, the online-enricher chain, and the unused enrichError/phase contract

### 修复 Fixed

- 批量更新收敛竞态：终态 done 事件不再出现 done<total；源中途启用 (re-enable) 或调度器刷新与手动全量更新重叠时，total 动态校正，批次不再可能永久停在 running（需重启才能再全量更新）
  - Batch-update convergence race: terminal done events no longer report done<total; when a source is re-enabled mid-batch or a scheduler refresh overlaps a manual full update, total is dynamically corrected — a batch can no longer get stuck in running forever (which previously required a restart)
- cn_isp 不再把运营商名写进 as_name；ISP 徽标仅中国 IP 显示
  - cn_isp no longer pollutes as_name with carrier names; the ISP badge is shown for CN IPs only
- STIX 导出：Location/AS 对象 id 规范为 `<type>--<UUID>`；残余 http 源 URL 全部改 https
  - STIX export: Location/AS object ids normalized to `<type>--<UUID>`; remaining http feed URLs switched to https
- DShield 解析容错：tab 分隔、`-` 占位归一为 null
  - DShield parsing hardening: tab-split tolerance; `-` placeholders normalized to null
- 进度显示一串修复：resync 后假 0%、rebuild 后取消边界、行数 K/M 晋升格式、loading 计数清零回归、cancelled 灰条
  - A run of progress-display fixes: false 0% after resync, cancel boundary after rebuild, K/M row-count formatting, loading-counter zeroing regression, and the cancelled grey bar

### 内部 Internal

- README：404StarLink banner、新截图、审计修正（链接/警告/venv 引导/刷新口径英文镜像）；agent skills 文档接地重写 + 漂移守卫测试；迁移到 pi 作为主 harness；测试加固（monotonic deadline、退避守卫去空洞化）
  - README: 404StarLink banner, new screenshots, audit fixes (links/warnings/venv bootstrap/EN mirror of refresh cadence); agent-skills docs rewritten as grounded pointers plus drift-guard tests; migrated to pi as the primary harness; test hardening (monotonic deadlines, de-vacuous backoff guard)

## v1.0.0 — 2026-08-18

开源首版。自托管威胁情报融合引擎：FastAPI + React 19 + LMDB，单容器部署，全栈本地运行，查询不出网。

### 核心

- **28 源威胁情报融合** —— 24 个免密钥源开箱即用（GeoLite2 / iptoasn / 主要封禁列表），4 个 🔑 源（ipinfo_lite / abuseipdb / otx / ip2proxy）可选开启
- **一份裁决，不是一堆列表** —— 源可靠性加权、交叉佐证、时间衰减的 0-100 置信度；单 IP 一句话结论，逐源证据可展开
- **地理 · 城市 · ASN · CN ISP 归属**（含港澳台）；开放代理 / VPN / Tor / CDN 一眼认出
- **流式批量查询** —— 文本 / 文件 / CIDR 输入，NDJSON 进度流，单批上限 50 万 IP，流式去重；STIX 2.1 导出
- **冷启动感知** —— 容器秒级可访问，页面横幅实时盯构建进度；积分查询门保证构建期绝不以半份数据出结论，超时强制放行防楔死
- **资源自觉** —— 重建内存阀门按宿主机 RAM 自动收敛并发；LMDB + mmap 存储，查询路径内存 MB 级；默认每 30 分钟后台自动刷新
- **Docker 一键部署** —— `docker compose up -d --build` 即全栈

### 修复

- ip2proxy：PX2 LITE CSV 本无表头，harvest 不再误把首行数据当表头丢弃（此前每次重建恰丢一行代理记录）

### 历程（v1.0.0 之前）

- 2026-06-08 项目起步：TSV 加载器 + FastAPI 查询路由 + React 脚手架
- 2026-06-16 内存索引迁移 MMDB：常驻内存从 GB 级降至 MB 级
- 2026-08-04 更新管线加固：崩溃恢复 / 快照膨胀 / OOM 防护
- 2026-08-11 CIDR 懒展开；结果表 5 万行分页
- 2026-08-12 重建内存阀门：load/rebuild 分离，重建并发按可用内存自动调节
- 2026-08-14 LMDB 存储试点（ipinfo_lite），铺平全源迁移
- 2026-08-17 开源发布：仓库净化，公开为 ip-radar
- 2026-08-18 流式进度协议 v2 + LRU 流式去重；冷启动感知（即时可用 / 横幅 / 积分门）
