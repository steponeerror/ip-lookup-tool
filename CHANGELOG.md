# Changelog

本项目的所有重要变更记录于此。自 v1.0.0 起按版本分节，格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## Unreleased

### 新增

- Fail2ban 集成：`scripts/fail2ban/ipradar.conf` —— ban 前先查本地裁决，确认恶意（conf ≥ 70 可调）记入长封名单，CDN/基础设施边缘跳过 ban 免误封
- Graylog 集成：`integrations/graylog/` —— Lookup Table + HTTP JSONPath 配置指南，日志富化一步到位
- Wazuh 集成：`integrations/wazuh/custom-ipradar` —— 带 IP 告警自动富化为 ECS threat.indicator 跟进告警，本地替代 VirusTotal 集成
- `/api/lookup` 新增顶层 `threat` 汇总字段（verdict/confidence/types/is_cdn），下游集成一句话拿裁决

### 变更

- 后台自动刷新改为每源固定错峰时刻：日更源每天 2 次、周更源每周 1 次（此前 30 分钟扫描、过期即拉，全源同刻聚集；AbuseIPDB 等配额源被动挨挤）

### 修复

- 批量更新收敛竞态：终态 done 事件不再出现 done<total；源中途启用
  (re-enable)或调度器刷新与手动全量更新重叠时，total 动态校正，
  批次不再可能永久停在 running（需重启才能再全量更新）

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
