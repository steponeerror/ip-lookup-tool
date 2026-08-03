# 实证验活(排除死源 / 换链 / 受限 / 免费层不含 bulk)

## 红线:不凭一次 curl FAIL 判死

2026-07-31 教训:greensnow 旧 `/list` 返回 404,曾误判「停运」,实际是换链接了(blocklist.greensnow.co)。必须多维验活 + 分类。

## 红线:不凭 'free' 措辞判免费 bulk

2026-07-31 教训:Pulsedive API doc 写「free account」,我信了,实际免费档仅 API 单点查询(1 req/秒),bulk Feed $1,500/mo+。「免费 key」≠「免费 bulk 离线」。验证免费 bulk 必读 **pricing/about 页**(/about/feed、/pricing);API doc 的 'free' 常指 key 注册免费,非 bulk 免费。

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

3. **四分类判定**(见下表)。**需 key 的源:额外读 pricing/about 页确认免费档含 bulk**(见第二条红线)。

## 四分类

| 分类 | 判据 | action | 证据 |
|---|---|---|---|
| **真死** | 站点死 / 域名挂售 / 作者声明停更 | 排除 | firehol issue / GoDaddy forsale / 作者首页声明 |
| **换 URL** | 站点活但旧路径 404 | Exa 搜新 URL,找到则正常加 | 新 URL 返回 200 + 数据 |
| **站点活但本地拉不到** | jina 通但本地 curl 4 组合全 FAIL(403 / IPv6 / 需注册) | 标「访问受限,不加」+ 记原因 | HTTP 403 / DNS 只解析 IPv6 / 401 missing_api_key |
| **免费 key 但 bulk 付费** | 站点活 + 免费注册 key + API 工作,但 bulk export 付费;免费档仅单点 rate-limited 查询(1 req/秒级) | 不符合免费离线约束 → 排除;或降为 online 富查询源(非 bulk,不入 Source pool) | pricing/about 页 Feed $X/mo + API doc 'free account' 措辞误导 |

## 工具

- Exa 搜新 URL:`mcporter call 'exa.web_search_exa(query: "...", numResults: 5)'`(agent-reach skill)
- jina 读:`curl -s "https://r.jina.ai/<URL>"`
- gh 搜社区证据:`gh search issues "<source> discontinued"`
- **pricing 验证**(需 key 的源必读):`curl -s "https://r.jina.ai/<site>/about/feed"` 或 `/pricing`,确认免费档含 bulk export

## 案例(2026-07-31)

- cruzit:域名 GoDaddy 挂售 + firehol #304 站长停运声明 → **真死,排除**
- nothink:作者首页 "data is no longer shared" → **真死,排除**
- greensnow:旧 /list 404,Exa 找到 blocklist.greensnow.co/greensnow.txt(200,3677 IP) → **换 URL,加**
- bambenek:站点活但 403(本地 + 代理都拉不到) → **受限,放弃 + 记录**(顶级 C2,但修 ROI 不确定,每个受限源都修会拖慢闭环)
- sans:DNS 只解析 Cloudflare IPv6(WSL IPv6 不通)+ jina 空 → **受限,放弃**
- pulsedive:API doc 'free account' + key 有效(indicator.php 返回 IP/risk/threats),但 about/feed 显示 Feed $1,500-3,000/mo,免费档仅 API 单点(1 req/秒),explore 是 ioc 搜索非 bulk → **免费 key 但 bulk 付费,排除**(停止信号 #3 约束触顶)
