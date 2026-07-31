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
