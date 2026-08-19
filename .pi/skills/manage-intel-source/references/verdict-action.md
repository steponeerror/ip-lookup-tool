# Verdict → Action(全 lever 表)

## weight-invariant 警告(先读)

降 SOURCE_RELIABILITY **不改 verdict、不改该源贡献的 IP**,只改 fusion 数值话语权 + STIX `x_reliability`。
想真正改变采用状态(问题源别贡献 / 某源别报 fp)必须 **disable / tighten noise filter / 精简数据**,光降权对 MIXED/NEGATIVE 无效。

## 全 lever 表

| verdict | action |
|---|---|
| POSITIVE-VERIFIED | 留,维持权重 |
| POSITIVE-UNVERIFIED | 降权(权威源例外,见下) |
| MIXED | 查 cost lever:conflict→查冲突源;fp→tighten load-time noise filter 或 disable;other 膨胀→收紧 `_MAP` |
| MARGINAL | 非权威→降权/精简;权威(is_malicious 等)→不动 |
| NEGATIVE | disable |
| INSUFFICIENT-SAMPLE | 补样本/换 corpus(别误判源差;多为 corpus 偏向,geo 源 IP 不在威胁 corpus) |
| N/A-ASSET | asset 源(is_tor/is_vpn/...)——不走 corroboration,按 AUTHORITATIVE_SOURCES 权威加权,不降 |

## 数值分档表(混合依据:分档 + 权威源第三方校准)

| 类型 | 基线 | 例 |
|---|---|---|
| 权威 curated | 0.85–0.90 | spamhaus, emerging_threats, threatfox, abuseipdb |
| 社区聚合 | 0.50–0.70 | otx, firehol, ipsum, blocklist_de, binarydefense, urlhaus, tweetfeed |
| asset 权威 | 0.70–0.95 | tor_exits, x4bnet_vpn, ip2proxy |

- UNVERIFIED 在所属档内 **-0.10~0.15**。
- **权威源(abuseipdb 等)即使 UNVERIFIED 也保持中高(≥0.65),别深度降**——CG=0 对权威源是「独家发现」(独立 IP 池)而非「不可信」;具体数值结合第三方校准 + 用户判断,不只靠分档推算。
- 权威源(影响大)额外查第三方实测(见 `third-party-calibration.md`)。

## 案例(2026-07-31)

- abuseipdb UNVERIFIED CG=0 → 0.75→0.65(权威,用户判断,不深度降)
- otx UNVERIFIED CG=0 → 0.75→0.55(社区)
- emerging_threats VERIFIED 但 ACNS'20 实测平庸 → 0.90→0.85(第三方校准下调)
- spamhaus MARGINAL OC=1.0 但 is_malicious 权威 → 0.90 不动
- tor_exits/x4bnet_vpn → N/A-ASSET(harness 修复后)
