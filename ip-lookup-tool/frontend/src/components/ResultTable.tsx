import { useState, useMemo, useEffect, Fragment } from "react";
import { motion, AnimatePresence, useReducedMotion } from "motion/react";
import type { LookupResult, MergedField, ClassificationAssessment } from "../api";

interface ResultTableProps {
  results: LookupResult[];
}

type SortKey = "ip" | "asn" | "country" | "as_name" | "verdict" | "threat" | "ip_range";

// Confidence color: continuous from red (0) → amber (50) → emerald (95+)
function confColor(conf: number): string {
  if (conf >= 70) return "bg-emerald-500";
  if (conf >= 30) return "bg-amber-500";
  return "bg-red-500";
}

function confTextColor(conf: number): string {
  if (conf >= 70) return "text-emerald-400";
  if (conf >= 30) return "text-amber-400";
  return "text-red-400";
}

// ── 判定 (verdict) — dominant color anchor. 红=恶意 / 橙=可疑 / 绿=可信 / 灰=未知 ──
const VERDICT_LABEL: Record<string, string> = {
  malicious: "恶意",
  suspicious: "可疑",
  benign: "可信",
  informational: "未知",
  clean: "可信",
};
const VERDICT_STYLE: Record<string, string> = {
  malicious: "bg-red-500/15 text-red-300 ring-1 ring-red-500/30",
  suspicious: "bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30",
  benign: "bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/30",
  informational: "bg-zinc-500/15 text-zinc-400 ring-1 ring-zinc-500/25",
  clean: "bg-zinc-700/40 text-zinc-500 ring-1 ring-zinc-600/40",
};
const VERDICT_RANK: Record<string, number> = {
  malicious: 3, suspicious: 2, benign: 1, informational: 0, clean: 0,
};

// 基础设施类标签 (anonymizing infra): neutral, not malicious.
const INFRA_TYPES = new Set(["tor", "proxy", "vpn", "hosting", "scanner_hosting"]);

// Normalize backend keys: hyphen → underscore ("brute-force" ≡ "brute_force").
function normType(type: string): string {
  return type.replace(/-/g, "_");
}

const CLASS_LABELS: Record<string, string> = {
  "c2_server": "C2",
  botnet_cc: "C2",
  scanner: "扫描",
  brute_force: "暴力破解",
  malware: "恶意软件",
  blacklist: "黑名",
  tor: "Tor",
  proxy: "代理",
  hosting: "机房",
  vpn: "VPN",
};

// Asset attribute labels (rendered in the asset zone, separate from threats).
const ASSET_LABELS: Record<string, string> = {
  is_proxy: "代理",
  is_hosting: "机房",
  is_tor: "Tor",
  is_vpn: "VPN",
  carrier: "运营商",
};

// Classification types that ALSO appear as asset keys — when a classification
// of this type exists, the asset badge is suppressed to avoid duplication.
const ASSET_DUPLICATES_CLASSIFICATION = new Set(["is_tor", "is_vpn", "is_proxy"]);

function assetBadges(r: LookupResult): { label: string; detail: string; key: string }[] {
  const out: { label: string; detail: string; key: string }[] = [];
  const classTypes = new Set(Object.keys(r.classifications));
  for (const [key, stmts] of Object.entries(r.attributes ?? {})) {
    if (!ASSET_LABELS[key]) continue;
    // De-dup: if classification already covers this, skip
    if (ASSET_DUPLICATES_CLASSIFICATION.has(key)) {
      const ctype: Record<string, string> = { is_tor: "tor", is_proxy: "proxy", is_vpn: "vpn" };
      if (classTypes.has(ctype[key])) continue;
    }
    const first = stmts[0];
    if (!first) continue;
    let detail = first.source;
    if (first.native_type) detail += ` · ${first.native_type}`;
    if (key === "carrier") detail = String(first.value);
    out.push({ label: ASSET_LABELS[key], detail, key });
  }
  return out;
}

const CLASS_PALETTE: Record<string, string> = {
  // 行为类 (active malice) — red/orange
  "c2_server": "bg-red-500/15 text-red-400 ring-1 ring-red-500/25",
  botnet_cc: "bg-red-500/15 text-red-400 ring-1 ring-red-500/25",
  malware: "bg-red-500/15 text-red-400 ring-1 ring-red-500/25",
  blacklist: "bg-red-500/15 text-red-400 ring-1 ring-red-500/25",
  scanner: "bg-orange-500/15 text-orange-400 ring-1 ring-orange-500/25",
  brute_force: "bg-orange-500/15 text-orange-400 ring-1 ring-orange-500/25",
  // 基础设施类 (anonymizing) — cyan/sky, neutral
  tor: "bg-cyan-500/12 text-cyan-400 ring-1 ring-cyan-500/20",
  proxy: "bg-cyan-500/12 text-cyan-400 ring-1 ring-cyan-500/20",
  vpn: "bg-cyan-500/12 text-cyan-400 ring-1 ring-cyan-500/20",
  hosting: "bg-sky-500/12 text-sky-400 ring-1 ring-sky-500/20",
};
const INFRA_FALLBACK = "bg-cyan-500/12 text-cyan-400 ring-1 ring-cyan-500/20";
const BEHAVIORAL_FALLBACK = "bg-orange-500/15 text-orange-400 ring-1 ring-orange-500/25";

function isInfra(type: string): boolean {
  const t = normType(type);
  return INFRA_TYPES.has(t) ||
    t.includes("tor") || t.includes("proxy") || t.includes("vpn") || t.includes("hosting");
}

function classPalette(type: string): string {
  const t = normType(type);
  if (CLASS_PALETTE[t]) return CLASS_PALETTE[t];
  if (t.includes("c2") || t.includes("botnet")) return CLASS_PALETTE["c2_server"];
  if (t.includes("malware")) return CLASS_PALETTE["malware"];
  if (t.includes("scan")) return CLASS_PALETTE["scanner"];
  if (t.includes("brute")) return CLASS_PALETTE["brute_force"];
  return isInfra(t) ? INFRA_FALLBACK : BEHAVIORAL_FALLBACK;
}

function classLabel(type: string): string {
  const t = normType(type);
  return CLASS_LABELS[t] ?? t.replace(/_/g, " ");
}

// Shorten a malware family for inline chip: "win.dcrat" → "dcrat".
function familyShort(name: string): string {
  return name.replace(/^(win|linux|mac|osx|android|ios|trojan|worm|backdoor)[._-]/i, "");
}

// Aggregate threat signal across all classifications on one IP.
function threatSummary(r: LookupResult): {
  verdict: string; confidence: number; sourceCount: number;
  corroborated: boolean; conflict: boolean; hasThreats: boolean;
} {
  const cas = Object.values(r.classifications).filter((c) => c.detected && c.confidence > 0);
  if (cas.length === 0) {
    return { verdict: "clean", confidence: 0, sourceCount: 0, corroborated: false, conflict: false, hasThreats: false };
  }
  let worst = cas[0];
  for (const c of cas) {
    if ((VERDICT_RANK[c.verdict] ?? 0) > (VERDICT_RANK[worst.verdict] ?? 0)) worst = c;
  }
  const worstVerdict = worst.verdict;
  const confidence = Math.max(...cas.filter((c) => c.verdict === worstVerdict).map((c) => c.confidence));
  const sources = new Set<string>();
  for (const c of cas) for (const s of c.sources) sources.add(s.source);
  return {
    verdict: worstVerdict,
    confidence,
    sourceCount: sources.size,
    corroborated: cas.some((c) => c.corroborated),
    conflict: cas.some((c) => c.verdict_conflict),
    hasThreats: true,
  };
}

const ALGORITHM_ICONS: Record<string, string> = {
  cascade: "🔑",
  voting: "📊",
  pcr6: "⚠️",
  authority: "🏛️",
  specificity: "🎯",
  corroboration: "🤝",
};

function VerdictCell({ summary }: { summary: ReturnType<typeof threatSummary> }) {
  const label = VERDICT_LABEL[summary.verdict] ?? "未知";
  const style = VERDICT_STYLE[summary.verdict] ?? VERDICT_STYLE.informational;
  const showConf = summary.verdict === "malicious" || summary.verdict === "suspicious";
  const tooltip = summary.hasThreats
    ? `${label}${showConf ? ` 置信度 ${summary.confidence}` : ""}${summary.sourceCount ? ` · ${summary.sourceCount} 源` : ""}${summary.corroborated ? " · 已印证" : ""}${summary.conflict ? " · 判定冲突" : ""}`
    : "未命中威胁情报";
  return (
    <span title={tooltip} className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-semibold ${style}`}>
      {label}
      {showConf && <span className="font-mono text-[10px] opacity-80">{summary.confidence}</span>}
    </span>
  );
}

function ThreatTags({ r, summary }: { r: LookupResult; summary: ReturnType<typeof threatSummary> }) {
  const keys = Object.keys(r.classifications).filter((t) => {
    const ca = r.classifications[t];
    return ca.detected && ca.confidence > 0;
  });
  if (keys.length === 0) return <span className="text-zinc-700 text-[11px]">-</span>;
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      {keys.map((type) => {
        const ca = r.classifications[type];
        const label = classLabel(type);
        const family = ca.malware_names.length > 0 ? familyShort(ca.malware_names[0]) : null;
        const tooltip = `${label}: ${VERDICT_LABEL[ca.verdict] ?? ca.verdict}, 置信度 ${ca.confidence}${ca.corroborated ? ", 已印证" : ""}`;
        return (
          <span key={type} title={tooltip} className={`rounded px-1.5 py-0.5 text-[11px] font-medium ${classPalette(type)}`}>
            {label}{family && <span className="ml-0.5 opacity-70">·{family}</span>}
          </span>
        );
      })}
      {summary.sourceCount > 0 && (
        <span className="text-[10px] text-zinc-500" title="命中情报源数">
          {summary.sourceCount}源{summary.corroborated && <span className="ml-px text-emerald-400">✓</span>}
        </span>
      )}
      {summary.conflict && (
        <span className="rounded bg-amber-500/15 px-1 py-0.5 text-[10px] font-medium text-amber-400 ring-1 ring-amber-500/25" title="多源判定冲突">
          ⚠冲突
        </span>
      )}
    </span>
  );
}

function lowestConfidence(r: LookupResult): number {
  const confs = [
    r.country.confidence,
    r.asn.confidence,
    r.as_name.confidence,
    r.ip_range.confidence,
    ...Object.values(r.classifications).map((c) => c.confidence),
  ];
  return Math.min(...confs);
}

function FieldDetail<T>({
  label,
  field,
  format,
}: {
  label: string;
  field: MergedField<T>;
  format: (v: T) => string;
}) {
  const entries = field.sources;
  if (entries.length === 0) return null;
  return (
    <div>
      <div className="flex items-center gap-2 mb-1">
        <span className="text-xs font-medium text-zinc-300">{label}</span>
        <span className="text-[10px] text-zinc-500">{format(field.value)}</span>
        <span className={`inline-block h-1.5 w-1.5 rounded-full ${confColor(field.confidence)}`} />
        <span className={`text-[10px] ${confTextColor(field.confidence)}`}>
          {field.confidence}
        </span>
        <span className="text-[10px] text-zinc-600">
          {ALGORITHM_ICONS[field.algorithm] ?? field.algorithm}
        </span>
      </div>
      {entries.length > 0 && (
        <div className="ml-3 flex flex-wrap gap-x-4 gap-y-0.5">
          {entries.map((s) => (
            <span key={s.source} className="text-[11px]">
              <span className="text-zinc-500">{s.source}</span>
              {s.authoritative && (
                <span className="text-amber-400 ml-0.5" title="authoritative">★</span>
              )}
              <span className="text-zinc-700 mx-1">:</span>
              <span className="text-zinc-400">{format(s.value)}</span>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function ClassificationDetailPanel({ classifications }: { classifications: Record<string, ClassificationAssessment> }) {
  const keys = Object.keys(classifications);
  if (keys.length === 0) {
    return (
      <div>
        <span className="text-xs font-medium text-zinc-300">威胁明细</span>
        <div className="ml-3 mt-1 text-[11px] text-zinc-600">未命中</div>
      </div>
    );
  }
  return (
    <div>
      <span className="text-xs font-medium text-zinc-300">威胁明细</span>
      <div className="ml-3 mt-1 space-y-2.5">
        {keys.map((type) => {
          const ca = classifications[type];
          return (
            <div key={type}>
              <div className="flex items-center gap-1.5 flex-wrap">
                <span className={`inline-block h-1.5 w-1.5 rounded-full ${ca.detected ? "bg-orange-400" : "bg-zinc-600"}`} />
                <span className="text-[11px] text-zinc-400 font-medium">{classLabel(type)}</span>
                <span className={`rounded px-1 py-px text-[10px] font-medium ${VERDICT_STYLE[ca.verdict] ?? VERDICT_STYLE.informational}`}>
                  {VERDICT_LABEL[ca.verdict] ?? ca.verdict}
                </span>
                <span className={`text-[10px] ${confTextColor(ca.confidence)}`}>{ca.confidence}</span>
                <span className="text-[10px] text-zinc-600">{ALGORITHM_ICONS[ca.algorithm] ?? ca.algorithm}</span>
                {ca.corroborated && (
                  <span className="text-[10px] text-amber-400" title="2+ 独立源印证">已印证</span>
                )}
                {ca.verdict_conflict && (
                  <span className="text-[10px] text-red-400" title="源之间判定冲突">判定冲突</span>
                )}
              </div>
              {/* 恶意软件家族 */}
              {ca.malware_names.length > 0 && (
                <div className="ml-3 mt-1 flex flex-wrap gap-1">
                  {ca.malware_names.map((m) => (
                    <span key={m} className="rounded bg-purple-500/10 px-1 py-px text-[10px] text-purple-400 font-mono">{m}</span>
                  ))}
                </div>
              )}
              {/* 每源明细 */}
              {ca.details.length > 0 && (
                <div className="ml-3 mt-1 flex flex-wrap gap-x-4 gap-y-0.5">
                  {ca.details.map((d, idx) => (
                    <span key={d.source + idx} className="text-[10px] leading-relaxed">
                      <span className="text-zinc-600">{d.source}</span>
                      {d.native_type && (
                        <span className="text-zinc-500 ml-1" title="源原生类型">
                          [{d.native_type}]
                        </span>
                      )}
                      {d.native_confidence != null && (
                        <span className="text-zinc-500 ml-0.5">{d.native_confidence}</span>
                      )}
                      {d.first_seen && (
                        <span className="text-zinc-700 ml-1">{d.first_seen.slice(0, 10)}</span>
                      )}
                    </span>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function ExpandableDetail({ r }: { r: LookupResult }) {
  return (
    <td colSpan={7} className="px-5 py-3 bg-zinc-900/60 border-b border-zinc-800/40">
      <div className="grid gap-2.5">
        <FieldDetail label="国家" field={r.country} format={String} />
        <FieldDetail label="ASN" field={r.asn} format={(v) => String(v)} />
        <FieldDetail label="机构 / ISP" field={r.as_name} format={String} />
        <ClassificationDetailPanel classifications={r.classifications} />
        <FieldDetail label="网段" field={r.ip_range} format={String} />
      </div>
    </td>
  );
}

function SummaryBar({ results }: { results: LookupResult[] }) {
  const stats = useMemo(() => {
    const classTotals: Record<string, number> = {};
    let ispCount = 0;
    let lowConf = 0;
    let medConf = 0;
    let highConf = 0;

    for (const r of results) {
      for (const type of Object.keys(r.classifications)) {
        classTotals[type] = (classTotals[type] || 0) + 1;
      }
      if (r.is_isp) ispCount++;
      const c = lowestConfidence(r);
      if (c < 30) lowConf++;
      else if (c < 70) medConf++;
      else highConf++;
    }

    return { classTotals, ispCount, lowConf, medConf, highConf };
  }, [results]);

  const activeClasses = Object.keys(stats.classTotals);
  if (activeClasses.length === 0 && stats.ispCount === 0 && stats.lowConf === 0 && stats.medConf === 0) {
    return (
      <div className="flex items-center gap-3 text-xs text-zinc-500">
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-500" />
          全部 {results.length.toLocaleString()} 条 高置信
        </span>
      </div>
    );
  }

  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-zinc-400">
      {stats.lowConf > 0 && (
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-red-500" />
          {stats.lowConf} 低置信
        </span>
      )}
      {stats.medConf > 0 && (
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-amber-500" />
          {stats.medConf} 中置信
        </span>
      )}
      {stats.highConf > 0 && (
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-500" />
          {stats.highConf} 高置信
        </span>
      )}
      {activeClasses.length > 0 && <span className="text-zinc-600">|</span>}
      {activeClasses.map((type) => (
        <span key={type} className="flex items-center gap-1">
          <span className={`rounded px-1 py-0.5 text-[10px] font-medium ${classPalette(type)}`}>
            {classLabel(type)}
          </span>
          <span className="text-zinc-500">{stats.classTotals[type]}</span>
        </span>
      ))}
      {stats.ispCount > 0 && (
        <>
          <span className="text-zinc-600">|</span>
          <span className="flex items-center gap-1">
            <span className="rounded bg-emerald-500/15 px-1 py-0.5 text-[10px] font-medium text-emerald-400 ring-1 ring-emerald-500/25">
              ISP
            </span>
            <span className="text-zinc-500">{stats.ispCount}</span>
          </span>
        </>
      )}
    </div>
  );
}

function ScoredCell({
  value,
  confidence,
  valueClass = "text-zinc-300",
}: {
  value: React.ReactNode;
  confidence: number;
  valueClass?: string;
}) {
  return (
    <td className="px-3 py-2 whitespace-nowrap">
      <span className={valueClass}>{value}</span>
      <span className={`ml-1 text-[10px] ${confTextColor(confidence)}`}>({confidence})</span>
    </td>
  );
}

const PAGE_SIZE_OPTIONS = [20, 50, 100, 200];

function Pagination({
  page,
  pageCount,
  pageSize,
  total,
  onPage,
  onPageSize,
}: {
  page: number;
  pageCount: number;
  pageSize: number;
  total: number;
  onPage: (p: number) => void;
  onPageSize: (s: number) => void;
}) {
  if (total === 0) return null;
  const from = page * pageSize + 1;
  const to = Math.min((page + 1) * pageSize, total);
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-zinc-400">
      <div className="flex items-center gap-2">
        <span className="text-zinc-500">每页</span>
        <select
          value={pageSize}
          onChange={(e) => onPageSize(Number(e.target.value))}
          className="rounded-md border border-zinc-800 bg-zinc-900 px-2 py-1 text-xs text-zinc-300 focus:outline-none focus:ring-1 focus:ring-emerald-500/30"
        >
          {PAGE_SIZE_OPTIONS.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <span className="text-zinc-500 tabular-nums">
          {from.toLocaleString()}–{to.toLocaleString()} / {total.toLocaleString()}
        </span>
      </div>
      {pageCount > 1 && (
        <div className="flex items-center gap-1">
          <button
            onClick={() => onPage(page - 1)}
            disabled={page === 0}
            className="rounded-md bg-zinc-800 px-2.5 py-1 text-zinc-300 transition-colors hover:text-emerald-400 disabled:opacity-30 disabled:cursor-not-allowed"
          >
            ‹
          </button>
          <span className="px-2 text-zinc-400 tabular-nums">
            {page + 1} / {pageCount}
          </span>
          <button
            onClick={() => onPage(page + 1)}
            disabled={page >= pageCount - 1}
            className="rounded-md bg-zinc-800 px-2.5 py-1 text-zinc-300 transition-colors hover:text-emerald-400 disabled:opacity-30 disabled:cursor-not-allowed"
          >
            ›
          </button>
        </div>
      )}
    </div>
  );
}

export function ResultTable({ results }: ResultTableProps) {
  const [sortKey, setSortKey] = useState<SortKey | null>(null);
  const [sortAsc, setSortAsc] = useState(true);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [disagreementsFirst, setDisagreementsFirst] = useState(false);
  const [filter, setFilter] = useState("");
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(50);
  const reduce = useReducedMotion();

  // Reset to first page whenever the result set or view config changes.
  useEffect(() => {
    setPage(0);
  }, [results, filter, sortKey, sortAsc, disagreementsFirst, pageSize]);

  const filtered = useMemo(() => {
    if (!filter.trim()) return results;
    const q = filter.trim().toLowerCase();
    return results.filter((r) =>
      r.ip.toLowerCase().includes(q) ||
      r.as_name.value.toLowerCase().includes(q) ||
      r.country.value.toLowerCase().includes(q) ||
      r.ip_range.value.toLowerCase().includes(q)
    );
  }, [results, filter]);

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortAsc(!sortAsc);
    } else {
      setSortKey(key);
      setSortAsc(true);
    }
  };

  const fieldValue = (r: LookupResult, key: SortKey): string | number => {
    switch (key) {
      case "ip": return r.ip;
      case "asn": return typeof r.asn.value === "number" ? r.asn.value : 0;
      case "country": return r.country.value;
      case "as_name": return r.as_name.value;
      case "verdict": return VERDICT_RANK[threatSummary(r).verdict] ?? 0;
      case "threat": {
        return Object.keys(r.classifications).filter((t) => {
          const ca = r.classifications[t];
          return ca.detected && ca.confidence > 0;
        }).length;
      }
      case "ip_range": return r.ip_range.value;
    }
  };

  const sorted = useMemo(() => {
    let arr = [...filtered];
    if (disagreementsFirst) {
      arr.sort((a, b) => lowestConfidence(a) - lowestConfidence(b));
      return arr;
    }
    if (!sortKey) return arr;
    return arr.sort((a, b) => {
      const va = fieldValue(a, sortKey);
      const vb = fieldValue(b, sortKey);
      if (typeof va === "number" && typeof vb === "number") {
        return sortAsc ? va - vb : vb - va;
      }
      return sortAsc
        ? String(va).localeCompare(String(vb))
        : String(vb).localeCompare(String(va));
    });
  }, [filtered, sortKey, sortAsc, disagreementsFirst]);

  // Pagination: render only the current page slice. Sorting/filtering still
  // run on the full set above (correct order); this just caps the DOM count.
  const pageCount = Math.max(1, Math.ceil(sorted.length / pageSize));
  const safePage = Math.min(page, pageCount - 1);
  const pageStart = safePage * pageSize;
  const pageRows = sorted.slice(pageStart, pageStart + pageSize);

  const toggleRow = (ip: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(ip)) next.delete(ip);
      else next.add(ip);
      return next;
    });
  };

  const expandDisagreements = () => {
    const ips = filtered
      .filter((r) => lowestConfidence(r) < 70)
      .map((r) => r.ip);
    setExpanded(new Set(ips));
  };

  const cols: { key: SortKey; label: string; className?: string }[] = [
    { key: "ip", label: "IP" },
    { key: "asn", label: "ASN", className: "w-24" },
    { key: "country", label: "国家", className: "w-24" },
    { key: "as_name", label: "ISP/Org" },
    { key: "verdict", label: "判定", className: "w-20 text-center" },
    { key: "threat", label: "威胁标签", className: "min-w-[180px]" },
    { key: "ip_range", label: "Range", className: "w-44" },
  ];

  return (
    <div className="space-y-3">
      <SummaryBar results={results} />

      <div className="flex flex-wrap items-center gap-2">
        <input
          type="text"
          placeholder="Filter by IP, org, country, range..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="flex-1 min-w-48 rounded-md border border-zinc-800 bg-zinc-900 px-3 py-1.5 text-xs text-zinc-300 placeholder:text-zinc-600 focus:border-emerald-500/40 focus:outline-none focus:ring-1 focus:ring-emerald-500/20"
        />
        <button
          onClick={() => setDisagreementsFirst(!disagreementsFirst)}
          className={`rounded-md px-2.5 py-1.5 text-xs transition-colors ${
            disagreementsFirst
              ? "bg-amber-500/15 text-amber-400 ring-1 ring-amber-500/25"
              : "bg-zinc-800 text-zinc-500 hover:text-zinc-300"
          }`}
        >
          Disagreements first
        </button>
        <button
          onClick={expandDisagreements}
          className="rounded-md bg-zinc-800 px-2.5 py-1.5 text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
        >
          Expand disagreements
        </button>
        <button
          onClick={() => {
            const ip = results[0]?.ip;
            if (ip) window.open(`/api/lookup/${ip}/stix`, "_blank");
          }}
          disabled={results.length !== 1}
          className="rounded-md bg-zinc-800 px-2.5 py-1.5 text-xs text-zinc-500 hover:text-zinc-300 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          title={results.length !== 1 ? "STIX export works on single-IP lookups" : "Export STIX 2.1 Bundle"}
        >
          Export STIX
        </button>
        {filter && (
          <span className="text-xs text-zinc-500">
            {filtered.length.toLocaleString()} of {results.length.toLocaleString()}
          </span>
        )}
      </div>

      <div className="overflow-auto rounded-lg border border-zinc-800">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-zinc-800 bg-zinc-900/80">
              {cols.map((col) => (
                <th
                  key={col.key}
                  onClick={() => handleSort(col.key)}
                  className={`cursor-pointer px-3 py-2.5 text-[11px] font-medium uppercase tracking-wider text-zinc-500 hover:text-emerald-400 transition-colors select-none ${col.className ?? ""}`}
                >
                  {col.label}
                  {sortKey === col.key && (
                    <span className="ml-1 text-emerald-500">{sortAsc ? "↑" : "↓"}</span>
                  )}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {pageRows.map((r, i) => {
              const summary = threatSummary(r);
              return (
              <Fragment key={r.ip + i}>
                <motion.tr
                  initial={reduce ? false : { opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{
                    duration: 0.25,
                    delay: reduce ? 0 : Math.min(i * 0.02, 0.4),
                    ease: [0.16, 1, 0.3, 1],
                  }}
                  onClick={() => toggleRow(r.ip)}
                  className={`cursor-pointer border-b border-zinc-800/40 font-mono text-xs transition-colors hover:bg-zinc-800/60 ${
                    expanded.has(r.ip) ? "bg-zinc-800/40" : ""
                  }`}
                >
                  <td className="px-3 py-2 text-zinc-100 font-semibold">{r.ip}</td>
                  <ScoredCell value={r.asn.value} confidence={r.asn.confidence} />
                  <ScoredCell value={r.country.value} confidence={r.country.confidence} />
                  <td className="px-3 py-2 whitespace-nowrap">
                    <span className="text-zinc-300">{r.as_name.value}</span>
                    <span className={`ml-1 text-[10px] ${confTextColor(r.as_name.confidence)}`}>({r.as_name.confidence})</span>
                    {r.is_isp && (
                      <span className="ml-1.5 rounded bg-emerald-500/15 px-1 py-0.5 text-[10px] text-emerald-400 ring-1 ring-emerald-500/25">
                        ISP
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-center">
                    <VerdictCell summary={summary} />
                  </td>
                  <td className="px-3 py-2">
                    <ThreatTags r={r} summary={summary} />
                    {assetBadges(r).length > 0 && (
                      <span className="inline-flex flex-wrap items-center gap-1 ml-1">
                        {assetBadges(r).map((a) => (
                          <span key={`asset-${a.key}`} className="inline-flex items-center rounded px-1.5 py-0.5 text-[11px] bg-sky-500/12 text-sky-400 ring-1 ring-sky-500/20" title={a.detail}>
                            {a.label}{a.key !== "carrier" ? "" : `: ${a.detail}`}
                          </span>
                        ))}
                      </span>
                    )}
                  </td>
                  <ScoredCell value={r.ip_range.value} confidence={r.ip_range.confidence} valueClass="text-zinc-500" />
                </motion.tr>
                <AnimatePresence>
                  {expanded.has(r.ip) && (
                    <motion.tr
                      key={"detail-" + r.ip}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      transition={{ duration: 0.15 }}
                    >
                      <ExpandableDetail r={r} />
                    </motion.tr>
                  )}
                </AnimatePresence>
              </Fragment>
              );
            })}
            {sorted.length === 0 && filter && (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-xs text-zinc-600">
                  No results matching "{filter}"
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <Pagination
        page={safePage}
        pageCount={pageCount}
        pageSize={pageSize}
        total={sorted.length}
        onPage={setPage}
        onPageSize={setPageSize}
      />
    </div>
  );
}
