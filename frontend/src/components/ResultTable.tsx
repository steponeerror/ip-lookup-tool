import { useState, useMemo, useEffect, Fragment } from "react";
import { motion, AnimatePresence, useReducedMotion } from "motion/react";
import type { LookupResult } from "../api";
import {
  confTextColor, VERDICT_STYLE, VERDICT_RANK, verdictLabelKey,
  normType, classLabel, familyShort, threatSummary,
} from "./threatDisplay";
import { useI18n } from "../i18n";
import { IpDetailPanel } from "./IpDetailPanel";

type TFn = (key: string, vars?: Record<string, string | number>) => string;

interface ResultTableProps {
  results: LookupResult[];
}

type SortKey = "ip" | "asn" | "country" | "as_name" | "verdict" | "threat" | "ip_range";

// 基础设施类标签 (anonymizing infra): neutral, not malicious.
const INFRA_TYPES = new Set(["tor", "proxy", "vpn", "hosting", "scanner_hosting"]);

// Classification types that ALSO appear as asset keys — when a classification
// of this type exists, the asset badge is suppressed to avoid duplication.
const ASSET_DUPLICATES_CLASSIFICATION = new Set(["is_tor", "is_vpn", "is_proxy"]);

function assetBadges(r: LookupResult, t: TFn): { label: string; detail: string; key: string }[] {
  const out: { label: string; detail: string; key: string }[] = [];
  const classTypes = new Set(Object.keys(r.classifications));
  for (const [key, stmts] of Object.entries(r.attributes ?? {})) {
    const assetKey = {
      is_proxy: "asset.is_proxy",
      is_hosting: "asset.is_hosting",
      is_tor: "asset.is_tor",
      is_vpn: "asset.is_vpn",
      carrier: "asset.carrier",
    }[key];
    if (!assetKey) continue;
    // De-dup: if classification already covers this, skip
    if (ASSET_DUPLICATES_CLASSIFICATION.has(key)) {
      const ctype: Record<string, string> = { is_tor: "tor", is_proxy: "proxy", is_vpn: "proxy" };
      if (classTypes.has(ctype[key])) continue;
    }
    const first = stmts[0];
    if (!first) continue;
    let detail = first.source;
    if (first.native_type) detail += ` · ${first.native_type}`;
    if (key === "carrier") detail = String(first.value);
    out.push({ label: t(assetKey), detail, key });
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

function VerdictCell({ summary }: { summary: ReturnType<typeof threatSummary> }) {
  const { t } = useI18n();
  const label = t(verdictLabelKey(summary.verdict));
  const style = VERDICT_STYLE[summary.verdict] ?? VERDICT_STYLE.informational;
  const showConf = summary.verdict === "malicious" || summary.verdict === "suspicious";
  const tooltip = summary.hasThreats
    ? `${label}${showConf ? ` ${t("common.confidence")} ${summary.confidence}` : ""}${summary.sourceCount ? ` · ${t("common.sourceCount", { n: summary.sourceCount })}` : ""}${summary.corroborated ? ` · ${t("common.corroborated")}` : ""}${summary.conflict ? ` · ${t("common.conflict")}` : ""}`
    : "";
  if (summary.verdict === "reserved") {
    return (
      <span title={t("reserved.notice")}
        className={`inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-semibold ${VERDICT_STYLE.reserved}`}>
        {t("verdict.reserved")}
      </span>
    );
  }
  if (!summary.hasThreats) return <span className="text-zinc-700 text-[11px]">-</span>;
  return (
    <span title={tooltip} className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-semibold ${style}`}>
      {label}
      {showConf && <span className="font-mono text-[10px] opacity-80">{summary.confidence}</span>}
    </span>
  );
}

function ThreatTags({ r, summary }: { r: LookupResult; summary: ReturnType<typeof threatSummary> }) {
  const { t } = useI18n();
  const keys = Object.keys(r.classifications).filter((t) => {
    const ca = r.classifications[t];
    return ca.detected && ca.confidence > 0;
  });
  if (keys.length === 0) return <span className="text-zinc-700 text-[11px]">-</span>;
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      {keys.map((type) => {
        const ca = r.classifications[type];
        const label = classLabel(type, t);
        const family = ca.malware_names.length > 0 ? familyShort(ca.malware_names[0]) : null;
        const tooltip = `${label}: ${t(verdictLabelKey(ca.verdict))}, ${t("common.confidence")} ${ca.confidence}${ca.corroborated ? `, ${t("common.corroborated")}` : ""}`;
        return (
          <span key={type} title={tooltip} className={`rounded px-1.5 py-0.5 text-[11px] font-medium ${classPalette(type)}`}>
            {label}{family && <span className="ml-0.5 opacity-70">·{family}</span>}
          </span>
        );
      })}
      {summary.sourceCount > 0 && (
        <span className="text-[10px] text-zinc-500" title={t("common.sourcesHit")}>
          {t("common.sourceCount", { n: summary.sourceCount })}{summary.corroborated && <span className="ml-px text-emerald-400">✓</span>}
        </span>
      )}
      {summary.conflict && (
        <span className="rounded bg-amber-500/15 px-1 py-0.5 text-[10px] font-medium text-amber-400 ring-1 ring-amber-500/25" title={t("common.conflictTooltip")}>
          {t("common.conflictBadge")}
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

export function SummaryBar({ results }: { results: LookupResult[] }) {
  const { t } = useI18n();
  const stats = useMemo(() => {
    const classTotals: Record<string, number> = {};
    let ispCount = 0;
    let lowConf = 0;
    let medConf = 0;
    let highConf = 0;
    let reservedCount = 0;

    for (const r of results) {
      if (r.is_reserved) {
        reservedCount++;
        continue;
      }
      for (const type of Object.keys(r.classifications)) {
        classTotals[type] = (classTotals[type] || 0) + 1;
      }
      if (r.is_isp) ispCount++;
      const c = lowestConfidence(r);
      if (c < 30) lowConf++;
      else if (c < 70) medConf++;
      else highConf++;
    }

    return { classTotals, ispCount, lowConf, medConf, highConf, reservedCount };
  }, [results]);

  const activeClasses = Object.keys(stats.classTotals);
  if (activeClasses.length === 0 && stats.ispCount === 0 && stats.lowConf === 0 && stats.medConf === 0 && stats.reservedCount === 0) {
    return (
      <div className="flex items-center gap-3 text-xs text-zinc-500">
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-500" />
          {t("summary.allHigh", { n: results.length.toLocaleString() })}
        </span>
      </div>
    );
  }

  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-zinc-400">
      {stats.lowConf > 0 && (
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-red-500" />
          {t("summary.lowConf", { n: stats.lowConf.toLocaleString() })}
        </span>
      )}
      {stats.medConf > 0 && (
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-amber-500" />
          {t("summary.medConf", { n: stats.medConf.toLocaleString() })}
        </span>
      )}
      {stats.highConf > 0 && (
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-500" />
          {t("summary.highConf", { n: stats.highConf.toLocaleString() })}
        </span>
      )}
      {activeClasses.length > 0 && <span className="text-zinc-600">|</span>}
      {activeClasses.map((type) => (
        <span key={type} className="flex items-center gap-1">
          <span className={`rounded px-1 py-0.5 text-[10px] font-medium ${classPalette(type)}`}>
            {classLabel(type, t)}
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
      {stats.reservedCount > 0 && (
        <>
          <span className="text-zinc-600">|</span>
          <span className="flex items-center gap-1">
            <span className="rounded bg-zinc-600/40 px-1 py-0.5 text-[10px] font-medium text-zinc-400 ring-1 ring-zinc-500/30">
              {t("verdict.reserved")}
            </span>
            <span className="text-zinc-500">{stats.reservedCount}</span>
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
  const { t } = useI18n();
  if (total === 0) return null;
  const from = page * pageSize + 1;
  const to = Math.min((page + 1) * pageSize, total);
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-zinc-400">
      <div className="flex items-center gap-2">
        <span className="text-zinc-500">{t("pagination.perPage")}</span>
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
  const { t } = useI18n();
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

  const disagreementIps = useMemo(
    () => filtered
      .filter((r) => !r.is_reserved && lowestConfidence(r) < 70)
      .map((r) => r.ip),
    [filtered],
  );
  const allDisagreementsExpanded =
    disagreementIps.length > 0 && disagreementIps.every((ip) => expanded.has(ip));

  const toggleDisagreements = () => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (allDisagreementsExpanded) disagreementIps.forEach((ip) => next.delete(ip));
      else disagreementIps.forEach((ip) => next.add(ip));
      return next;
    });
  };

  const cols: { key: SortKey; label: string; className?: string }[] = [
    { key: "ip", label: "IP" },
    { key: "asn", label: "ASN", className: "w-24" },
    { key: "country", label: t("column.country"), className: "w-24" },
    { key: "as_name", label: t("ipDetail.org") },
    { key: "verdict", label: t("column.verdict"), className: "w-20 text-center" },
    { key: "threat", label: t("column.threat"), className: "min-w-[180px]" },
    { key: "ip_range", label: t("ipDetail.range"), className: "w-44" },
  ];

  return (
    <div className="space-y-3">
      <SummaryBar results={results} />

      <div className="flex flex-wrap items-center gap-2">
        <input
          type="text"
          placeholder={t("resultTable.filterPlaceholder")}
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
          {t("resultTable.disagreementsFirst")}
        </button>
        <button
          onClick={toggleDisagreements}
          className={`rounded-md px-2.5 py-1.5 text-xs transition-colors ${
            allDisagreementsExpanded
              ? "bg-amber-500/15 text-amber-400 ring-1 ring-amber-500/25"
              : "bg-zinc-800 text-zinc-500 hover:text-zinc-300"
          }`}
        >
          {allDisagreementsExpanded ? t("resultTable.collapseAll") : t("resultTable.expandAll")}
        </button>
        <button
          onClick={() => {
            const ip = results[0]?.ip;
            if (ip) window.open(`/api/lookup/${ip}/stix`, "_blank");
          }}
          disabled={results.length !== 1}
          className="rounded-md bg-zinc-800 px-2.5 py-1.5 text-xs text-zinc-500 hover:text-zinc-300 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          title={results.length !== 1 ? t("resultTable.stixDisabledTitle") : t("resultTable.stixTitle")}
        >
          {t("resultTable.exportStix")}
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
              const badges = assetBadges(r, t);
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
                  <td className={`px-3 py-2 font-semibold ${r.is_reserved ? "text-zinc-500" : "text-zinc-100"}`}>{r.ip}</td>
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
                    {badges.length > 0 && (
                      <span className="inline-flex flex-wrap items-center gap-1 ml-1">
                        {badges.map((a) => (
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
                      <td colSpan={7} className="px-5 py-3 bg-zinc-900/60 border-b border-zinc-800/40">
                        {r.is_reserved ? (
                          <div className="text-xs text-zinc-500">{t("reserved.notice")}</div>
                        ) : (
                          <IpDetailPanel r={r} />
                        )}
                      </td>
                    </motion.tr>
                  )}
                </AnimatePresence>
              </Fragment>
              );
            })}
            {sorted.length === 0 && filter && (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-xs text-zinc-600">
                  {t("resultTable.noMatch", { filter })}
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
