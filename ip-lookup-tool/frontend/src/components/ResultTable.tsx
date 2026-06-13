import { useState, useMemo, Fragment } from "react";
import { motion, AnimatePresence, useReducedMotion } from "motion/react";
import type { LookupResult, MergedField, ThreatAssessment } from "../api";

interface ResultTableProps {
  results: LookupResult[];
}

type SortKey = "ip" | "asn" | "country" | "as_name" | "is_isp" | "threat" | "ip_range";

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

const THREAT_LABELS: Record<string, string> = {
  proxy: "代理",
  mobile: "基站",
  hosting: "机房",
  tor: "Tor",
  vpn: "VPN",
  malicious: "恶意",
};

const THREAT_ACTIVE: Record<string, string> = {
  proxy: "bg-orange-500/15 text-orange-400 ring-1 ring-orange-500/25",
  mobile: "bg-blue-500/15 text-blue-400 ring-1 ring-blue-500/25",
  hosting: "bg-purple-500/15 text-purple-400 ring-1 ring-purple-500/25",
  tor: "bg-rose-500/15 text-rose-400 ring-1 ring-rose-500/25",
  vpn: "bg-cyan-500/15 text-cyan-400 ring-1 ring-cyan-500/25",
  malicious: "bg-red-500/15 text-red-400 ring-1 ring-red-500/25",
};

const THREAT_OUTLINED: Record<string, string> = {
  proxy: "text-orange-400/60 ring-1 ring-orange-500/15",
  mobile: "text-blue-400/60 ring-1 ring-blue-500/15",
  hosting: "text-purple-400/60 ring-1 ring-purple-500/15",
  tor: "text-rose-400/60 ring-1 ring-rose-500/15",
  vpn: "text-cyan-400/60 ring-1 ring-cyan-500/15",
  malicious: "text-red-400/60 ring-1 ring-red-500/15",
};

const ALGORITHM_ICONS: Record<string, string> = {
  cascade: "🔑",
  voting: "📊",
  pcr6: "⚠️",
  authority: "🏛️",
  specificity: "🎯",
};

const THREAT_KEYS = ["proxy", "mobile", "hosting", "tor", "vpn", "malicious"] as const;

function ThreatBadges({ threats }: { threats: Record<string, ThreatAssessment> }) {
  return (
    <span className="inline-flex flex-wrap gap-1">
      {THREAT_KEYS.map((key) => {
        const ta = threats[key];
        if (!ta) return null;
        if (!ta.detected && ta.confidence === 0) return null;
        const label = THREAT_LABELS[key];
        if (ta.detected) {
          const cls = ta.confidence >= 70 ? THREAT_ACTIVE[key] : THREAT_OUTLINED[key];
          return (
            <span key={key} className={`rounded px-1.5 py-0.5 text-[11px] font-medium ${cls}`}>
              {label}
            </span>
          );
        }
        return null;
      })}
    </span>
  );
}

function lowestConfidence(r: LookupResult): number {
  const confs = [
    r.country.confidence,
    r.asn.confidence,
    r.as_name.confidence,
    r.ip_range.confidence,
    ...Object.values(r.threats).map((t) => t.confidence),
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

function ThreatDetail({ threats }: { threats: Record<string, ThreatAssessment> }) {
  return (
    <div>
      <span className="text-xs font-medium text-zinc-300">Threat</span>
      <div className="ml-3 mt-1 grid grid-cols-2 gap-x-6 gap-y-1.5 sm:grid-cols-3">
        {THREAT_KEYS.map((key) => {
          const ta = threats[key];
          if (!ta) return null;
          if (!ta.detected && ta.confidence === 0 && ta.sources.length === 0) return null;
          return (
            <div key={key}>
              <div className="flex items-center gap-1.5">
                <span
                  className={`inline-block h-1.5 w-1.5 rounded-full ${
                    ta.detected ? "bg-orange-400" : "bg-zinc-600"
                  }`}
                />
                <span className="text-[11px] text-zinc-400">{THREAT_LABELS[key]}</span>
                <span className={`text-[10px] ${confTextColor(ta.confidence)}`}>
                  {ta.confidence}
                </span>
                <span className="text-[10px] text-zinc-600">
                  {ALGORITHM_ICONS[ta.algorithm] ?? ta.algorithm}
                </span>
              </div>
              {ta.sources.length > 0 && (
                <div className="ml-3 flex flex-wrap gap-x-3">
                  {ta.sources.map((s) => (
                    <span key={s.source} className="text-[10px]">
                      <span className="text-zinc-600">{s.source}</span>
                      {s.authoritative && (
                        <span className="text-amber-400" title="authoritative">★</span>
                      )}
                      <span className="text-zinc-700 mx-0.5">:</span>
                      <span className={s.value ? "text-orange-400" : "text-zinc-500"}>
                        {String(s.value ?? "N/A")}
                      </span>
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
        <FieldDetail label="Country" field={r.country} format={String} />
        <FieldDetail label="ASN" field={r.asn} format={(v) => String(v)} />
        <FieldDetail label="ISP / Org" field={r.as_name} format={String} />
        <ThreatDetail threats={r.threats} />
        <FieldDetail label="Range" field={r.ip_range} format={String} />
      </div>
    </td>
  );
}

function SummaryBar({ results }: { results: LookupResult[] }) {
  const stats = useMemo(() => {
    const threats: Record<string, number> = {};
    for (const k of THREAT_KEYS) threats[k] = 0;
    let ispCount = 0;
    let lowConf = 0;
    let medConf = 0;
    let highConf = 0;

    for (const r of results) {
      for (const k of THREAT_KEYS) {
        if (r.threats[k]?.detected) threats[k]++;
      }
      if (r.is_isp) ispCount++;
      const c = lowestConfidence(r);
      if (c < 30) lowConf++;
      else if (c < 70) medConf++;
      else highConf++;
    }

    return { threats, ispCount, lowConf, medConf, highConf };
  }, [results]);

  const activeThreats = THREAT_KEYS.filter((k) => stats.threats[k] > 0);
  if (activeThreats.length === 0 && stats.ispCount === 0 && stats.lowConf === 0 && stats.medConf === 0) {
    return (
      <div className="flex items-center gap-3 text-xs text-zinc-500">
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-500" />
          All {results.length.toLocaleString()} results high confidence
        </span>
      </div>
    );
  }

  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-zinc-400">
      {stats.lowConf > 0 && (
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-red-500" />
          {stats.lowConf} low confidence
        </span>
      )}
      {stats.medConf > 0 && (
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-amber-500" />
          {stats.medConf} medium confidence
        </span>
      )}
      {stats.highConf > 0 && (
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-500" />
          {stats.highConf} high confidence
        </span>
      )}
      {activeThreats.length > 0 && <span className="text-zinc-600">|</span>}
      {activeThreats.map((k) => (
        <span key={k} className="flex items-center gap-1">
          <span className={`rounded px-1 py-0.5 text-[10px] font-medium ${THREAT_ACTIVE[k]}`}>
            {THREAT_LABELS[k]}
          </span>
          <span className="text-zinc-500">{stats.threats[k]}</span>
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

export function ResultTable({ results }: ResultTableProps) {
  const [sortKey, setSortKey] = useState<SortKey | null>(null);
  const [sortAsc, setSortAsc] = useState(true);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [disagreementsFirst, setDisagreementsFirst] = useState(false);
  const [filter, setFilter] = useState("");
  const reduce = useReducedMotion();

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
      case "is_isp": return r.is_isp ? 1 : 0;
      case "threat": {
        const t = r.threats;
        return (t.proxy?.detected ? 4 : 0) + (t.mobile?.detected ? 2 : 0) + (t.hosting?.detected ? 1 : 0);
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
    { key: "country", label: "Country", className: "w-24" },
    { key: "as_name", label: "ISP / Org" },
    { key: "is_isp", label: "ISP", className: "w-16 text-center" },
    { key: "threat", label: "Type" },
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
            {sorted.map((r, i) => (
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
                  <td className="px-3 py-2">
                    <span className="inline-flex items-center gap-1.5">
                      <span className={`inline-block h-1.5 w-1.5 rounded-full ${confColor(r.asn.confidence)}`} />
                      <span className="text-zinc-300">{r.asn.value}</span>
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <span className="inline-flex items-center gap-1.5">
                      <span className={`inline-block h-1.5 w-1.5 rounded-full ${confColor(r.country.confidence)}`} />
                      <span className="text-zinc-300">{r.country.value}</span>
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <span className="inline-flex items-center gap-1.5">
                      <span className={`inline-block h-1.5 w-1.5 rounded-full ${confColor(r.as_name.confidence)}`} />
                      <span className="text-zinc-300">{r.as_name.value}</span>
                      {r.is_isp && (
                        <span className="rounded bg-emerald-500/15 px-1 py-0.5 text-[10px] text-emerald-400 ring-1 ring-emerald-500/25">
                          ISP
                        </span>
                      )}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-center">
                    {r.is_isp ? (
                      <span className="inline-block rounded bg-emerald-500/15 px-1.5 py-0.5 text-[10px] text-emerald-400 ring-1 ring-emerald-500/25">
                        ISP
                      </span>
                    ) : (
                      <span className="text-zinc-700">-</span>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    <ThreatBadges threats={r.threats} />
                  </td>
                  <td className="px-3 py-2">
                    <span className="inline-flex items-center gap-1.5">
                      <span className={`inline-block h-1.5 w-1.5 rounded-full ${confColor(r.ip_range.confidence)}`} />
                      <span className="text-zinc-500">{r.ip_range.value}</span>
                    </span>
                  </td>
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
            ))}
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
    </div>
  );
}
