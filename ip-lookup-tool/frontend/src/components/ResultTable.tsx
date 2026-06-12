import { useState, useMemo, Fragment } from "react";
import { motion, AnimatePresence, useReducedMotion } from "motion/react";
import type { LookupResult, ThreatFieldResult, FieldResult } from "../api";

interface ResultTableProps {
  results: LookupResult[];
}

type SortKey = "ip" | "asn" | "country" | "as_name" | "is_isp" | "threat" | "ip_range";

const CONF_DOT: Record<string, string> = {
  high: "bg-emerald-500",
  medium: "bg-amber-500",
  low: "bg-red-500",
};

const THREAT_LABELS: Record<string, string> = {
  is_proxy: "代理",
  is_mobile: "基站",
  is_hosting: "机房",
  is_tor: "Tor",
  is_vpn: "VPN",
  is_malicious: "恶意",
};

const THREAT_ACTIVE: Record<string, string> = {
  is_proxy: "bg-orange-500/15 text-orange-400 ring-1 ring-orange-500/25",
  is_mobile: "bg-blue-500/15 text-blue-400 ring-1 ring-blue-500/25",
  is_hosting: "bg-purple-500/15 text-purple-400 ring-1 ring-purple-500/25",
  is_tor: "bg-rose-500/15 text-rose-400 ring-1 ring-rose-500/25",
  is_vpn: "bg-cyan-500/15 text-cyan-400 ring-1 ring-cyan-500/25",
  is_malicious: "bg-red-500/15 text-red-400 ring-1 ring-red-500/25",
};

const THREAT_OUTLINED: Record<string, string> = {
  is_proxy: "text-orange-400/60 ring-1 ring-orange-500/15",
  is_mobile: "text-blue-400/60 ring-1 ring-blue-500/15",
  is_hosting: "text-purple-400/60 ring-1 ring-purple-500/15",
  is_tor: "text-rose-400/60 ring-1 ring-rose-500/15",
  is_vpn: "text-cyan-400/60 ring-1 ring-cyan-500/15",
  is_malicious: "text-red-400/60 ring-1 ring-red-500/15",
};

const THREAT_KEYS = ["is_proxy", "is_mobile", "is_hosting", "is_tor", "is_vpn", "is_malicious"] as const;

function ThreatBadges({ threat }: { threat: ThreatFieldResult }) {
  return (
    <span className="inline-flex flex-wrap gap-1">
      {THREAT_KEYS.map((key) => {
        const value = threat.value[key];
        const conf = threat.per_boolean_confidence[key];
        if (!value && conf === "low") return null;
        const label = THREAT_LABELS[key];
        if (value) {
          const cls = conf === "high" ? THREAT_ACTIVE[key] : THREAT_OUTLINED[key];
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

function lowestConfidence(r: LookupResult): "high" | "medium" | "low" {
  const confs = [
    r.country.confidence,
    r.asn.confidence,
    r.as_name.confidence,
    r.ip_range.confidence,
    ...Object.values(r.threat.per_boolean_confidence),
  ];
  if (confs.includes("low")) return "low";
  if (confs.includes("medium")) return "medium";
  return "high";
}

function FieldDetail<T>({
  label,
  field,
  format,
}: {
  label: string;
  field: FieldResult<T>;
  format: (v: T) => string;
}) {
  const entries = Object.entries(field.sources);
  if (entries.length === 0) return null;
  return (
    <div>
      <div className="flex items-center gap-2 mb-1">
        <span className="text-xs font-medium text-zinc-300">{label}</span>
        <span className="text-[10px] text-zinc-500">{format(field.value)}</span>
        <span className={`inline-block h-1.5 w-1.5 rounded-full ${CONF_DOT[field.confidence]}`} />
        <span className="text-[10px] text-zinc-600">{field.confidence}</span>
      </div>
      {entries.length > 1 && (
        <div className="ml-3 flex flex-wrap gap-x-4 gap-y-0.5">
          {entries.map(([src, val]) => (
            <span key={src} className="text-[11px]">
              <span className="text-zinc-500">{src}</span>
              <span className="text-zinc-700 mx-1">:</span>
              <span className="text-zinc-400">{format(val)}</span>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function ThreatDetail({ threat }: { threat: ThreatFieldResult }) {
  const sourceNames = Object.keys(threat.sources);
  return (
    <div>
      <span className="text-xs font-medium text-zinc-300">Threat</span>
      <div className="ml-3 mt-1 grid grid-cols-2 gap-x-6 gap-y-1.5 sm:grid-cols-3">
        {THREAT_KEYS.map((b) => {
          const val = threat.value[b];
          const conf = threat.per_boolean_confidence[b];
          const srcEntries = sourceNames.filter((s) => threat.sources[s][b] != null);
          if (!val && conf === "low" && srcEntries.length === 0) return null;
          return (
            <div key={b}>
              <div className="flex items-center gap-1.5">
                <span className={`inline-block h-1.5 w-1.5 rounded-full ${val ? "bg-orange-400" : "bg-zinc-600"}`} />
                <span className="text-[11px] text-zinc-400">{THREAT_LABELS[b]}</span>
                <span className="text-[10px] text-zinc-600">{conf}</span>
              </div>
              {srcEntries.length > 0 && (
                <div className="ml-3 flex flex-wrap gap-x-3">
                  {srcEntries.map((s) => (
                    <span key={s} className="text-[10px]">
                      <span className="text-zinc-600">{s}</span>
                      <span className="text-zinc-700 mx-0.5">:</span>
                      <span className={threat.sources[s][b] ? "text-orange-400" : "text-zinc-500"}>
                        {String(threat.sources[s][b] ?? "N/A")}
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
        <ThreatDetail threat={r.threat} />
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
        if (r.threat.value[k]) threats[k]++;
      }
      if (r.is_isp) ispCount++;
      const c = lowestConfidence(r);
      if (c === "low") lowConf++;
      else if (c === "medium") medConf++;
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
          {stats.lowConf} low
        </span>
      )}
      {stats.medConf > 0 && (
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-amber-500" />
          {stats.medConf} medium
        </span>
      )}
      {stats.highConf > 0 && (
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-500" />
          {stats.highConf} high
        </span>
      )}
      {activeThreats.length > 0 && (
        <span className="text-zinc-600">|</span>
      )}
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
        const t = r.threat.value;
        return (t.is_proxy ? 4 : 0) + (t.is_mobile ? 2 : 0) + (t.is_hosting ? 1 : 0);
      }
      case "ip_range": return r.ip_range.value;
    }
  };

  const sorted = useMemo(() => {
    let arr = [...filtered];
    if (disagreementsFirst) {
      const order: Record<string, number> = { low: 0, medium: 1, high: 2 };
      arr.sort((a, b) => order[lowestConfidence(a)] - order[lowestConfidence(b)]);
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
      .filter((r) => lowestConfidence(r) !== "high")
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
                      <span className={`inline-block h-1.5 w-1.5 rounded-full ${CONF_DOT[r.asn.confidence]}`} />
                      <span className="text-zinc-300">{r.asn.value}</span>
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <span className="inline-flex items-center gap-1.5">
                      <span className={`inline-block h-1.5 w-1.5 rounded-full ${CONF_DOT[r.country.confidence]}`} />
                      <span className="text-zinc-300">{r.country.value}</span>
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <span className="inline-flex items-center gap-1.5">
                      <span className={`inline-block h-1.5 w-1.5 rounded-full ${CONF_DOT[r.as_name.confidence]}`} />
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
                    <ThreatBadges threat={r.threat} />
                  </td>
                  <td className="px-3 py-2">
                    <span className="inline-flex items-center gap-1.5">
                      <span className={`inline-block h-1.5 w-1.5 rounded-full ${CONF_DOT[r.ip_range.confidence]}`} />
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
