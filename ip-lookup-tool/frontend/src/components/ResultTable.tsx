import { useState, useMemo, Fragment } from "react";
import { motion, useReducedMotion } from "motion/react";
import type { LookupResult, ThreatFieldResult, FieldResult } from "../api";

interface ResultTableProps {
  results: LookupResult[];
}

type SortKey = "ip" | "asn" | "country" | "as_name" | "is_isp" | "threat" | "ip_range";

const CONF_STYLES: Record<string, string> = {
  high: "bg-emerald-500 text-white",
  medium: "bg-amber-500 text-white",
  low: "bg-red-500 text-white",
};

const CONF_LABELS: Record<string, string> = { high: "H", medium: "M", low: "L" };

const THREAT_LABELS: Record<string, string> = {
  is_proxy: "代理",
  is_mobile: "基站",
  is_hosting: "机房",
  is_tor: "Tor",
  is_vpn: "VPN",
  is_malicious: "恶意",
};

const THREAT_ACTIVE: Record<string, string> = {
  is_proxy: "bg-orange-500/20 text-orange-400",
  is_mobile: "bg-blue-500/20 text-blue-400",
  is_hosting: "bg-purple-500/20 text-purple-400",
  is_tor: "bg-rose-500/20 text-rose-400",
  is_vpn: "bg-cyan-500/20 text-cyan-400",
  is_malicious: "bg-red-500/20 text-red-400",
};

const THREAT_OUTLINED: Record<string, string> = {
  is_proxy: "border border-orange-500/30 text-orange-400",
  is_mobile: "border border-blue-500/30 text-blue-400",
  is_hosting: "border border-purple-500/30 text-purple-400",
  is_tor: "border border-rose-500/30 text-rose-400",
  is_vpn: "border border-cyan-500/30 text-cyan-400",
  is_malicious: "border border-red-500/30 text-red-400",
};

function ConfidenceDot({ confidence }: { confidence: "high" | "medium" | "low" }) {
  return (
    <span
      className={`inline-flex h-5 w-5 items-center justify-center rounded-full text-[10px] font-bold ${CONF_STYLES[confidence]}`}
      title={confidence}
    >
      {CONF_LABELS[confidence]}
    </span>
  );
}

function ThreatBadges({ threat }: { threat: ThreatFieldResult }) {
  return (
    <span className="inline-flex gap-1">
      {(["is_proxy", "is_mobile", "is_hosting", "is_tor", "is_vpn", "is_malicious"] as const).map((key) => {
        const value = threat.value[key];
        const conf = threat.per_boolean_confidence[key];
        if (!value && conf === "low") return null;

        const label = THREAT_LABELS[key];
        if (value) {
          const cls = conf === "high" ? THREAT_ACTIVE[key] : THREAT_OUTLINED[key];
          return (
            <span key={key} className={`rounded px-2 py-0.5 text-xs ${cls}`}>
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

function ExpandableDetail({ r }: { r: LookupResult }) {
  return (
    <tr className="border-b border-zinc-800/50 bg-zinc-950/80">
      <td colSpan={7} className="px-6 py-3 text-xs font-mono">
        <div className="grid gap-3">
          <FieldDetail label="Country" field={r.country} format={String} />
          <FieldDetail label="ASN" field={r.asn} format={(v) => String(v)} />
          <FieldDetail label="ISP/Org" field={r.as_name} format={String} />
          <ThreatDetail threat={r.threat} />
          <FieldDetail label="Range" field={r.ip_range} format={String} />
        </div>
      </td>
    </tr>
  );
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
      <span className="text-zinc-300">
        {label}: {format(field.value)}
      </span>{" "}
      <span className="text-zinc-500">({field.confidence})</span>
      <div className="ml-4 text-zinc-500">
        {entries.map(([src, val], i) => (
          <div key={src}>
            <span className="text-zinc-600">
              {i === entries.length - 1 ? "└" : "├"}
            </span>{" "}
            <span className="text-zinc-400">{src}:</span> {format(val)}
          </div>
        ))}
      </div>
    </div>
  );
}

function ThreatDetail({ threat }: { threat: ThreatFieldResult }) {
  const bools: ("is_proxy" | "is_mobile" | "is_hosting" | "is_tor" | "is_vpn" | "is_malicious")[] = [
    "is_proxy",
    "is_mobile",
    "is_hosting",
    "is_tor",
    "is_vpn",
    "is_malicious",
  ];
  const sourceNames = Object.keys(threat.sources);
  return (
    <div>
      <span className="text-zinc-300">Threat:</span>
      <div className="ml-4">
        {bools.map((b, bi) => {
          const val = threat.value[b];
          const conf = threat.per_boolean_confidence[b];
          const srcEntries = sourceNames.filter((s) => threat.sources[s][b] !== null);
          return (
            <div key={b}>
              <span className="text-zinc-600">
                {bi === bools.length - 1 ? "└" : "├"}
              </span>{" "}
              <span className="text-zinc-400">{THREAT_LABELS[b]}:</span>{" "}
              <span className={val ? "text-orange-400" : "text-zinc-300"}>
                {String(val)}
              </span>{" "}
              <span className="text-zinc-500">({conf})</span>
              <div className="ml-6 text-zinc-500">
                {srcEntries.map((s, si) => (
                  <div key={s}>
                    <span className="text-zinc-600">
                      {si === srcEntries.length - 1 ? "└" : "├"}
                    </span>{" "}
                    <span className="text-zinc-400">{s}:</span>{" "}
                    {String(threat.sources[s][b])}
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export function ResultTable({ results }: ResultTableProps) {
  const [sortKey, setSortKey] = useState<SortKey | null>(null);
  const [sortAsc, setSortAsc] = useState(true);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [disagreementsFirst, setDisagreementsFirst] = useState(false);
  const reduce = useReducedMotion();

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
    let arr = [...results];
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
  }, [results, sortKey, sortAsc, disagreementsFirst]);

  const toggleRow = (ip: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(ip)) next.delete(ip);
      else next.add(ip);
      return next;
    });
  };

  const expandDisagreements = () => {
    const ips = results
      .filter((r) => lowestConfidence(r) !== "high")
      .map((r) => r.ip);
    setExpanded(new Set(ips));
  };

  const cols: { key: SortKey; label: string }[] = [
    { key: "ip", label: "IP" },
    { key: "asn", label: "ASN" },
    { key: "country", label: "Country" },
    { key: "as_name", label: "ISP / Org" },
    { key: "is_isp", label: "ISP IP" },
    { key: "threat", label: "Type" },
    { key: "ip_range", label: "Range" },
  ];

  return (
    <div>
      <div className="mb-2 flex gap-2">
        <button
          onClick={() => setDisagreementsFirst(!disagreementsFirst)}
          className={`rounded px-3 py-1 text-xs transition-colors ${
            disagreementsFirst
              ? "bg-amber-500/20 text-amber-400 border border-amber-500/30"
              : "bg-zinc-800 text-zinc-400 hover:text-zinc-300"
          }`}
        >
          Disagreements first
        </button>
        <button
          onClick={expandDisagreements}
          className="rounded bg-zinc-800 px-3 py-1 text-xs text-zinc-400 hover:text-zinc-300 transition-colors"
        >
          Expand disagreements
        </button>
      </div>

      <div className="overflow-auto rounded-lg border border-zinc-800">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-zinc-800 bg-zinc-900 text-zinc-400">
              {cols.map((col) => (
                <th
                  key={col.key}
                  onClick={() => handleSort(col.key)}
                  className="cursor-pointer px-4 py-3 font-mono text-xs uppercase tracking-wider hover:text-emerald-400 transition-colors"
                >
                  {col.label}
                  {sortKey === col.key && (sortAsc ? " ↑" : " ↓")}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sorted.map((r, i) => (
              <Fragment key={r.ip + i}>
                <motion.tr
                  initial={reduce ? false : { opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{
                    duration: 0.3,
                    delay: reduce ? 0 : Math.min(i * 0.03, 0.5),
                    ease: [0.16, 1, 0.3, 1],
                  }}
                  onClick={() => toggleRow(r.ip)}
                  className={`cursor-pointer border-b border-zinc-800/50 font-mono text-xs hover:bg-emerald-500/5 ${
                    i % 2 === 0 ? "bg-zinc-950" : "bg-zinc-900/50"
                  } ${expanded.has(r.ip) ? "bg-emerald-500/5" : ""}`}
                >
                  <td className="px-4 py-2 text-zinc-100">{r.ip}</td>
                  <td className="px-4 py-2">
                    <span className="flex items-center gap-1.5">
                      <ConfidenceDot confidence={r.asn.confidence} />
                      <span className="text-zinc-300">{r.asn.value}</span>
                    </span>
                  </td>
                  <td className="px-4 py-2">
                    <span className="flex items-center gap-1.5">
                      <ConfidenceDot confidence={r.country.confidence} />
                      <span className="text-zinc-300">{r.country.value}</span>
                    </span>
                  </td>
                  <td className="px-4 py-2">
                    <span className="flex items-center gap-1.5">
                      <ConfidenceDot confidence={r.as_name.confidence} />
                      <span className="text-zinc-300">{r.as_name.value}</span>
                      {r.is_isp && (
                        <span className="rounded bg-emerald-500/20 px-1.5 py-0.5 text-[10px] text-emerald-400">
                          ISP
                        </span>
                      )}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-center">
                    {r.is_isp ? (
                      <span className="inline-block rounded bg-emerald-500/20 px-2 py-0.5 text-xs text-emerald-400">
                        ISP
                      </span>
                    ) : (
                      <span className="text-zinc-600">-</span>
                    )}
                  </td>
                  <td className="px-4 py-2 text-center">
                    <ThreatBadges threat={r.threat} />
                  </td>
                  <td className="px-4 py-2">
                    <span className="flex items-center gap-1.5">
                      <ConfidenceDot confidence={r.ip_range.confidence} />
                      <span className="text-zinc-500">{r.ip_range.value}</span>
                    </span>
                  </td>
                </motion.tr>
                {expanded.has(r.ip) && <ExpandableDetail r={r} />}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
