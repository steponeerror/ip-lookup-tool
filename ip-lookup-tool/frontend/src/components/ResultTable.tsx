import { useState, useMemo } from "react";
import { motion, useReducedMotion } from "motion/react";
import type { LookupResult } from "../api";

interface ResultTableProps {
  results: LookupResult[];
}

type SortKey = "ip" | "asn" | "country_code" | "as_name" | "is_isp" | "conn_type";

const CONN_STYLES: Record<string, string> = {
  基站: "bg-blue-500/20 text-blue-400",
  代理: "bg-orange-500/20 text-orange-400",
  机房: "bg-purple-500/20 text-purple-400",
};

function ConnTypeBadges({ r }: { r: LookupResult }) {
  const badges: string[] = [];
  if (r.is_mobile) badges.push("基站");
  if (r.is_proxy) badges.push("代理");
  if (r.is_hosting) badges.push("机房");

  if (badges.length === 0) {
    return <span className="text-zinc-600">-</span>;
  }

  return (
    <span className="inline-flex gap-1">
      {badges.map((label) => (
        <span
          key={label}
          className={`rounded px-2 py-0.5 text-xs ${CONN_STYLES[label]}`}
        >
          {label}
        </span>
      ))}
    </span>
  );
}

export function ResultTable({ results }: ResultTableProps) {
  const [sortKey, setSortKey] = useState<SortKey | null>(null);
  const [sortAsc, setSortAsc] = useState(true);
  const reduce = useReducedMotion();

  const connTypeScore = (r: LookupResult) =>
    (r.is_mobile ? 4 : 0) + (r.is_proxy ? 2 : 0) + (r.is_hosting ? 1 : 0);

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortAsc(!sortAsc);
    } else {
      setSortKey(key);
      setSortAsc(true);
    }
  };

  const sorted = useMemo(() => {
    if (!sortKey) return results;
    return [...results].sort((a, b) => {
      if (sortKey === "is_isp") {
        return sortAsc
          ? Number(a.is_isp) - Number(b.is_isp)
          : Number(b.is_isp) - Number(a.is_isp);
      }
      if (sortKey === "conn_type") {
        return sortAsc
          ? connTypeScore(a) - connTypeScore(b)
          : connTypeScore(b) - connTypeScore(a);
      }
      if (sortKey === "asn") {
        const na = typeof a.asn === "number" ? a.asn : 0;
        const nb = typeof b.asn === "number" ? b.asn : 0;
        return sortAsc ? na - nb : nb - na;
      }
      const va = String(a[sortKey] ?? "");
      const vb = String(b[sortKey] ?? "");
      return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
    });
  }, [results, sortKey, sortAsc]);

  const cols: { key: SortKey; label: string }[] = [
    { key: "ip", label: "IP" },
    { key: "asn", label: "ASN" },
    { key: "country_code", label: "Country" },
    { key: "as_name", label: "ISP / Org" },
    { key: "is_isp", label: "ISP IP" },
    { key: "conn_type", label: "Type" },
  ];

  return (
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
            <th className="px-4 py-3 font-mono text-xs uppercase tracking-wider text-zinc-400">
              Range
            </th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((r, i) => (
            <motion.tr
              key={r.ip + i}
              initial={reduce ? false : { opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{
                duration: 0.3,
                delay: reduce ? 0 : Math.min(i * 0.03, 0.5),
                ease: [0.16, 1, 0.3, 1],
              }}
              className={`border-b border-zinc-800/50 font-mono text-xs hover:bg-emerald-500/5 ${
                i % 2 === 0 ? "bg-zinc-950" : "bg-zinc-900/50"
              }`}
            >
              <td className="px-4 py-2 text-zinc-100">{r.ip}</td>
              <td className="px-4 py-2 text-zinc-300">{r.asn}</td>
              <td className="px-4 py-2 text-zinc-300">{r.country_code}</td>
              <td className="px-4 py-2 text-zinc-300">{r.as_name}</td>
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
                <ConnTypeBadges r={r} />
              </td>
              <td className="px-4 py-2 text-zinc-500">{r.ip_range}</td>
            </motion.tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
