import { useState } from "react";
import { motion, useReducedMotion } from "motion/react";
import type { LookupResult } from "../api";

interface ResultTableProps {
  results: LookupResult[];
}

type SortKey = "ip" | "asn" | "country_code" | "as_name";

export function ResultTable({ results }: ResultTableProps) {
  const [sortKey, setSortKey] = useState<SortKey | null>(null);
  const [sortAsc, setSortAsc] = useState(true);
  const reduce = useReducedMotion();

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortAsc(!sortAsc);
    } else {
      setSortKey(key);
      setSortAsc(true);
    }
  };

  const sorted = sortKey
    ? [...results].sort((a, b) => {
        const va = String(a[sortKey] ?? "");
        const vb = String(b[sortKey] ?? "");
        return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
      })
    : results;

  const cols: { key: SortKey; label: string }[] = [
    { key: "ip", label: "IP" },
    { key: "asn", label: "ASN" },
    { key: "country_code", label: "Country" },
    { key: "as_name", label: "ISP / Org" },
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
                delay: reduce ? 0 : i * 0.03,
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
              <td className="px-4 py-2 text-zinc-500">{r.ip_range}</td>
            </motion.tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
