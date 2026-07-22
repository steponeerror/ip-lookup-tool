import type { LookupResult } from "../api";

export function confColor(conf: number): string {
  if (conf >= 70) return "bg-emerald-500";
  if (conf >= 30) return "bg-amber-500";
  return "bg-red-500";
}

export function confTextColor(conf: number): string {
  if (conf >= 70) return "text-emerald-400";
  if (conf >= 30) return "text-amber-400";
  return "text-red-400";
}

export const VERDICT_LABEL: Record<string, string> = {
  malicious: "恶意",
  suspicious: "可疑",
  benign: "可信",
  informational: "未知",
  clean: "—",
};

export const VERDICT_STYLE: Record<string, string> = {
  malicious: "bg-red-500/15 text-red-300 ring-1 ring-red-500/30",
  suspicious: "bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30",
  benign: "bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/30",
  informational: "bg-zinc-500/15 text-zinc-400 ring-1 ring-zinc-500/25",
  clean: "bg-zinc-700/40 text-zinc-500 ring-1 ring-zinc-600/40",
};

export const VERDICT_RANK: Record<string, number> = {
  malicious: 3, suspicious: 2, benign: 1, informational: 0, clean: 0,
};

export const ALGORITHM_ICONS: Record<string, string> = {
  cascade: "🔑",
  voting: "📊",
  pcr6: "⚠️",
  authority: "🏛️",
  specificity: "🎯",
  corroboration: "🤝",
};

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

export function normType(type: string): string {
  return type.replace(/-/g, "_");
}

export function classLabel(type: string): string {
  const t = normType(type);
  return CLASS_LABELS[t] ?? t.replace(/_/g, " ");
}

export function familyShort(name: string): string {
  return name.replace(/^(win|linux|mac|osx|android|ios|trojan|worm|backdoor)[._-]/i, "");
}

export function threatSummary(r: LookupResult): {
  verdict: string;
  confidence: number;
  sourceCount: number;
  corroborated: boolean;
  conflict: boolean;
  hasThreats: boolean;
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
