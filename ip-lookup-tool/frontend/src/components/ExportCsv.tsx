import type { LookupResult } from "../api";

interface ExportCsvProps {
  results: LookupResult[];
}

export function ExportCsv({ results }: ExportCsvProps) {
  if (results.length === 0) return null;

  const csvEscape = (v: string) => /[,"\n\r]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;

  const handleExport = () => {
    const header =
      "ip,asn,asn_confidence,asn_algorithm,country,country_confidence,country_algorithm," +
      "as_name,as_name_confidence,as_name_algorithm,is_isp," +
      "proxy_detected,proxy_confidence,proxy_algorithm," +
      "mobile_detected,mobile_confidence,mobile_algorithm," +
      "hosting_detected,hosting_confidence,hosting_algorithm," +
      "tor_detected,tor_confidence,tor_algorithm," +
      "vpn_detected,vpn_confidence,vpn_algorithm," +
      "malicious_detected,malicious_confidence,malicious_algorithm," +
      "ip_range,range_confidence,range_algorithm,error\n";

    const rows = results
      .map((r) => {
        const p = r.threats.proxy ?? { detected: false, confidence: 0, algorithm: "voting", sources: [] };
        const m = r.threats.mobile ?? { detected: false, confidence: 0, algorithm: "voting", sources: [] };
        const h = r.threats.hosting ?? { detected: false, confidence: 0, algorithm: "voting", sources: [] };
        const t = r.threats.tor ?? { detected: false, confidence: 0, algorithm: "voting", sources: [] };
        const v = r.threats.vpn ?? { detected: false, confidence: 0, algorithm: "voting", sources: [] };
        const mal = r.threats.malicious ?? { detected: false, confidence: 0, algorithm: "voting", sources: [] };

        return [
          csvEscape(r.ip),
          csvEscape(String(r.asn.value)),
          String(r.asn.confidence),
          csvEscape(r.asn.algorithm),
          csvEscape(r.country.value),
          String(r.country.confidence),
          csvEscape(r.country.algorithm),
          csvEscape(r.as_name.value),
          String(r.as_name.confidence),
          csvEscape(r.as_name.algorithm),
          String(r.is_isp),
          String(p.detected), String(p.confidence), csvEscape(p.algorithm),
          String(m.detected), String(m.confidence), csvEscape(m.algorithm),
          String(h.detected), String(h.confidence), csvEscape(h.algorithm),
          String(t.detected), String(t.confidence), csvEscape(t.algorithm),
          String(v.detected), String(v.confidence), csvEscape(v.algorithm),
          String(mal.detected), String(mal.confidence), csvEscape(mal.algorithm),
          csvEscape(r.ip_range.value),
          String(r.ip_range.confidence),
          csvEscape(r.ip_range.algorithm),
          csvEscape(r.error ?? ""),
        ].join(",");
      })
      .join("\n");

    const blob = new Blob([header + rows], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ip-lookup-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <button
      onClick={handleExport}
      className="rounded-lg bg-emerald-500 px-5 py-2 text-sm font-semibold text-zinc-950 transition-transform hover:scale-[1.02] active:scale-[0.98]"
    >
      Export CSV ({results.length} rows)
    </button>
  );
}
