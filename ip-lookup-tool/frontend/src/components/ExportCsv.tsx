import type { LookupResult } from "../api";

interface ExportCsvProps {
  results: LookupResult[];
}

export function ExportCsv({ results }: ExportCsvProps) {
  if (results.length === 0) return null;

  const csvEscape = (v: string) => /[,"\n\r]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;

  const handleExport = () => {
    const header = "ip,asn,country_code,as_name,is_isp,is_mobile,is_proxy,is_hosting,ip_range,error\n";
    const rows = results
      .map((r) =>
        [
          csvEscape(r.ip),
          csvEscape(String(r.asn)),
          csvEscape(r.country_code),
          csvEscape(r.as_name ?? ""),
          csvEscape(String(r.is_isp ?? false)),
          csvEscape(String(r.is_mobile ?? false)),
          csvEscape(String(r.is_proxy ?? false)),
          csvEscape(String(r.is_hosting ?? false)),
          csvEscape(r.ip_range ?? ""),
          csvEscape(r.error ?? ""),
        ].join(",")
      )
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
