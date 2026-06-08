import type { LookupResult } from "../api";

interface ExportCsvProps {
  results: LookupResult[];
}

export function ExportCsv({ results }: ExportCsvProps) {
  if (results.length === 0) return null;

  const handleExport = () => {
    const header = "ip,asn,country_code,as_name,ip_range,error\n";
    const rows = results
      .map((r) =>
        [
          r.ip,
          r.asn,
          r.country_code,
          `"${(r.as_name ?? "").replace(/"/g, '""')}"`,
          r.ip_range,
          r.error ?? "",
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
