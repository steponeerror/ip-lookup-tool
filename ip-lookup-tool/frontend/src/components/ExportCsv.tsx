import type { LookupResult } from "../api";

interface ExportCsvProps {
  results: LookupResult[];
}

export function ExportCsv({ results }: ExportCsvProps) {
  if (results.length === 0) return null;

  const csvEscape = (v: string) => /[,"\n\r]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;

  const handleExport = () => {
    const header =
      "ip,asn,asn_confidence,country,country_confidence,as_name,as_name_confidence," +
      "is_isp,is_proxy,is_proxy_confidence,is_mobile,is_mobile_confidence," +
      "is_hosting,is_hosting_confidence,ip_range,range_confidence\n";

    const rows = results
      .map((r) =>
        [
          csvEscape(r.ip),
          csvEscape(String(r.asn.value)),
          csvEscape(r.asn.confidence),
          csvEscape(r.country.value),
          csvEscape(r.country.confidence),
          csvEscape(r.as_name.value),
          csvEscape(r.as_name.confidence),
          csvEscape(String(r.is_isp)),
          csvEscape(String(r.threat.value.is_proxy)),
          csvEscape(r.threat.per_boolean_confidence.is_proxy),
          csvEscape(String(r.threat.value.is_mobile)),
          csvEscape(r.threat.per_boolean_confidence.is_mobile),
          csvEscape(String(r.threat.value.is_hosting)),
          csvEscape(r.threat.per_boolean_confidence.is_hosting),
          csvEscape(r.ip_range.value),
          csvEscape(r.ip_range.confidence),
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
