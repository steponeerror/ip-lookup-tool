import type { LookupResult } from "../api";
import { threatSummary, classLabel, familyShort } from "./ResultTable";

interface ExportCsvProps {
  results: LookupResult[];
}

export function ExportCsv({ results }: ExportCsvProps) {
  if (results.length === 0) return null;

  const csvEscape = (v: string) => /[,"\n\r]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;

  const assetVal = (r: LookupResult, key: string): string => {
    const stmts = r.attributes?.[key];
    if (!stmts || !stmts.length) return "";
    return String(stmts[0].value);
  };
  const assetNative = (r: LookupResult, key: string): string => {
    const stmts = r.attributes?.[key];
    if (!stmts || !stmts.length) return "";
    return stmts[0].native_type ?? "";
  };

  // Readable threat tags mirroring the table's 威胁标签 cell: classLabel · malware family.
  const threatTags = (r: LookupResult): string => {
    const tags = Object.keys(r.classifications)
      .filter((t) => {
        const ca = r.classifications[t];
        return ca.detected && ca.confidence > 0;
      })
      .map((type) => {
        const ca = r.classifications[type];
        const label = classLabel(type);
        const family = ca.malware_names.length > 0 ? familyShort(ca.malware_names[0]) : null;
        return family ? `${label}·${family}` : label;
      });
    return tags.join(" | ");
  };

  const handleExport = () => {
    // Columns mirror the page table: identity fields, verdict (判定), threat tags
    // (威胁标签), range, then inline asset badges.
    const header =
      "ip,asn,asn_confidence,country,country_confidence,as_name,as_name_confidence," +
      "is_isp,verdict,verdict_confidence,threat_tags,ip_range,range_confidence,error," +
      "is_proxy,proxy_subtype,is_hosting,is_tor,is_vpn,carrier\n";

    const rows = results
      .map((r) => {
        const summary = threatSummary(r);
        return [
          csvEscape(r.ip),
          csvEscape(String(r.asn.value)),
          String(r.asn.confidence),
          csvEscape(r.country.value),
          String(r.country.confidence),
          csvEscape(r.as_name.value),
          String(r.as_name.confidence),
          String(r.is_isp),
          csvEscape(summary.verdict),
          String(summary.confidence),
          csvEscape(threatTags(r)),
          csvEscape(r.ip_range.value),
          String(r.ip_range.confidence),
          csvEscape(r.error ?? ""),
          csvEscape(assetVal(r, "is_proxy")),
          csvEscape(assetNative(r, "is_proxy")),
          csvEscape(assetVal(r, "is_hosting")),
          csvEscape(assetVal(r, "is_tor")),
          csvEscape(assetVal(r, "is_vpn")),
          csvEscape(assetVal(r, "carrier")),
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
