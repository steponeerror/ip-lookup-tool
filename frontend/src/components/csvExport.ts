import type { LookupResult } from "../api";
import { threatSummary, classLabel, familyShort } from "./threatDisplay";

export function aggregateThreatDepth(r: LookupResult) {
  const cas = Object.values(r.classifications);
  const reporter_total = cas.reduce((s, c) => s + (c.reporter_total || 0), 0);
  const verdict_conflict = cas.some((c) => c.verdict_conflict);
  const corroborated = cas.some((c) => c.corroborated);
  const mw = new Set<string>();
  for (const c of cas) for (const m of c.malware_names) mw.add(m);
  const malware_names = [...mw].sort();
  const dominant = threatSummary(r).verdict;
  // Max source reliability among details of the dominant (worst) verdict — scans all
  // classifications with that verdict (non-detected groups typically have empty details).
  let top_reliability = 0;
  for (const c of cas) {
    if (c.verdict === dominant) {
      for (const d of c.details) {
        if ((d.reliability ?? 0) > top_reliability) top_reliability = d.reliability;
      }
    }
  }
  return {
    reporter_total,
    verdict_conflict,
    corroborated,
    malware_names,
    top_reliability: Math.round(top_reliability * 100) / 100,
  };
}

const csvEscape = (v: string) => (/[","\n\r]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);

function threatTags(r: LookupResult): string {
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
}

function assetVal(r: LookupResult, key: string): string {
  const stmts = r.attributes?.[key];
  return stmts && stmts.length ? String(stmts[0].value) : "";
}

function assetNative(r: LookupResult, key: string): string {
  const stmts = r.attributes?.[key];
  return stmts && stmts.length ? stmts[0].native_type ?? "" : "";
}

// Build the full CSV document for a result set. A leading UTF-8 BOM (U+FEFF) is
// prepended so Excel detects UTF-8 instead of falling back to the system ANSI
// code page (e.g. GBK on Chinese Windows) and garbling CJK text.
export function buildCsvContent(results: LookupResult[]): string {
  const header =
    "ip,asn,asn_confidence,country,country_confidence,as_name,as_name_confidence," +
    "is_isp,verdict,verdict_confidence,threat_tags," +
    "reporter_total,verdict_conflict,corroborated,malware_names,top_reliability," +
    "ip_range,range_confidence,error," +
    "is_proxy,proxy_subtype,is_hosting,is_tor,is_vpn,carrier\n";

  const rows = results
    .map((r) => {
      const summary = threatSummary(r);
      const depth = aggregateThreatDepth(r);
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
        String(depth.reporter_total),
        String(depth.verdict_conflict),
        String(depth.corroborated),
        csvEscape(depth.malware_names.join("|")),
        String(depth.top_reliability),
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

  return String.fromCharCode(0xfeff) + header + rows;
}
