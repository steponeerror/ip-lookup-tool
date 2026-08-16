import { describe, it, expect } from "vitest";
import { aggregateThreatDepth, buildCsvContent, buildCsvRow, CSV_HEADER } from "../csvExport";
import type { LookupResult } from "../../api";

const mf = (value: string) => ({
  value, confidence: 95, algorithm: "cascade" as const,
  sources: [{ source: "geo", value, reliability: 0.9, authoritative: true }],
});

const r: LookupResult = {
  ip: "8.8.8.8", country: mf("US"), city: mf("Mountain View"), asn: mf("15169"), as_name: mf("Google"),
  ip_range: mf("8.8.8.0/24"), is_isp: true,
  classifications: {
    c2_server: {
      type: "c2_server", verdict: "malicious", detected: true, confidence: 92,
      algorithm: "corroboration", corroborated: true, reporter_total: 3,
      verdict_conflict: true, malware_names: ["win.vidar"],
      details: [
        { source: "otx", reliability: 0.9 },
        { source: "threatfox", reliability: 0.73 },
      ],
      sources: [],
    },
  },
  attributes: { is_proxy: [{ source: "ip2proxy", value: true, native_type: "PUB" }] },
};

describe("aggregateThreatDepth", () => {
  it("sums reporter_total, flags conflict/corroborated, unions malware", () => {
    const a = aggregateThreatDepth(r);
    expect(a.reporter_total).toBe(3);
    expect(a.verdict_conflict).toBe(true);
    expect(a.corroborated).toBe(true);
    expect(a.malware_names).toEqual(["win.vidar"]);
  });
  it("top_reliability = max reliability among the dominant-verdict details", () => {
    expect(aggregateThreatDepth(r).top_reliability).toBe(0.9);
  });
  it("top_reliability rounds to 2 decimal places", () => {
    const rounded: LookupResult = {
      ...r,
      classifications: {
        c2_server: {
          type: "c2_server", verdict: "malicious", detected: true, confidence: 92,
          algorithm: "corroboration", corroborated: true, reporter_total: 0,
          verdict_conflict: false, malware_names: [],
          details: [{ source: "otx", reliability: 0.734 }],
          sources: [],
        },
      },
    };
    expect(aggregateThreatDepth(rounded).top_reliability).toBe(0.73);
  });
  it("clean IP yields zeros/empty", () => {
    const clean = { ...r, classifications: {} };
    const a = aggregateThreatDepth(clean);
    expect(a.reporter_total).toBe(0);
    expect(a.verdict_conflict).toBe(false);
    expect(a.corroborated).toBe(false);
    expect(a.malware_names).toEqual([]);
    expect(a.top_reliability).toBe(0);
  });
});

describe("buildCsvContent", () => {
  it("emits the header with the 5 new columns after threat_tags", () => {
    const csv = buildCsvContent([r]);
    const headerRow = csv.split("\n")[0];
    const tagsIdx = headerRow.split(",").indexOf("threat_tags");
    const afterTags = headerRow.split(",").slice(tagsIdx + 1, tagsIdx + 6);
    expect(afterTags).toEqual([
      "reporter_total", "verdict_conflict", "corroborated", "malware_names", "top_reliability",
    ]);
  });
  it("writes the aggregated values into the data row", () => {
    const row = buildCsvContent([r]).split("\n")[1];
    // reporter_total,verdict_conflict,corroborated sit right after threat_tags value
    expect(row).toContain(",3,true,true,win.vidar,0.9,");
  });
  it("writes 'reserved' verdict for reserved IPs", () => {
    const reserved = { ...r, is_reserved: true, classifications: {} };
    const row = buildCsvContent([reserved]).split("\n")[1];
    expect(row).toContain(",reserved,");
  });
  it("pins threat_tags labels to English regardless of locale", () => {
    const scannerRow: LookupResult = {
      ...r,
      classifications: {
        scanner: {
          type: "scanner", verdict: "suspicious", detected: true, confidence: 60,
          algorithm: "corroboration", corroborated: false, reporter_total: 0,
          verdict_conflict: false, malware_names: [],
          details: [], sources: [],
        },
      },
    };
    const row = buildCsvContent([scannerRow]).split("\n")[1];
    expect(row).toContain("Scanner"); // English label, never "扫描"
    expect(row).not.toContain("扫描");
  });
  it("includes service + service_provider columns for an infra asset", () => {
    const dnsRow: LookupResult = {
      ...r,
      classifications: {},
      attributes: { service: [{ source: "infra_services", value: "dns", native_type: "Google Public DNS" }] },
    };
    const lines = buildCsvContent([dnsRow]).split("\n");
    const header = lines[0].split(",");
    expect(header).toContain("service");
    expect(header).toContain("service_provider");
    const row = lines[1].split(",");
    expect(row[header.indexOf("service")]).toBe("dns");
    expect(row[header.indexOf("service_provider")]).toBe("Google Public DNS");
  });
});

describe("buildCsvRow", () => {
  it("produces the same row as buildCsvContent for a single result", () => {
    const fromContent = buildCsvContent([r]).split("\n")[1];
    const fromRow = buildCsvRow(r);
    expect(fromRow).toBe(fromContent);
  });

  it("is pure: same input → same output, no neighbor dependency", () => {
    const other: LookupResult = { ...r, ip: "9.9.9.9" };
    // buildCsvRow(r) must not change when a neighbor exists
    expect(buildCsvRow(r)).toBe(buildCsvRow(r));
    buildCsvRow(other); // call with different input in between
    expect(buildCsvRow(r)).toBe(buildCsvContent([r]).split("\n")[1]);
  });

  it("appends city columns at tail", () => {
    expect(CSV_HEADER.trimEnd().endsWith("city,city_confidence")).toBe(true);
    const row = buildCsvRow(r);
    expect(row.trimEnd().endsWith(",Mountain View,95")).toBe(true);
  });
});
