import { describe, it, expect } from "vitest";
import { aggregateThreatDepth, buildCsv } from "../csvExport";
import type { LookupResult } from "../../api";

const mf = (value: string) => ({
  value, confidence: 95, algorithm: "cascade" as const,
  sources: [{ source: "geo", value, reliability: 0.9, authoritative: true }],
});

const r: LookupResult = {
  ip: "8.8.8.8", country: mf("US"), asn: mf("15169"), as_name: mf("Google"),
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
  is_whitelisted: false, whitelist_notes: [],
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

describe("buildCsv", () => {
  it("emits the header with the 5 new columns after threat_tags", () => {
    const csv = buildCsv([r]);
    const headerRow = csv.split("\n")[0];
    const tagsIdx = headerRow.split(",").indexOf("threat_tags");
    const afterTags = headerRow.split(",").slice(tagsIdx + 1, tagsIdx + 6);
    expect(afterTags).toEqual([
      "reporter_total", "verdict_conflict", "corroborated", "malware_names", "top_reliability",
    ]);
  });
  it("writes the aggregated values into the data row", () => {
    const row = buildCsv([r]).split("\n")[1];
    // reporter_total,verdict_conflict,corroborated sit right after threat_tags value
    expect(row).toContain(",3,true,true,win.vidar,0.9,");
  });
});
