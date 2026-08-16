import { describe, it, expect } from "vitest";
import type { LookupResult } from "../api";
import { buildCsvContent } from "./csvExport";

const sampleResult: LookupResult = {
  ip: "1.2.3.4",
  country: { value: "中国", confidence: 100, algorithm: "authority", sources: [] },
  city: { value: "北京", confidence: 100, algorithm: "authority", sources: [] },
  asn: { value: 12345, confidence: 100, algorithm: "authority", sources: [] },
  as_name: { value: "测试ISP", confidence: 100, algorithm: "authority", sources: [] },
  ip_range: { value: "1.2.3.0/24", confidence: 100, algorithm: "authority", sources: [] },
  is_isp: false,
  classifications: {},
};

describe("buildCsvContent", () => {
  it("begins with a UTF-8 BOM so Excel detects the encoding instead of garbling CJK", () => {
    const content = buildCsvContent([sampleResult]);
    expect(content.charCodeAt(0)).toBe(0xfeff);
  });

  it("escapes fields containing a comma or quote (RFC 4180 quoting)", () => {
    const r: LookupResult = {
      ...sampleResult,
      country: { value: "US, Test", confidence: 100, algorithm: "authority", sources: [] },
      as_name: { value: 'Acme "Q" Corp', confidence: 100, algorithm: "authority", sources: [] },
    };
    const content = buildCsvContent([r]);
    expect(content).toContain('"US, Test"');
    expect(content).toContain('"Acme ""Q"" Corp"');
  });
});
