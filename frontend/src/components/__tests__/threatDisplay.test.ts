import { describe, it, expect } from "vitest";
import {
  classLabel, familyShort, threatSummary, confTextColor, normType,
} from "../threatDisplay";
import type { LookupResult } from "../../api";

const mf = (value: string, confidence = 95) => ({
  value, confidence, algorithm: "cascade" as const,
  sources: [{ source: "geo", value, reliability: 0.9, authoritative: true }],
});

const dirty: LookupResult = {
  ip: "1.1.1.1",
  country: mf("US"), asn: mf("1"), as_name: mf("X"), ip_range: mf("1.0.0.0/24"),
  is_isp: false,
  classifications: {
    scanner: { type: "scanner", verdict: "suspicious", detected: true, confidence: 50,
      algorithm: "corroboration", corroborated: false, reporter_total: 0,
      verdict_conflict: false, malware_names: [], details: [],
      sources: [{ source: "a", value: true, reliability: 0.5, authoritative: false }] },
    c2_server: { type: "c2_server", verdict: "malicious", detected: true, confidence: 90,
      algorithm: "corroboration", corroborated: true, reporter_total: 2,
      verdict_conflict: true, malware_names: ["win.x"], details: [],
      sources: [{ source: "b", value: true, reliability: 0.8, authoritative: false }] },
  },
  attributes: {},
};

describe("threatDisplay", () => {
  it("classLabel maps known types and normalizes hyphens", () => {
    expect(classLabel("c2_server")).toBe("C2");
    expect(classLabel("brute-force")).toBe("暴力破解");
    expect(classLabel("novel_thing")).toBe("novel thing");
  });
  it("normType replaces hyphens with underscores", () => {
    expect(normType("brute-force")).toBe("brute_force");
  });
  it("familyShort strips os prefix", () => {
    expect(familyShort("win.vidar")).toBe("vidar");
    expect(familyShort("remcos")).toBe("remcos");
  });
  it("confTextColor thresholds", () => {
    expect(confTextColor(95)).toBe("text-emerald-400");
    expect(confTextColor(50)).toBe("text-amber-400");
    expect(confTextColor(10)).toBe("text-red-400");
  });
  it("threatSummary picks worst verdict, counts sources, flags corroborated+conflict", () => {
    const s = threatSummary(dirty);
    expect(s.verdict).toBe("malicious");
    expect(s.confidence).toBe(90);
    expect(s.sourceCount).toBe(2);
    expect(s.corroborated).toBe(true);
    expect(s.conflict).toBe(true);
    expect(s.hasThreats).toBe(true);
  });
  it("threatSummary reports clean when nothing detected", () => {
    const clean = { ...dirty, classifications: {} };
    const s = threatSummary(clean);
    expect(s.hasThreats).toBe(false);
    expect(s.verdict).toBe("clean");
  });
});
