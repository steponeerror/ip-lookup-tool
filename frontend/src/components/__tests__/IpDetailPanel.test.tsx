import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { IpDetailPanel } from "../IpDetailPanel";
import type { LookupResult } from "../../api";

const mf = <T,>(value: T, confidence = 95) => ({
  value, confidence, algorithm: "cascade" as const,
  sources: [{ source: "geo", value, reliability: 0.9, authoritative: true }],
});

const r: LookupResult = {
  ip: "8.8.8.8",
  country: mf("US"),
  asn: mf(15169),
  as_name: mf("Google"),
  ip_range: mf("8.8.8.0/24"),
  is_isp: true,
  classifications: {
    c2_server: {
      type: "c2_server", verdict: "malicious", detected: true, confidence: 92,
      algorithm: "corroboration", corroborated: true, reporter_total: 3,
      verdict_conflict: false, malware_names: ["win.vidar"],
      details: [{ source: "otx", reliability: 0.9 }], sources: [],
    },
  },
  attributes: {},
  is_whitelisted: false,
  whitelist_notes: [],
};

describe("IpDetailPanel", () => {
  it("renders Z1 identity fields", () => {
    render(<IpDetailPanel r={r} />);
    expect(screen.getByText("国家")).toBeInTheDocument();
    // FieldDetail renders the value both in the header row and in each source row;
    // the mf() fixture reuses the same value for both, so use getAllByText here.
    expect(screen.getAllByText("US")[0]).toBeInTheDocument();
    expect(screen.getByText("ASN")).toBeInTheDocument();
    expect(screen.getByText("机构 / ISP")).toBeInTheDocument();
    expect(screen.getByText("网段")).toBeInTheDocument();
  });

  it("renders the 威胁明细 section with the classification block", () => {
    render(<IpDetailPanel r={r} />);
    expect(screen.getByText("威胁明细")).toBeInTheDocument();
    expect(screen.getByText("C2")).toBeInTheDocument();
    expect(screen.getByText(/·3上报/)).toBeInTheDocument();
  });

  it("shows 未命中 when there are no classifications", () => {
    const clean = { ...r, classifications: {} };
    render(<IpDetailPanel r={clean} />);
    expect(screen.getByText("未命中")).toBeInTheDocument();
  });
});
