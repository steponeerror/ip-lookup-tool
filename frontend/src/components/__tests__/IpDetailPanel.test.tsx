import { describe, it, expect } from "vitest";
import { screen } from "@testing-library/react";
import { renderWithI18n } from "../../test/i18nTestUtils";
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
};

describe("IpDetailPanel", () => {
  it("renders Z1 identity fields", () => {
    renderWithI18n(<IpDetailPanel r={r} />);
    expect(screen.getByText("Country")).toBeInTheDocument();
    // FieldDetail renders the value both in the header row and in each source row;
    // the mf() fixture reuses the same value for both, so use getAllByText here.
    expect(screen.getAllByText("US")[0]).toBeInTheDocument();
    expect(screen.getByText("ASN")).toBeInTheDocument();
    expect(screen.getByText("Org / ISP")).toBeInTheDocument();
    expect(screen.getByText("Range")).toBeInTheDocument();
  });

  it("renders the 威胁明细 section with the classification block", () => {
    renderWithI18n(<IpDetailPanel r={r} />);
    expect(screen.getByText("Threat details")).toBeInTheDocument();
    expect(screen.getByText("C2")).toBeInTheDocument();
    expect(screen.getByText(/3 reporters/)).toBeInTheDocument();
  });

  it("shows 未命中 when there are no classifications", () => {
    const clean = { ...r, classifications: {} };
    renderWithI18n(<IpDetailPanel r={clean} />);
    expect(screen.getByText("No hits")).toBeInTheDocument();
  });
});
