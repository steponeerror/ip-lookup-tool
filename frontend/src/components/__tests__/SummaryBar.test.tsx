import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { SummaryBar } from "../ResultTable";
import type { LookupResult } from "../../api";

const mf = <T,>(value: T, confidence = 95) => ({
  value, confidence, algorithm: "cascade" as const,
  sources: [{ source: "geo", value, reliability: 0.9, authoritative: true }],
});

const reserved: LookupResult = {
  ip: "10.0.0.1", country: mf("N/A", 0), asn: mf(0, 0),
  as_name: mf("N/A", 0), ip_range: mf("N/A", 0), is_isp: false,
  classifications: {}, is_reserved: true,
};

describe("SummaryBar reserved bucket", () => {
  it("counts reserved IPs as 保留地址, not as 低置信", () => {
    render(<SummaryBar results={[reserved]} />);
    expect(screen.getByText("保留地址")).toBeInTheDocument();
    expect(screen.queryByText(/低置信/)).not.toBeInTheDocument();
  });
});
