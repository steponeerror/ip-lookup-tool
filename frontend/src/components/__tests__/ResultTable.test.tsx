import { describe, it, expect } from "vitest";
import { screen, fireEvent } from "@testing-library/react";
import { renderWithI18n } from "../../test/i18nTestUtils";
import { ResultTable } from "../ResultTable";
import type { LookupResult } from "../../api";

const mf = <T,>(value: T, confidence = 95) => ({
  value, confidence, algorithm: "cascade" as const,
  sources: [{ source: "geo", value, reliability: 0.9, authoritative: true }],
});

const reserved: LookupResult = {
  ip: "10.0.0.1",
  country: mf("N/A", 0), asn: mf(0, 0), as_name: mf("N/A", 0),
  ip_range: mf("N/A", 0), is_isp: false, classifications: {},
  is_reserved: true,
};

describe("ResultTable reserved rows", () => {
  it("renders 保留地址 verdict for a reserved IP", () => {
    renderWithI18n(<ResultTable results={[reserved]} />);
    expect(screen.getAllByText("Reserved").length).toBeGreaterThanOrEqual(1);
  });
});

const lowConf: LookupResult = {
  ip: "203.0.113.5", country: mf("US", 50), asn: mf(64500, 50),
  as_name: mf("Example", 50), ip_range: mf("203.0.113.0/24", 50),
  is_isp: false, classifications: {},
};

describe("Expand disagreements toggle", () => {
  it("expands on first click, collapses on second", async () => {
    renderWithI18n(<ResultTable results={[lowConf]} />);
    // collapsed initially – detail panel not shown
    expect(screen.queryByText("Threat details")).not.toBeInTheDocument();

    const expand = screen.getByRole("button", { name: /expand disagreements/i });
    fireEvent.click(expand);
    expect(await screen.findByText("Threat details")).toBeInTheDocument();

    // button flipped to Collapse; clicking it collapses
    const collapse = screen.getByRole("button", { name: /collapse disagreements/i });
    fireEvent.click(collapse);
    expect(screen.getByRole("button", { name: /expand disagreements/i })).toBeInTheDocument();
  });
});
