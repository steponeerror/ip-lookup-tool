import { describe, it, expect } from "vitest";
import { screen } from "@testing-library/react";
import { renderWithI18n } from "../../test/i18nTestUtils";
import { ClassificationBlock } from "../ClassificationBlock";
import type { ClassificationAssessment } from "../../api";

const ca: ClassificationAssessment = {
  type: "c2_server",
  verdict: "malicious",
  detected: true,
  confidence: 92,
  algorithm: "corroboration",
  corroborated: true,
  reporter_total: 4,
  verdict_conflict: false,
  malware_names: ["win.vidar"],
  details: [
    { source: "otx", reliability: 0.9, malware_name: "remcos" },
    { source: "threatfox", reliability: 0.7 },
  ],
  sources: [],
};

describe("ClassificationBlock", () => {
  it("renders Z2 header with label, verdict, and reporter_total", () => {
    renderWithI18n(<ClassificationBlock type="c2_server" ca={ca} />);
    expect(screen.getByText("C2")).toBeInTheDocument();
    expect(screen.getByText("Malicious")).toBeInTheDocument();
    expect(screen.getByText(/4 reporters/)).toBeInTheDocument();
    expect(screen.getByText(/Corroborated/)).toBeInTheDocument();
  });

  it("renders aggregated malware family chips", () => {
    renderWithI18n(<ClassificationBlock type="c2_server" ca={ca} />);
    expect(screen.getByText("win.vidar")).toBeInTheDocument();
  });

  it("renders one SourceDetailRow per detail entry", () => {
    renderWithI18n(<ClassificationBlock type="c2_server" ca={ca} />);
    expect(screen.getAllByText(/otx/).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/threatfox/)).toBeInTheDocument();
  });

  it("omits the 上报 suffix when reporter_total is 0", () => {
    const zero = { ...ca, reporter_total: 0 };
    renderWithI18n(<ClassificationBlock type="c2_server" ca={zero} />);
    expect(screen.queryByText(/reporters/)).not.toBeInTheDocument();
  });

  it("shows 判定冲突 badge when verdict_conflict", () => {
    const conflicted = { ...ca, verdict_conflict: true };
    renderWithI18n(<ClassificationBlock type="c2_server" ca={conflicted} />);
    expect(screen.getByText(/Conflict/)).toBeInTheDocument();
  });
});
