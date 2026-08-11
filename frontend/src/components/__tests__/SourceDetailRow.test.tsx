import { describe, it, expect } from "vitest";
import { screen, fireEvent } from "@testing-library/react";
import { renderWithI18n } from "../../test/i18nTestUtils";
import { SourceDetailRow } from "../SourceDetailRow";
import type { ClassificationDetail } from "../../api";

const base: ClassificationDetail = { source: "otx", reliability: 0.9 };

describe("SourceDetailRow", () => {
  it("always renders source and reliability", () => {
    renderWithI18n(<SourceDetailRow detail={base} />);
    expect(screen.getByText(/otx/)).toBeInTheDocument();
    expect(screen.getByText(/rel 0\.9/)).toBeInTheDocument();
  });

  it("renders all optional fields when present", () => {
    const d: ClassificationDetail = {
      ...base,
      malware_name: "remcos",
      comment: "sinkholed by abuse.ch",
      tags: ["c2", "botnet"],
      reporter_count: 4,
      native_confidence: 85,
      first_seen: "2026-07-01T00:00:00+00:00",
      native_categories: ["PUB"],
    };
    renderWithI18n(<SourceDetailRow detail={d} />);
    expect(screen.getByText(/malware: remcos/)).toBeInTheDocument();
    expect(screen.getByText(/reporters: 4/)).toBeInTheDocument();
    expect(screen.getByText(/\[c2\]/)).toBeInTheDocument();
    expect(screen.getByText(/\[PUB\]/)).toBeInTheDocument();
    expect(screen.getByText(/native 85/)).toBeInTheDocument();
    expect(screen.getByText(/first 2026-07-01/)).toBeInTheDocument();
  });

  it("omits optional lines and the extra toggle when absent", () => {
    renderWithI18n(<SourceDetailRow detail={base} />);
    expect(screen.queryByText(/malware:/)).not.toBeInTheDocument();
    expect(screen.queryByText(/reporters:/)).not.toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("truncates long comments and exposes the full text via title", () => {
    const long = "x".repeat(60);
    const d: ClassificationDetail = { ...base, comment: long };
    renderWithI18n(<SourceDetailRow detail={d} />);
    const node = screen.getByText(/comment:/);
    expect(node.getAttribute("title")).toBe(long);
    expect(node.textContent).toContain("…");
  });

  it("toggles the extra JSON block", () => {
    const d: ClassificationDetail = {
      ...base,
      extra: { foo: "bar", n: 1, b: true },
    };
    renderWithI18n(<SourceDetailRow detail={d} />);
    const toggle = screen.getByRole("button", { name: /extra 3 keys/i });
    expect(screen.queryByText(/"foo"/)).not.toBeInTheDocument();
    fireEvent.click(toggle);
    expect(screen.getByText(/"foo"/)).toBeInTheDocument();
  });

  it("renders native_categories as chips", () => {
    const d: ClassificationDetail = { ...base, native_categories: ["15", "16"] };
    renderWithI18n(<SourceDetailRow detail={d} />);
    expect(screen.getByText(/\[15\]/)).toBeInTheDocument();
    expect(screen.getByText(/\[16\]/)).toBeInTheDocument();
  });

  it("ignores retired extra.native_type (fallback removed)", () => {
    const d: ClassificationDetail = { ...base, extra: { native_type: "PUB" } };
    renderWithI18n(<SourceDetailRow detail={d} />);
    expect(screen.queryByText(/\[PUB\]/)).not.toBeInTheDocument();  // fallback gone
  });
});
