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

  it("toggles the extra key/value block", () => {
    const d: ClassificationDetail = {
      ...base,
      extra: { foo: "bar", n: 1, b: true },
    };
    renderWithI18n(<SourceDetailRow detail={d} />);
    const toggle = screen.getByRole("button", { name: /extra 3 keys/i });
    const rowText = () => document.body.textContent ?? "";
    fireEvent.click(toggle);
    expect(rowText()).toContain("foo: ");
    expect(rowText()).toContain('"bar"');
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

  it("sbl_id and urls render as links, others plain", () => {
    const d: ClassificationDetail = {
      ...base,
      extra: { sbl_id: "SBL123456", tweet_url: "https://x.com/p/1", port: 80 },
    };
    renderWithI18n(<SourceDetailRow detail={d} />);
    fireEvent.click(screen.getByRole("button", { name: /extra 3 keys/i }));
    const sbl = screen.getByRole("link", { name: "SBL123456" }) as HTMLAnchorElement;
    expect(sbl.href).toBe("https://check.spamhaus.org/sbl/query/SBL123456");
    expect(sbl.target).toBe("_blank");
    const tweet = screen.getByRole("link", { name: "https://x.com/p/1" }) as HTMLAnchorElement;
    expect(tweet.href).toBe("https://x.com/p/1");
    // non-link values render as bare JSON text (no quotes stripped)
    expect(screen.getByText((c, el) => c === "80" && el?.className.includes("break-all") === false)).toBeTruthy();
  });
});
