import { describe, it, expect, vi } from "vitest";
import { screen, fireEvent } from "@testing-library/react";
import LookupView from "../LookupView";
import { renderWithI18n } from "../test/i18nTestUtils";
import { queryIpsStream } from "../api";

vi.mock("../api", async () => {
  const real = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...real,
    queryIpsStream: vi.fn().mockResolvedValue({
      results: [],
      csvDownloaded: false,
      invalidLines: 0,
      ipv6Unsupported: 0,
      total: 1,
      error: "boom",
    }),
  };
});

describe("LookupView stream done.error", () => {
  it("shows error banner when queryIpsStream resolves with error (no throw)", async () => {
    renderWithI18n(<LookupView />);

    const textarea = screen.getByPlaceholderText(/1\.1\.1\.1/i);
    fireEvent.change(textarea, { target: { value: "8.8.8.8" } });
    fireEvent.click(screen.getByRole("button", { name: /^Query$/i }));

    expect(await screen.findByText("boom")).toBeInTheDocument();
    expect(queryIpsStream).toHaveBeenCalledWith(["8.8.8.8"], expect.anything());
  });
});
