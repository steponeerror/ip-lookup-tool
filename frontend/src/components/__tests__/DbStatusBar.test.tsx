import { describe, it, expect, vi } from "vitest";
import { screen, waitFor, fireEvent } from "@testing-library/react";
import { DbStatusBar } from "../DbStatusBar";
import { TaskProvider } from "../../tasks/TaskProvider";
import { renderWithI18n } from "../../test/i18nTestUtils";
import {
  enqueueBatch, pauseBatch, cancelBatch, cancelTask, getTasks,
} from "../../api";

vi.mock("../../api", async () => {
  const real = await vi.importActual<any>("../../api");
  return {
    ...real,
    getDbStatus: vi.fn().mockResolvedValue({
      last_updated: "", record_count: 0, cn_record_count: 0, total_records: 100,
      scalar_records: 60, threat_records: 30, asset_records: 10, is_stale: false,
    }),
    getTasks: vi.fn().mockResolvedValue({
      tasks: [{ id: "t1", source: "feodo", host: null, state: "downloading", error: null, batch_id: "b1" }],
      batch: { id: "b1", state: "running", done: 0, total: 2 },
    }),
    subscribeTasks: vi.fn(() => () => {}),
    enqueueBatch: vi.fn().mockResolvedValue({ batch_id: "b1" }),
    cancelTask: vi.fn().mockResolvedValue(undefined),
    cancelBatch: vi.fn().mockResolvedValue(undefined),
    pauseBatch: vi.fn().mockResolvedValue(undefined),
    resumeBatch: vi.fn().mockResolvedValue(undefined),
  };
});

function render(el: React.ReactElement) {
  return renderWithI18n(<TaskProvider>{el}</TaskProvider>);
}

describe("DbStatusBar active panel", () => {
  it("shows overall pct and a per-source row when batch active", async () => {
    render(<DbStatusBar />);
    // Per-source row appears from the snapshot
    expect(await screen.findByText(/feodo/)).toBeInTheDocument();
    // Overall done/total (regex matches "Updating · 0/2 · 0%")
    expect(screen.getByText(/0\/2/)).toBeInTheDocument();
  });

  it("calls pauseBatch when Pause is clicked", async () => {
    render(<DbStatusBar />);
    const pauseBtn = await screen.findByRole("button", { name: /Pause/i });
    fireEvent.click(pauseBtn);
    await waitFor(() => expect(pauseBatch).toHaveBeenCalled());
  });

  it("calls cancelBatch when Abort is clicked", async () => {
    render(<DbStatusBar />);
    const abortBtn = await screen.findByRole("button", { name: /Abort/i });
    fireEvent.click(abortBtn);
    await waitFor(() => expect(cancelBatch).toHaveBeenCalled());
  });

  it("calls cancelTask with id when per-row ✕ is clicked", async () => {
    render(<DbStatusBar />);
    // The per-row ✕ is a button with aria-label "Cancel feodo".
    const rowCancel = await screen.findByRole("button", { name: /Cancel feodo/i });
    fireEvent.click(rowCancel);
    await waitFor(() => expect(cancelTask).toHaveBeenCalledWith("t1"));
  });
});

describe("DbStatusBar idle bar", () => {
  it("renders Update DB button and triggers enqueueBatch on click", async () => {
    // Override getTasks to return empty (idle state)
    (getTasks as any).mockResolvedValue({ tasks: [], batch: null });
    render(<DbStatusBar />);
    const updateBtn = await screen.findByRole("button", { name: /Update DB/i });
    fireEvent.click(updateBtn);
    await waitFor(() => expect(enqueueBatch).toHaveBeenCalled());
  });
});
