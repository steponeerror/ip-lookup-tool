import { describe, it, expect, vi } from "vitest";
import { screen, waitFor, fireEvent, act } from "@testing-library/react";
import { DbStatusBar } from "../DbStatusBar";
import { TaskProvider } from "../../tasks/TaskProvider";
import { renderWithI18n } from "../../test/i18nTestUtils";
import {
  enqueueBatch, pauseBatch, cancelBatch, cancelTask, getTasks, resumeBatch,
} from "../../api";

// Hoisted holder so the (also hoisted) vi.mock factory can capture the SSE
// onEvent callback and tests can drive events through it. Tests that don't
// fire events simply never read this.
const sse = vi.hoisted(() => ({ onEvent: null as ((e: any) => void) | null }));

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
    subscribeTasks: vi.fn((onEvent: (e: any) => void) => {
      sse.onEvent = onEvent;
      return () => {};
    }),
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
    expect(await screen.findByText(/feodo/)).toBeInTheDocument();
    expect(screen.getByText(/0\/2/)).toBeInTheDocument();
  });

  it("calls pauseBatch when Pause is clicked", async () => {
    render(<DbStatusBar />);
    const pauseBtn = await screen.findByRole("button", { name: /Pause/i });
    fireEvent.click(pauseBtn);
    await waitFor(() => expect(pauseBatch).toHaveBeenCalled());
  });

  it("calls resumeBatch when Resume is clicked (paused batch)", async () => {
    const mockGetTasks = getTasks as any;
    mockGetTasks.mockReset();
    mockGetTasks.mockResolvedValue({
      tasks: [{ id: "t1", source: "feodo", host: null, state: "downloading", error: null, batch_id: "b1" }],
      batch: { id: "b1", state: "paused", done: 1, total: 2 },
    });
    render(<DbStatusBar />);
    const resumeBtn = await screen.findByRole("button", { name: /Resume/i });
    fireEvent.click(resumeBtn);
    await waitFor(() => expect(resumeBatch).toHaveBeenCalled());
  });

  it("calls cancelBatch when Abort is clicked", async () => {
    render(<DbStatusBar />);
    const abortBtn = await screen.findByRole("button", { name: /Abort/i });
    fireEvent.click(abortBtn);
    await waitFor(() => expect(cancelBatch).toHaveBeenCalled());
  });

  it("calls cancelTask with id when per-row ✕ is clicked", async () => {
    render(<DbStatusBar />);
    const rowCancel = await screen.findByRole("button", { name: /Cancel feodo/i });
    fireEvent.click(rowCancel);
    await waitFor(() => expect(cancelTask).toHaveBeenCalledWith("t1"));
  });
});

describe("DbStatusBar collapse on done", () => {
  it("lingers ~5s after batch done, then collapses to idle", async () => {
    const mockGetTasks = getTasks as any;
    mockGetTasks.mockReset();
    mockGetTasks.mockResolvedValue({
      tasks: [{ id: "t1", source: "feodo", host: null, state: "downloading", error: null, batch_id: "b1" }],
      batch: { id: "b1", state: "running", done: 0, total: 2 },
    });

    render(<DbStatusBar />);
    // Active panel visible — running batch shows 0/2 progress.
    expect(await screen.findByText(/0\/2/)).toBeInTheDocument();

    // Switch to fake timers to control the 5s collapse deterministically.
    vi.useFakeTimers();
    try {
      // Drive SSE: tasks all finished + batch done.
      await act(async () => {
        sse.onEvent!({
          type: "snapshot",
          data: {
            tasks: [{ id: "t1", source: "feodo", host: null, state: "done", error: null, batch_id: "b1" }],
            batch: { id: "b1", state: "done", done: 2, total: 2 },
          },
        });
      });
      // 2/2 visible — panel lingers to show the finished state.
      expect(screen.getByText(/2\/2/)).toBeInTheDocument();

      // Just under the 5s threshold — still lingering.
      await act(async () => { vi.advanceTimersByTime(4999); });
      expect(screen.getByText(/2\/2/)).toBeInTheDocument();

      // Cross the 5s threshold — panel collapses to idle.
      await act(async () => { vi.advanceTimersByTime(2); });
      expect(screen.queryByText(/2\/2/)).not.toBeInTheDocument();
      // Idle bar visible.
      expect(screen.getByRole("button", { name: /Update DB/i })).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("DbStatusBar idle bar", () => {
  it("renders Update DB button and triggers enqueueBatch on click", async () => {
    (getTasks as any).mockResolvedValueOnce({ tasks: [], batch: null });
    render(<DbStatusBar />);
    const updateBtn = await screen.findByRole("button", { name: /Update DB/i });
    fireEvent.click(updateBtn);
    await waitFor(() => expect(enqueueBatch).toHaveBeenCalled());
  });
});

describe("DbStatusBar cold-load with stale done batch", () => {
  it("does NOT pop the active panel when the snapshot already reports a done batch", async () => {
    const mockGetTasks = getTasks as any;
    mockGetTasks.mockReset();
    // Backend keeps _active_batch pointing at a finished batch, so the cold
    // snapshot reports batch.state === "done". This must NOT re-trigger the
    // 5s "recently done" celebration on every page load.
    mockGetTasks.mockResolvedValue({
      tasks: [],
      batch: { id: "b1", state: "done", done: 2, total: 2 },
    });
    render(<DbStatusBar />);
    // Drive the initial snapshot to resolution and flush the state update +
    // batch effect that derive from it. Asserting before this flush is racy:
    // the done batch has not yet been applied to `batch` state.
    await act(async () => {
      await waitFor(() => expect(getTasks).toHaveBeenCalled());
      await mockGetTasks.mock.results[0].value;   // resolved snapshot
      await Promise.resolve();                     // flush setBatch + effect
    });
    // The active source-update panel would render "2/2" (pct=100%); it must
    // NOT appear on a cold load whose snapshot reports an already-done batch.
    expect(screen.queryByText(/2\/2/)).not.toBeInTheDocument();
    // The idle bar should be shown instead.
    expect(screen.getByRole("button", { name: /Update DB/i })).toBeInTheDocument();
  });
});

describe("DbStatusBar batchless update hides stale tasks", () => {
  it("shows only the active batchless task, not terminal tasks from prior batches", async () => {
    const mockGetTasks = getTasks as any;
    mockGetTasks.mockReset();
    // After a batch finished, _tasks still holds its terminal tasks. A later
    // single-source update runs batchless (batch_id null, batch null). The panel
    // must show ONLY the active task, not the stale failed/done ones.
    mockGetTasks.mockResolvedValue({
      tasks: [
        { id: "t1", source: "abuseipdb", host: null, state: "failed", error: "429", batch_id: "old" },
        { id: "t2", source: "dataplane", host: null, state: "done", error: null, batch_id: "old" },
        { id: "t3", source: "ip2proxy", host: null, state: "loading", error: null, batch_id: null },
      ],
      batch: null,
    });
    render(<DbStatusBar />);
    expect(await screen.findByText(/ip2proxy/)).toBeInTheDocument();
    expect(screen.queryByText(/abuseipdb/)).not.toBeInTheDocument();
    expect(screen.queryByText(/dataplane/)).not.toBeInTheDocument();
  });
});

describe("DbStatusBar batchless single-task", () => {
  it("shows Updating label without 0/0 when active task has no batch", async () => {
    const mockGetTasks = getTasks as any;
    mockGetTasks.mockReset();
    mockGetTasks.mockResolvedValue({
      tasks: [{ id: "t1", source: "feodo", host: null, state: "downloading", error: null, batch_id: null }],
      batch: null,
    });
    render(<DbStatusBar />);
    expect(await screen.findByText(/feodo/)).toBeInTheDocument();
    // Batchless header: no misleading 0/0 · 0% suffix.
    expect(screen.queryByText(/0\/0/)).not.toBeInTheDocument();
  });
});
