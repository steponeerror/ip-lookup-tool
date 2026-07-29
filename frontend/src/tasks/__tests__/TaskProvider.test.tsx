import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, act } from "@testing-library/react";
import { TaskProvider, useTasks } from "../TaskProvider";
import type { TaskState, BatchState } from "../../api";

function Probe() {
  const t = useTasks();
  return (
    <div>
      <span data-testid="count">{t.tasks.length}</span>
      <span data-testid="batch">
        {t.batch ? `${t.batch.state}:${t.batch.done}/${t.batch.total}` : "none"}
      </span>
      <button onClick={() => t.enqueueSingle("feodo")}>single</button>
      <button onClick={() => t.enqueueBatch()}>batch</button>
    </div>
  );
}

// Build a mock EventSource constructor whose onmessage/onopen handlers can be
// captured and fired from tests. Arrow-function impls can't be `new`-ed, so we
// use a real function and stash handlers on the instance.
function makeFakeEventSource(closeSpy?: () => void) {
  let onMessage: ((m: any) => void) | null = null;
  let onOpen: (() => void) | null = null;
  function FakeEventSource(this: any) {
    this.close = closeSpy ?? (() => {});
    Object.defineProperty(this, "onmessage", {
      get: () => onMessage,
      set: (v) => { onMessage = v; },
      configurable: true,
    });
    Object.defineProperty(this, "onopen", {
      get: () => onOpen,
      set: (v) => { onOpen = v; },
      configurable: true,
    });
  }
  return {
    FakeEventSource,
    fireMessage: (data: any) => {
      onMessage?.({ data: typeof data === "string" ? data : JSON.stringify(data) });
    },
    fireOpen: () => { onOpen?.(); },
  };
}

describe("TaskProvider", () => {
  beforeEach(() => {
    // Default stub; tests that need to assert on SSE overwrite this.
    (globalThis as any).EventSource = vi.fn(function (this: any) {
      this.onmessage = null;
      this.onopen = null;
      this.close = () => {};
    });
  });

  it("loads snapshot on mount", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        tasks: [
          { id: "t1", source: "feodo", host: null, state: "done", error: null, batch_id: "b1" },
        ],
        batch: { id: "b1", state: "done", done: 1, total: 1 },
      }),
    });
    (globalThis as any).fetch = fetchMock;
    render(
      <TaskProvider>
        <Probe />
      </TaskProvider>,
    );
    expect(await screen.findByText("1")).toBeInTheDocument();
    expect(await screen.findByText("done:1/1")).toBeInTheDocument();
  });

  it("applies snapshot event replacing all tasks", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ tasks: [], batch: null }),
    });
    (globalThis as any).fetch = fetchMock;
    const es = makeFakeEventSource();
    (globalThis as any).EventSource = es.FakeEventSource as any;
    render(
      <TaskProvider>
        <Probe />
      </TaskProvider>,
    );
    await screen.findByText("none");
    await act(async () => {
      es.fireMessage({
        type: "snapshot",
        data: {
          tasks: [
            { id: "a", source: "feodo", host: null, state: "done", error: null, batch_id: "b1" },
            { id: "b", source: "tor", host: null, state: "downloading", error: null, batch_id: "b1" },
          ],
          batch: { id: "b1", state: "running", done: 1, total: 2 },
        },
      });
    });
    expect(await screen.findByText("2")).toBeInTheDocument();
    expect(await screen.findByText("running:1/2")).toBeInTheDocument();
  });

  it("upserts a single task event by id", async () => {
    const t1: TaskState = { id: "t1", source: "feodo", host: null, state: "queued", error: null, batch_id: "b1" };
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ tasks: [t1], batch: { id: "b1", state: "running", done: 0, total: 1 } as BatchState }),
    });
    (globalThis as any).fetch = fetchMock;
    const es = makeFakeEventSource();
    (globalThis as any).EventSource = es.FakeEventSource as any;
    render(
      <TaskProvider>
        <Probe />
      </TaskProvider>,
    );
    await screen.findByText("1");
    // upsert existing t1 -> done (count unchanged)
    await act(async () => {
      es.fireMessage({
        type: "task",
        task: { id: "t1", source: "feodo", host: null, state: "done", error: null, batch_id: "b1" },
      });
    });
    expect(await screen.findByText("1")).toBeInTheDocument();
    // insert new t2 (count -> 2)
    await act(async () => {
      es.fireMessage({
        type: "task",
        task: { id: "t2", source: "tor", host: null, state: "queued", error: null, batch_id: "b1" },
      });
    });
    expect(await screen.findByText("2")).toBeInTheDocument();
  });

  it("updates batch state on batch and done events", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ tasks: [], batch: null }),
    });
    (globalThis as any).fetch = fetchMock;
    const es = makeFakeEventSource();
    (globalThis as any).EventSource = es.FakeEventSource as any;
    render(
      <TaskProvider>
        <Probe />
      </TaskProvider>,
    );
    await screen.findByText("none");
    await act(async () => {
      es.fireMessage({
        type: "batch",
        batch: { id: "b1", state: "running", done: 0, total: 3 },
      });
    });
    expect(await screen.findByText("running:0/3")).toBeInTheDocument();
    await act(async () => {
      es.fireMessage({
        type: "done",
        batch: { id: "b1", state: "done", done: 3, total: 3 },
      });
    });
    expect(await screen.findByText("done:3/3")).toBeInTheDocument();
  });

  it("re-fetches snapshot on reconnect (onopen)", async () => {
    const fetchMock = vi.fn();
    fetchMock
      .mockResolvedValueOnce({ ok: true, json: async () => ({ tasks: [], batch: null }) })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          tasks: [{ id: "r1", source: "feodo", host: null, state: "done", error: null, batch_id: "b2" }],
          batch: { id: "b2", state: "done", done: 1, total: 1 },
        }),
      });
    (globalThis as any).fetch = fetchMock;
    const es = makeFakeEventSource();
    (globalThis as any).EventSource = es.FakeEventSource as any;
    render(
      <TaskProvider>
        <Probe />
      </TaskProvider>,
    );
    await screen.findByText("none");
    await act(async () => { es.fireOpen(); });
    expect(await screen.findByText("1")).toBeInTheDocument();
    expect(await screen.findByText("done:1/1")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("closes EventSource on unmount", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ tasks: [], batch: null }),
    });
    (globalThis as any).fetch = fetchMock;
    const closeSpy = vi.fn();
    const es = makeFakeEventSource(closeSpy);
    (globalThis as any).EventSource = es.FakeEventSource as any;
    const { unmount } = render(
      <TaskProvider>
        <Probe />
      </TaskProvider>,
    );
    await screen.findByText("none");
    unmount();
    expect(closeSpy).toHaveBeenCalled();
  });

  it("useTasks throws when used outside provider", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    function Orphan() {
      useTasks();
      return null;
    }
    expect(() => render(<Orphan />)).toThrow(/useTasks must be used within TaskProvider/);
    spy.mockRestore();
  });
});
