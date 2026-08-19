import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, act, waitFor } from "@testing-library/react";
import { TaskProvider, useTasks } from "../TaskProvider";
import type { TaskState, BatchState } from "../../api";

function Probe() {
  const t = useTasks();
  return (
    <div>
      <span data-testid="count">{t.tasks.length}</span>
      <span data-testid="frozen">{t.tasks[0]?.frozenFrac ?? "-"}</span>
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

  it("progress ticks mid-fetch do NOT discard the resync snapshot (F5)", async () => {
    // 下载洪峰期 progress tick ~0.15s 一次;若它也置 sseSaw,resync 快照
    // 几乎总被丢弃(SSE 溢出丢掉 done 事件时 batch 永远卡 running)。
    let resolveSnap!: (v: any) => void;
    const delayed = new Promise<any>(r => { resolveSnap = r; });
    const fetchMock = vi.fn().mockReturnValue(delayed);
    (globalThis as any).fetch = fetchMock;
    const es = makeFakeEventSource();
    (globalThis as any).EventSource = es.FakeEventSource as any;
    render(
      <TaskProvider>
        <Probe />
      </TaskProvider>,
    );
    await screen.findByText("none");   // 挂载渲染完成,fetch 仍 pending
    await act(async () => {
      es.fireMessage({ type: "task_progress", task_id: "x", received: 1, total: 2 });
    });
    resolveSnap({
      ok: true,
      json: async () => ({
        tasks: [{ id: "s1", source: "feodo", host: null, state: "done", error: null, batch_id: "b9" }],
        batch: { id: "b9", state: "done", done: 1, total: 1 },
      }),
    });
    expect(await screen.findByText("done:1/1")).toBeInTheDocument();  // 快照生效
  });

  it("a state event mid-fetch still discards the resync snapshot (fresher wins)", async () => {
    let resolveSnap!: (v: any) => void;
    const delayed = new Promise<any>(r => { resolveSnap = r; });
    const fetchMock = vi.fn().mockReturnValue(delayed);
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
      es.fireMessage({ type: "batch", batch: { id: "b1", state: "running", done: 0, total: 1 } });
    });
    expect(await screen.findByText("running:0/1")).toBeInTheDocument();
    resolveSnap({
      ok: true,
      json: async () => ({ tasks: [], batch: { id: "zz", state: "done", done: 0, total: 0 } }),
    });
    await act(async () => {});   // flush 微任务
    expect(screen.getByTestId("batch").textContent).toBe("running:0/1");  // 被丢弃
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

  it("终态 failed 事件冻结最后非终态分数", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ tasks: [], batch: null }),
    });
    (globalThis as unknown as { fetch: typeof fetch }).fetch = fetchMock;
    const es = makeFakeEventSource();
    (globalThis as unknown as { EventSource: typeof EventSource }).EventSource =
      es.FakeEventSource as unknown as typeof EventSource;
    render(
      <TaskProvider>
        <Probe />
      </TaskProvider>,
    );
    await screen.findByText("none");
    await act(async () => {
      es.fireMessage({ type: "task", task: {
        id: "t1", source: "s", host: null, state: "downloading",
        error: null, batch_id: null } });
    });
    await act(async () => {
      es.fireMessage({ type: "task_progress", task_id: "t1", received: 40, total: 100 });
    });
    await act(async () => {
      es.fireMessage({ type: "task", task: {
        id: "t1", source: "s", host: null, state: "failed",
        error: "x", batch_id: null, received: 40, total: 100 } });
    });
    await waitFor(() => expect(screen.getByTestId("frozen").textContent).toBe("0.2"));
  });

  it("终态 cancelled 同样冻结;done 不冻结(=1 由公式给出)", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ tasks: [], batch: null }),
    });
    (globalThis as unknown as { fetch: typeof fetch }).fetch = fetchMock;
    const es = makeFakeEventSource();
    (globalThis as unknown as { EventSource: typeof EventSource }).EventSource =
      es.FakeEventSource as unknown as typeof EventSource;
    render(
      <TaskProvider>
        <Probe />
      </TaskProvider>,
    );
    await screen.findByText("none");
    await act(async () => {
      es.fireMessage({ type: "task", task: { id: "t2", source: "s", host: null,
        state: "loading", error: null, batch_id: null } });
    });
    await act(async () => {
      es.fireMessage({ type: "task_progress", task_id: "t2", received: 50, total: 100 });
    });
    await act(async () => {
      es.fireMessage({ type: "task", task: { id: "t2", source: "s", host: null,
        state: "cancelled", error: null, batch_id: null } });
    });
    await waitFor(() => expect(screen.getByTestId("frozen").textContent).toBe("0.75"));
  });
});
