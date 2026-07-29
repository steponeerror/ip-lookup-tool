import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  enqueueBatch,
  enqueueSingle,
  getTasks,
  cancelTask,
  cancelBatch,
  pauseBatch,
  resumeBatch,
  subscribeTasks,
} from "../api";

describe("api task functions", () => {
  beforeEach(() => {
    globalThis.fetch = vi.fn() as any;
    (globalThis.EventSource as any) = vi.fn(() => ({ close: () => {} })) as any;
  });

  it("enqueueBatch posts /api/update-db", async () => {
    (globalThis.fetch as any).mockResolvedValue({
      ok: true,
      json: async () => ({ batch_id: "b1" }),
    });
    const r = await enqueueBatch();
    expect(r.batch_id).toBe("b1");
    expect((globalThis.fetch as any).mock.calls[0][0]).toBe("/api/update-db");
    expect((globalThis.fetch as any).mock.calls[0][1].method).toBe("POST");
  });

  it("enqueueSingle posts to source update", async () => {
    (globalThis.fetch as any).mockResolvedValue({
      ok: true,
      json: async () => ({ task_id: "t1" }),
    });
    const r = await enqueueSingle("feodo");
    expect(r.task_id).toBe("t1");
    const [url, init] = (globalThis.fetch as any).mock.calls[0];
    expect(url).toBe("/api/sources/feodo/update");
    expect(init.method).toBe("POST");
  });

  it("enqueueSingle encodes the source name", async () => {
    (globalThis.fetch as any).mockResolvedValue({
      ok: true,
      json: async () => ({ task_id: "t2" }),
    });
    await enqueueSingle("weird name");
    expect((globalThis.fetch as any).mock.calls[0][0]).toBe(
      "/api/sources/weird%20name/update",
    );
  });

  it("getTasks returns snapshot", async () => {
    (globalThis.fetch as any).mockResolvedValue({
      ok: true,
      json: async () => ({ tasks: [], batch: null }),
    });
    const s = await getTasks();
    expect(s.tasks).toEqual([]);
    expect(s.batch).toBeNull();
    expect((globalThis.fetch as any).mock.calls[0][0]).toBe("/api/tasks");
  });

  it("getTasks throws on non-ok response", async () => {
    (globalThis.fetch as any).mockResolvedValue({
      ok: false,
      statusText: "Server Error",
    });
    await expect(getTasks()).rejects.toThrow();
  });

  it("enqueueBatch throws on non-ok response", async () => {
    (globalThis.fetch as any).mockResolvedValue({
      ok: false,
      statusText: "Boom",
    });
    await expect(enqueueBatch()).rejects.toThrow();
  });

  it("cancelTask posts to /api/tasks/:id/cancel", async () => {
    (globalThis.fetch as any).mockResolvedValue({ ok: true });
    await cancelTask("t9");
    const [url, init] = (globalThis.fetch as any).mock.calls[0];
    expect(url).toBe("/api/tasks/t9/cancel");
    expect(init.method).toBe("POST");
  });

  it("cancelBatch posts to /api/update-db/cancel", async () => {
    (globalThis.fetch as any).mockResolvedValue({ ok: true });
    await cancelBatch();
    const [url, init] = (globalThis.fetch as any).mock.calls[0];
    expect(url).toBe("/api/update-db/cancel");
    expect(init.method).toBe("POST");
  });

  it("pauseBatch posts to /api/update-db/pause", async () => {
    (globalThis.fetch as any).mockResolvedValue({ ok: true });
    await pauseBatch();
    const [url, init] = (globalThis.fetch as any).mock.calls[0];
    expect(url).toBe("/api/update-db/pause");
    expect(init.method).toBe("POST");
  });

  it("resumeBatch posts to /api/update-db/resume", async () => {
    (globalThis.fetch as any).mockResolvedValue({ ok: true });
    await resumeBatch();
    const [url, init] = (globalThis.fetch as any).mock.calls[0];
    expect(url).toBe("/api/update-db/resume");
    expect(init.method).toBe("POST");
  });
});

describe("subscribeTasks", () => {
  beforeEach(() => {
    globalThis.fetch = vi.fn() as any;
  });

  it("opens EventSource on /api/events, parses JSON, returns unsub that closes", () => {
    const close = vi.fn();
    let msgHandler: ((m: any) => void) | null = null;
    let openHandler: (() => void) | null = null;
    (globalThis.EventSource as any) = vi.fn(function (this: any, url: string) {
      expect(url).toBe("/api/events");
      this.onmessage = null;
      this.onopen = null;
      Object.defineProperty(this, "onmessage", {
        set(f: any) { msgHandler = f; },
        get() { return msgHandler; },
      });
      Object.defineProperty(this, "onopen", {
        set(f: any) { openHandler = f; },
        get() { return openHandler; },
      });
      this.close = close;
    }) as any;

    const events: any[] = [];
    const onReconnect = vi.fn();
    const unsub = subscribeTasks((e) => events.push(e), onReconnect);

    // onopen fires → onReconnect
    openHandler!();
    expect(onReconnect).toHaveBeenCalledTimes(1);

    // valid JSON payload is parsed & forwarded
    msgHandler!({ data: JSON.stringify({ tasks: [], batch: null }) });
    expect(events).toHaveLength(1);
    expect(events[0]).toEqual({ tasks: [], batch: null });

    // invalid JSON is swallowed (no throw, no push)
    expect(() => msgHandler!({ data: "not-json" })).not.toThrow();
    expect(events).toHaveLength(1);

    // unsub closes the EventSource
    unsub();
    expect(close).toHaveBeenCalledTimes(1);
  });

  it("onReconnect is optional", () => {
    (globalThis.EventSource as any) = vi.fn(function (this: any) {
      this.onmessage = null;
      this.onopen = null;
      this.close = () => {};
    }) as any;
    const unsub = subscribeTasks(() => {});
    expect(() => unsub()).not.toThrow();
  });
});
