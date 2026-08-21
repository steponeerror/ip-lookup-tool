import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  enqueueBatch,
  enqueueSingle,
  getTasks,
  getDbStatus,
  cancelTask,
  cancelBatch,
  pauseBatch,
  resumeBatch,
  subscribeTasks,
  queryIpsStream,
  TABLE_THRESHOLD,
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

describe("queryIpsStream (row protocol v2)", () => {
  beforeEach(() => {
    globalThis.fetch = vi.fn() as any;
    (globalThis.EventSource as any) = vi.fn(() => ({ close: () => {} })) as any;
  });

  it("table mode: total ≤ threshold → results sorted by idx", async () => {
    const ndjson = [
      `{"type":"start","total":2}`,
      `{"type":"row","idx":1,"result":{"ip":"1.1.1.1"}}`,
      `{"type":"row","idx":0,"result":{"ip":"8.8.8.8"}}`,
      `{"type":"progress","done":2,"total":2}`,
      `{"type":"done","invalid_lines":0,"ipv6_unsupported":0}`,
    ].join("\n");
    const reader = (async function* () {
      for (const line of ndjson.split("\n")) yield new TextEncoder().encode(line + "\n");
    })();
    (globalThis.fetch as any).mockResolvedValue({
      ok: true,
      body: { getReader: () => ({ read: () => reader.next() }) },
    });

    const out = await queryIpsStream(["8.8.8.8", "1.1.1.1"], () => {});
    expect(out.csvDownloaded).toBe(false);
    expect(out.results.map((r: any) => r.ip)).toEqual(["8.8.8.8", "1.1.1.1"]); // idx order
  });

  it("csv mode: total > threshold → csvDownloaded=true, results empty", async () => {
    // build N=threshold+1 fake rows; minimal valid LookupResult (buildCsvRow traverses
    // classifications/merged fields, so the fixture must satisfy that shape)
    const n = TABLE_THRESHOLD + 1;
    const fakeRow = (i: number) => {
      const r: any = {
        ip: `10.0.0.${i}`,
        country: { value: "", confidence: 0, algorithm: "", sources: [] },
        city: { value: "", confidence: 0, algorithm: "", sources: [] },
        asn: { value: 0, confidence: 0, algorithm: "", sources: [] },
        as_name: { value: "", confidence: 0, algorithm: "", sources: [] },
        ip_range: { value: "", confidence: 0, algorithm: "", sources: [] },
        is_isp: false,
        classifications: {},
      };
      return `{"type":"row","idx":${i},"result":${JSON.stringify(r)}}`;
    };
    const lines = [`{"type":"start","total":${n}}`];
    for (let i = 0; i < n; i++) lines.push(fakeRow(i));
    lines.push(`{"type":"done","invalid_lines":0,"ipv6_unsupported":0}`);
    const ndjson = lines.join("\n");
    const reader = (async function* () {
      yield new TextEncoder().encode(ndjson + "\n");
    })();
    (globalThis.fetch as any).mockResolvedValue({
      ok: true,
      body: { getReader: () => ({ read: () => reader.next() }) },
    });

    const URL_CREATE = globalThis.URL.createObjectURL;
    const REVOKE = globalThis.URL.revokeObjectURL;
    globalThis.URL.createObjectURL = (() => "blob:x") as any;
    globalThis.URL.revokeObjectURL = (() => {}) as any;
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});

    const out = await queryIpsStream(["10.0.0.0/20"], () => {});
    expect(out.csvDownloaded).toBe(true);
    expect(out.results).toEqual([]);
    expect(clickSpy).toHaveBeenCalledTimes(1);

    globalThis.URL.createObjectURL = URL_CREATE;
    globalThis.URL.revokeObjectURL = REVOKE;
    clickSpy.mockRestore();
  });

  it("done surfaces invalid_lines and ipv6_unsupported counts", async () => {
    const ndjson = [
      `{"type":"start","total":1}`,
      `{"type":"row","idx":0,"result":{"ip":"8.8.8.8"}}`,
      `{"type":"done","invalid_lines":2,"ipv6_unsupported":1}`,
    ].join("\n");
    const reader = (async function* () {
      yield new TextEncoder().encode(ndjson + "\n");
    })();
    (globalThis.fetch as any).mockResolvedValue({
      ok: true,
      body: { getReader: () => ({ read: () => reader.next() }) },
    });
    const out = await queryIpsStream(["8.8.8.8"], () => {});
    expect(out.invalidLines).toBe(2);
    expect(out.ipv6Unsupported).toBe(1);
  });

  it("done surfaces error into outcome", async () => {
    const ndjson = [
      `{"type":"start","total":2}`,
      `{"type":"row","idx":0,"result":{"ip":"8.8.8.8"}}`,
      `{"type":"done","invalid_lines":0,"ipv6_unsupported":0,"error":"boom"}`,
    ].join("\n");
    const reader = (async function* () {
      yield new TextEncoder().encode(ndjson + "\n");
    })();
    (globalThis.fetch as any).mockResolvedValue({
      ok: true,
      body: { getReader: () => ({ read: () => reader.next() }) },
    });

    const out = await queryIpsStream(["8.8.8.8"], () => {});
    expect(out.error).toBe("boom");
  });

  it("clean EOF without done → error 'stream ended before done'", async () => {
    // 代理截断/进程被杀的干净关闭: start+row 已到但 done 永不到来
    const ndjson = [
      `{"type":"start","total":2}`,
      `{"type":"row","idx":0,"result":{"ip":"8.8.8.8"}}`,
    ].join("\n");
    const reader = (async function* () {
      yield new TextEncoder().encode(ndjson + "\n");
    })();
    (globalThis.fetch as any).mockResolvedValue({
      ok: true,
      body: { getReader: () => ({ read: () => reader.next() }) },
    });

    const out = await queryIpsStream(["8.8.8.8", "1.1.1.1"], () => {});
    expect(out.error).toBe("stream ended before done");
  });
});

describe("apiError status attachment (review #10)", () => {
  beforeEach(() => {
    globalThis.fetch = vi.fn() as any;
  });

  it("getDbStatus throws an error carrying the HTTP status and reason", async () => {
    (globalThis.fetch as any).mockResolvedValue(
      new Response(JSON.stringify({ detail: "database is warming up" }), {
        status: 503,
        headers: { "Content-Type": "application/json", "X-IPRadar-Reason": "warming" },
      }),
    );
    const err: any = await getDbStatus().then(() => null, (e: unknown) => e);
    expect(err).toBeInstanceOf(Error);
    expect(err.status).toBe(503);
    expect(err.reason).toBe("warming");
    expect(err.message).toBe("database is warming up");
  });

  it("falls back and still carries status when the body is not JSON", async () => {
    (globalThis.fetch as any).mockResolvedValue(
      new Response("gateway hiccup", { status: 502 }),
    );
    const err: any = await getDbStatus().then(() => null, (e: unknown) => e);
    expect(err).toBeInstanceOf(Error);
    expect(err.status).toBe(502);
  });
});
