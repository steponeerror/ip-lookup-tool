import { buildCsvRow, CSV_HEADER, downloadCsv } from "./components/csvExport";

export interface SourceAttribution {
  source: string;
  value: any;
  reliability: number;
  authoritative: boolean;
}

export interface AssetStatement {
  source: string;
  value: boolean | string;
  native_type?: string;
}

export interface MergedField<T = any> {
  value: T;
  confidence: number;           // 0-100 integer
  algorithm: string;            // "cascade" | "voting" | "pcr6" | "authority" | "specificity"
  sources: SourceAttribution[];
}

export interface ClassificationDetail {
  source: string;
  reliability: number;
  malware_name?: string;
  native_confidence?: number;
  first_seen?: string;
  comment?: string;
  tags?: string[];
  native_categories?: string[];
  reporter_count?: number;
  extra?: Record<string, unknown>;
}

export interface ClassificationAssessment {
  type: string;
  verdict: string;             // "malicious" | "suspicious" | "benign" | "informational"
  detected: boolean;
  confidence: number;           // 0-100 integer
  algorithm: string;
  corroborated: boolean;
  reporter_total: number;
  verdict_conflict: boolean;
  malware_names: string[];
  details: ClassificationDetail[];
  sources: SourceAttribution[];
}

export interface LookupResult {
  ip: string;
  country: MergedField<string>;
  city: MergedField<string>;
  city_zh?: string | null;
  asn: MergedField<number | string>;
  as_name: MergedField<string>;
  ip_range: MergedField<string>;
  is_isp: boolean;
  classifications: Record<string, ClassificationAssessment>;
  attributes?: Record<string, AssetStatement[]>;
  error?: string;
  is_reserved?: boolean;
}

export interface DbStatus {
  last_updated: string;
  record_count: number;
  cn_record_count: number;
  total_records: number;
  scalar_records: number;
  threat_records: number;
  asset_records: number;
  is_stale: boolean;
  warnings?: string[];
}

// Above this expanded-IP count the UI switches from table to CSV download.
// ResultTable paginates (renders only the current page slice), so DOM cost is
// constant regardless of total — the real ceiling is React state memory
// (results[] held in LookupView state, ~2KB/result → ~100MB at 50k).
export const TABLE_THRESHOLD = 50000;

export interface StreamOutcome {
  results: LookupResult[];   // table mode: populated; csv mode: []
  csvDownloaded: boolean;
  invalidLines: number;
  ipv6Unsupported: number;
  enrichError?: string | null;
  total: number;
}

export async function getDbStatus(): Promise<DbStatus> {
  const res = await fetch("/api/db-status");
  if (!res.ok) {
    let detail: string;
    try { const body = await res.json(); detail = body.detail || ""; } catch { detail = res.statusText; }
    throw new Error(detail || "Failed to get database status");
  }
  return res.json();
}

export interface Progress {
  done: number;
  total: number;
  phase: "lookup" | "enrich";
}

async function readStream(
  res: Response,
  onProgress: (p: Progress) => void,
  keepAlive?: () => void,
): Promise<StreamOutcome> {
  if (!res.body) throw new Error("Streaming not supported");
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let total = 0;
  let mode: "table" | "csv" | null = null;
  const resultsByIdx = new Map<number, LookupResult>();
  const csvParts: string[] = [CSV_HEADER];
  let rowBuffer: string[] = [];
  let invalidLines = 0;
  let ipv6Unsupported = 0;
  let enrichError: string | null = null;

  const flushRows = () => {
    if (rowBuffer.length) {
      csvParts.push(rowBuffer.join("\n") + "\n");
      rowBuffer = [];
    }
  };

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    keepAlive?.();
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop()!;
    for (const line of lines) {
      if (!line.trim()) continue;
      let evt: any;
      try { evt = JSON.parse(line); } catch { continue; }
      if (evt.type === "start") {
        total = evt.total;
        mode = total <= TABLE_THRESHOLD ? "table" : "csv";
      } else if (evt.type === "row") {
        const r = evt.result as LookupResult;
        if (mode === "table") {
          resultsByIdx.set(evt.idx, r);
        } else {
          rowBuffer.push(buildCsvRow(r));
          if (rowBuffer.length >= 1000) flushRows();
        }
      } else if (evt.type === "progress") {
        onProgress({ done: evt.done, total: evt.total, phase: "lookup" });
      } else if (evt.type === "done") {
        invalidLines = evt.invalid_lines ?? 0;
        ipv6Unsupported = evt.ipv6_unsupported ?? 0;
        enrichError = evt.enrich_error ?? null;
      }
    }
  }

  if (mode === "csv") {
    flushRows();
    if (csvParts.length > 1) {  // more than just the header → has rows
      downloadCsv(csvParts);
      return { results: [], csvDownloaded: true, invalidLines, ipv6Unsupported, enrichError, total };
    }
    return { results: [], csvDownloaded: false, invalidLines, ipv6Unsupported, enrichError, total };
  }

  // table mode — reassemble in idx order
  const results = Array.from({ length: total }, (_, i) => resultsByIdx.get(i)).filter(
    (x): x is LookupResult => x !== undefined,
  );
  return { results, csvDownloaded: false, invalidLines, ipv6Unsupported, enrichError, total };
}

function streamFetchTimeout(controller: AbortController, connectMs = 30_000, idleMs = 120_000) {
  let timer = setTimeout(() => controller.abort(), connectMs);
  return {
    resetIdle() {
      clearTimeout(timer);
      timer = setTimeout(() => controller.abort(), idleMs);
    },
    clear() {
      clearTimeout(timer);
    },
  };
}

export async function queryIpsStream(
  ips: string[],
  onProgress: (p: Progress) => void,
): Promise<StreamOutcome> {
  const controller = new AbortController();
  const { resetIdle, clear } = streamFetchTimeout(controller);
  try {
    const res = await fetch(`/api/query/stream`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ips }),
      signal: controller.signal,
    });
    if (!res.ok) {
      let detail: string;
      try { const body = await res.json(); detail = body.detail || ""; } catch { detail = res.statusText; }
      throw new Error(detail || "Query failed");
    }
    resetIdle();
    return await readStream(res, onProgress, resetIdle);
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError") {
      throw new Error("Request timed out (120s idle)");
    }
    throw e;
  } finally {
    clear();
  }
}

export async function uploadFileStream(
  file: File,
  onProgress: (p: Progress) => void,
): Promise<StreamOutcome> {
  const form = new FormData();
  form.append("file", file);
  const controller = new AbortController();
  const { resetIdle, clear } = streamFetchTimeout(controller);
  try {
    const res = await fetch(`/api/upload/stream`, {
      method: "POST",
      body: form,
      signal: controller.signal,
    });
    if (!res.ok) {
      let detail: string;
      try { const body = await res.json(); detail = body.detail || ""; } catch { detail = res.statusText; }
      throw new Error(detail || "Upload failed");
    }
    resetIdle();
    return await readStream(res, onProgress, resetIdle);
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError") {
      throw new Error("Request timed out (120s idle)");
    }
    throw e;
  } finally {
    clear();
  }
}

export interface SourceHealth {
  name: string;
  loaded: boolean;
  record_count: number;
  covered_ips: number;
  last_updated: string | null;
  is_stale: boolean;
  error: string | null;
}

export interface SourceInfo {
  name: string;
  enabled: boolean;
  category: "geo_asn" | "threat" | "asset" | "other";
  archetype: "offline" | "online";
  fields: string[];
  reliability: number;
  authoritative_for: string[];
  classification_type: string | null;
  url: string | null;
  stale_days: number | null;
  health: SourceHealth;
}

async function jsonOrThrow(res: Response, fallback: string) {
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || detail;
    } catch (e) {
      throw new Error(detail || fallback, { cause: e });
    }
    throw new Error(detail || fallback);
  }
  return res.json();
}

export async function getSources(): Promise<SourceInfo[]> {
  return jsonOrThrow(await fetch("/api/sources"), "Failed to load sources");
}

export async function setSourceEnabled(name: string, enabled: boolean): Promise<SourceInfo> {
  const res = await fetch(`/api/sources/${encodeURIComponent(name)}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled }),
  });
  return jsonOrThrow(res, "Failed to update source");
}

export async function updateSource(name: string): Promise<SourceInfo> {
  const res = await fetch(`/api/sources/${encodeURIComponent(name)}/update`, { method: "POST" });
  return jsonOrThrow(res, "Failed to refresh source");
}

// --- Task client: enqueue / control / subscribe (SSE) ---

export interface TaskState {
  id: string;
  source: string;
  host: string | null;
  state: "queued" | "downloading" | "loading" | "done" | "failed" | "cancelled";
  error: string | null;
  batch_id: string | null;
  received?: number;   // bytes downloaded (downloading phase only, via task_progress)
  total?: number;      // Content-Length, 0/unknown when absent
}

export interface BatchState {
  id: string;
  state: "running" | "paused" | "done";
  done: number;
  total: number;
}

export interface TasksSnapshot {
  tasks: TaskState[];
  batch: BatchState | null;
}

export async function getTasks(): Promise<TasksSnapshot> {
  const res = await fetch("/api/tasks");
  if (!res.ok) throw new Error("Failed to load tasks");
  return res.json();
}

export async function enqueueBatch(): Promise<{ batch_id: string | null; refreshed?: number }> {
  const res = await fetch("/api/update-db", { method: "POST" });
  if (!res.ok) throw new Error("Failed to start batch");
  return res.json();
}

export async function enqueueSingle(name: string): Promise<{ task_id: string }> {
  const res = await fetch(`/api/sources/${encodeURIComponent(name)}/update`, { method: "POST" });
  if (!res.ok) throw new Error(`Failed to update ${name}`);
  return res.json();
}

export async function cancelTask(id: string): Promise<void> {
  await fetch(`/api/tasks/${encodeURIComponent(id)}/cancel`, { method: "POST" });
}

export async function cancelBatch(): Promise<void> {
  await fetch("/api/update-db/cancel", { method: "POST" });
}

export async function pauseBatch(): Promise<void> {
  await fetch("/api/update-db/pause", { method: "POST" });
}

export async function resumeBatch(): Promise<void> {
  await fetch("/api/update-db/resume", { method: "POST" });
}

/**
 * Subscribe to task updates via SSE. `onEvent` receives each parsed JSON
 * payload; `onReconnect` fires on each (re)connection so the caller can
 * re-fetch a snapshot via `getTasks`. Returns an unsubscribe that closes
 * the EventSource. The browser handles auto-reconnect natively.
 */
export function subscribeTasks(
  onEvent: (e: any) => void,
  onReconnect?: () => void,
): () => void {
  const es = new EventSource("/api/events");
  es.onmessage = (m: MessageEvent) => {
    try {
      onEvent(JSON.parse(m.data));
    } catch {
      /* skip malformed payload */
    }
  };
  es.onopen = () => onReconnect?.();
  return () => es.close();
}

