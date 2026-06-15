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
  native_type?: string;
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
  asn: MergedField<number | string>;
  as_name: MergedField<string>;
  ip_range: MergedField<string>;
  is_isp: boolean;
  classifications: Record<string, ClassificationAssessment>;
  attributes?: Record<string, AssetStatement[]>;
  is_whitelisted: boolean;
  whitelist_notes: string[];
  error?: string;
}

export interface DbStatus {
  last_updated: string;
  record_count: number;
  cn_record_count: number;
  is_stale: boolean;
  warnings?: string[];
}

export interface QueryResponse {
  results: LookupResult[];
  enrich_error?: string;
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

export interface UpdateProgress {
  done: number;
  total: number;
  currentStep: string;
  stepStatus: string;
  errors: string[];
}

export async function updateDbStream(
  onProgress: (p: UpdateProgress) => void,
): Promise<DbStatus> {
  const res = await fetch("/api/update-db", { method: "POST" });
  if (!res.ok) {
    let detail: string;
    try { const body = await res.json(); detail = body.detail || ""; } catch { detail = res.statusText; }
    throw new Error(detail || "Database update failed");
  }
  if (!res.body) throw new Error("Streaming not supported");

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let finalStatus: DbStatus | null = null;
  const errors: string[] = [];

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop()!;
    for (const line of lines) {
      if (!line.trim()) continue;
      let evt: any;
      try { evt = JSON.parse(line); } catch { continue; }
      if (evt.type === "start") {
        onProgress({ done: 0, total: evt.total, currentStep: "", stepStatus: "starting", errors: [] });
      } else if (evt.type === "step") {
        if (evt.error) errors.push(evt.error);
        onProgress({ done: evt.done, total: evt.total, currentStep: evt.name, stepStatus: evt.status, errors: [...errors] });
      } else if (evt.type === "complete") {
        finalStatus = evt.status;
      }
    }
  }
  if (!finalStatus) throw new Error("No status received");
  return finalStatus;
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
): Promise<QueryResponse> {
  if (!res.body) throw new Error("Streaming not supported");
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let finalResult: QueryResponse | null = null;

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
        onProgress({ done: 0, total: evt.total, phase: "lookup" });
      } else if (evt.type === "progress") {
        onProgress({ done: evt.done, total: evt.total, phase: "lookup" });
      } else if (evt.type === "enriching") {
        onProgress({ done: evt.done, total: evt.total, phase: "enrich" });
      } else if (evt.type === "complete") {
        const result: QueryResponse = { results: evt.results };
        if (evt.enrich_error) result.enrich_error = evt.enrich_error;
        finalResult = result;
      }
    }
  }
  if (!finalResult) throw new Error("No results received");
  return finalResult;
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
): Promise<QueryResponse> {
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
): Promise<QueryResponse> {
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
