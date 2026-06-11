export interface FieldResult<T> {
  value: T;
  confidence: "high" | "medium" | "low";
  sources: Record<string, T>;
}

export interface ThreatValue {
  is_proxy: boolean;
  is_mobile: boolean;
  is_hosting: boolean;
}

export interface ThreatSourceValue {
  is_proxy: boolean | null;
  is_mobile: boolean | null;
  is_hosting: boolean | null;
}

export interface ThreatFieldResult {
  value: ThreatValue;
  sources: Record<string, ThreatSourceValue>;
  per_boolean_confidence: {
    is_proxy: "high" | "medium" | "low";
    is_mobile: "high" | "medium" | "low";
    is_hosting: "high" | "medium" | "low";
  };
}

export interface LookupResult {
  ip: string;
  asn: FieldResult<number | string>;
  country: FieldResult<string>;
  as_name: FieldResult<string>;
  is_isp: boolean;
  threat: ThreatFieldResult;
  ip_range: FieldResult<string>;
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

export async function queryIps(ips: string[], enrich?: boolean): Promise<QueryResponse> {
  const params = enrich ? "?enrich=true" : "";
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 120_000);
  try {
    const res = await fetch(`/api/query${params}`, {
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
    const data = await res.json();
    return data;
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError") {
      throw new Error("Request timed out (120s)");
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

export async function uploadFile(file: File, enrich?: boolean): Promise<QueryResponse> {
  const params = enrich ? "?enrich=true" : "";
  const form = new FormData();
  form.append("file", file);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 120_000);
  try {
    const res = await fetch(`/api/upload${params}`, {
      method: "POST",
      body: form,
      signal: controller.signal,
    });
    if (!res.ok) {
      let detail: string;
      try { const body = await res.json(); detail = body.detail || ""; } catch { detail = res.statusText; }
      throw new Error(detail || "Upload failed");
    }
    const data = await res.json();
    return data;
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError") {
      throw new Error("Request timed out (120s)");
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
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

export async function updateDb(): Promise<DbStatus> {
  const res = await fetch("/api/update-db", { method: "POST" });
  if (!res.ok) {
    let detail: string;
    try { const body = await res.json(); detail = body.detail || ""; } catch { detail = res.statusText; }
    throw new Error(detail || "Database update failed");
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
): Promise<QueryResponse> {
  if (!res.body) throw new Error("Streaming not supported");
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let finalResult: QueryResponse | null = null;

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

export async function queryIpsStream(
  ips: string[],
  onProgress: (p: Progress) => void,
): Promise<QueryResponse> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 120_000);
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
    return await readStream(res, onProgress);
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError") {
      throw new Error("Request timed out (120s)");
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

export async function uploadFileStream(
  file: File,
  onProgress: (p: Progress) => void,
): Promise<QueryResponse> {
  const form = new FormData();
  form.append("file", file);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 120_000);
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
    return await readStream(res, onProgress);
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError") {
      throw new Error("Request timed out (120s)");
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}
