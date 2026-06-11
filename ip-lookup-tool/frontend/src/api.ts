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
}

export async function queryIps(ips: string[], enrich?: boolean): Promise<LookupResult[]> {
  const params = enrich ? "?enrich=true" : "";
  const res = await fetch(`/api/query${params}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ips }),
  });
  if (!res.ok) {
    let detail: string;
    try { const body = await res.json(); detail = body.detail || ""; } catch { detail = res.statusText; }
    throw new Error(detail || "Query failed");
  }
  const data = await res.json();
  return data.results;
}

export async function uploadFile(file: File, enrich?: boolean): Promise<LookupResult[]> {
  const params = enrich ? "?enrich=true" : "";
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`/api/upload${params}`, {
    method: "POST",
    body: form,
  });
  if (!res.ok) {
    let detail: string;
    try { const body = await res.json(); detail = body.detail || ""; } catch { detail = res.statusText; }
    throw new Error(detail || "Upload failed");
  }
  const data = await res.json();
  return data.results;
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
