export interface LookupResult {
  ip: string;
  asn: number | string;
  country_code: string;
  as_name: string;
  ip_range: string;
  error?: string;
}

export interface DbStatus {
  last_updated: string;
  record_count: number;
  is_stale: boolean;
}

export async function queryIps(ips: string[]): Promise<LookupResult[]> {
  const res = await fetch("/api/query", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ips }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || "Query failed");
  }
  const data = await res.json();
  return data.results;
}

export async function uploadFile(file: File): Promise<LookupResult[]> {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch("/api/upload", {
    method: "POST",
    body: form,
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || "Upload failed");
  }
  const data = await res.json();
  return data.results;
}

export async function getDbStatus(): Promise<DbStatus> {
  const res = await fetch("/api/db-status");
  return res.json();
}

export async function updateDb(): Promise<DbStatus> {
  const res = await fetch("/api/update-db", { method: "POST" });
  return res.json();
}
