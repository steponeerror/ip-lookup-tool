import { useEffect, useState } from "react";
import { getDbStatus, updateDb } from "../api";
import type { DbStatus } from "../api";

export function DbStatusBar() {
  const [status, setStatus] = useState<DbStatus | null>(null);
  const [updating, setUpdating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getDbStatus()
      .then(setStatus)
      .catch((e) => setError(e instanceof Error ? e.message : "Status unavailable"));
  }, []);

  const handleUpdate = async () => {
    setUpdating(true);
    setError(null);
    try {
      const s = await updateDb();
      setStatus(s);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Database update failed");
    } finally {
      setUpdating(false);
    }
  };

  if (!status && !error) return null;

  const hasWarnings = status?.warnings && status.warnings.length > 0;

  // Full failure: no status, only error
  if (!status) {
    return (
      <div className="fixed bottom-0 inset-x-0 border-t border-red-500/30 bg-zinc-950/90 backdrop-blur-sm">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-2 text-xs font-mono">
          <div className="flex items-center gap-3 text-red-400">
            <span className="inline-flex h-2 w-2 rounded-full bg-red-500" />
            <span>{error}</span>
          </div>
          <button
            onClick={handleUpdate}
            disabled={updating}
            className="rounded px-3 py-1 text-red-400 transition-colors hover:bg-zinc-800 hover:text-red-300 disabled:opacity-50"
          >
            {updating ? "Retrying..." : "Retry"}
          </button>
        </div>
      </div>
    );
  }

  // Partial failure: status + warnings
  if (hasWarnings) {
    return (
      <div className="fixed bottom-0 inset-x-0 border-t border-amber-500/30 bg-zinc-950/90 backdrop-blur-sm">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-2 text-xs font-mono text-amber-400">
          <div className="flex items-center gap-3">
            <span className="inline-flex h-2 w-2 rounded-full bg-amber-500" />
            <span>{status.warnings!.join("; ")}</span>
            <span className="text-zinc-700">|</span>
            <span className="text-zinc-500">
              {status.record_count.toLocaleString()} ASN + {status.cn_record_count.toLocaleString()} CN ISP
            </span>
          </div>
          <button
            onClick={handleUpdate}
            disabled={updating}
            className="rounded px-3 py-1 text-amber-400 transition-colors hover:bg-zinc-800 hover:text-amber-300 disabled:opacity-50"
          >
            {updating ? "Updating..." : "Retry"}
          </button>
        </div>
      </div>
    );
  }

  // Success
  return (
    <div className="fixed bottom-0 inset-x-0 border-t border-zinc-800 bg-zinc-950/90 backdrop-blur-sm">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-2 text-xs font-mono text-zinc-500">
        <div className="flex items-center gap-3">
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-40" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
          </span>
          <span>{status.record_count.toLocaleString()} ASN + {status.cn_record_count.toLocaleString()} CN ISP</span>
          <span className="text-zinc-700">|</span>
          <span>Updated {status.last_updated}</span>
          {status.is_stale && (
            <span className="text-yellow-500">(stale)</span>
          )}
        </div>
        <button
          onClick={handleUpdate}
          disabled={updating}
          className="rounded px-3 py-1 text-zinc-400 transition-colors hover:bg-zinc-800 hover:text-emerald-400 disabled:opacity-50"
        >
          {updating ? "Updating..." : "Update DB"}
        </button>
      </div>
    </div>
  );
}
