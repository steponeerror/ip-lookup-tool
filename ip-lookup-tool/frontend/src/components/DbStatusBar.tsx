import { useEffect, useState } from "react";
import { getDbStatus, updateDb } from "../api";
import type { DbStatus } from "../api";

export function DbStatusBar() {
  const [status, setStatus] = useState<DbStatus | null>(null);
  const [updating, setUpdating] = useState(false);

  useEffect(() => {
    getDbStatus().then(setStatus);
  }, []);

  const handleUpdate = async () => {
    setUpdating(true);
    try {
      const s = await updateDb();
      setStatus(s);
    } finally {
      setUpdating(false);
    }
  };

  if (!status) return null;

  return (
    <div className="fixed bottom-0 inset-x-0 border-t border-zinc-800 bg-zinc-950/90 backdrop-blur-sm">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-2 text-xs font-mono text-zinc-500">
        <div className="flex items-center gap-3">
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-40" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
          </span>
          <span>{status.record_count.toLocaleString()} records</span>
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