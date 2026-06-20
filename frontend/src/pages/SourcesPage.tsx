import { useCallback, useEffect, useState } from "react";
import { motion, useReducedMotion } from "motion/react";
import {
  getSources,
  setSourceEnabled,
  updateSource,
  updateDbStream,
} from "../api";
import type { SourceInfo } from "../api";

const CATEGORY_LABELS: Record<string, string> = {
  geo_asn: "Geo / ASN",
  threat: "Threat intel",
  asset: "Asset attributes",
  other: "Other",
};
const CATEGORY_ORDER = ["geo_asn", "threat", "asset", "other"];

function formatCount(n: number): string {
  if (n <= 0) return "-";
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1).replace(/\.0$/, "") + "M";
  if (n >= 1_000) return Math.round(n / 1_000) + "K";
  return String(n);
}

function timeAgo(iso: string | null): string {
  if (!iso) return "on-demand";
  const ms = Date.now() - Date.parse(iso);
  if (Number.isNaN(ms)) return "unknown";
  const min = Math.floor(ms / 60000);
  if (min < 1) return "just now";
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  return `${Math.floor(hr / 24)}d ago`;
}

function statusOf(s: SourceInfo): { label: string; className: string } {
  if (s.health.error) return { label: "error", className: "text-red-400 border-red-400/30 bg-red-400/10" };
  if (!s.enabled) return { label: "off", className: "text-zinc-500 border-zinc-700 bg-zinc-800/50" };
  if (s.archetype === "online") return { label: "on-demand", className: "text-emerald-400 border-emerald-500/20 bg-emerald-500/5" };
  if (!s.health.loaded) return { label: "not loaded", className: "text-amber-400 border-amber-400/30 bg-amber-400/10" };
  if (s.health.is_stale) return { label: "stale", className: "text-amber-400 border-amber-400/30 bg-amber-400/10" };
  return { label: "fresh", className: "text-emerald-400 border-emerald-500/20 bg-emerald-500/5" };
}

function Toggle({ on, disabled, onChange, label }: {
  on: boolean; disabled: boolean; onChange: (v: boolean) => void; label: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!on)}
      className={`relative h-5 w-9 shrink-0 rounded-full transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400 ${
        on ? "bg-emerald-500" : "bg-zinc-700"
      } ${disabled ? "cursor-not-allowed opacity-50" : ""}`}
    >
      <span className={`absolute top-0.5 h-4 w-4 rounded-full bg-white transition-transform ${
        on ? "translate-x-4" : "translate-x-0.5"
      }`} />
    </button>
  );
}

export default function SourcesPage() {
  const [sources, setSources] = useState<SourceInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyName, setBusyName] = useState<string | null>(null);
  const [refreshingAll, setRefreshingAll] = useState(false);
  const reduce = useReducedMotion();

  const fetchSources = useCallback(async () => {
    setError(null);
    try {
      setSources(await getSources());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load sources");
    } finally {
      setLoading(false);
    }
  }, []);

  // Initial fetch: setState is reached only after `await getSources()` inside the
  // async callback, but react-hooks/set-state-in-effect is a heuristic flag.
  // Same idiom as ResultTable.tsx (pre-existing); pattern mandated by task brief.
  // eslint-disable-next-line react-hooks/set-state-in-effect
  useEffect(() => { fetchSources(); }, [fetchSources]);

  const patch = (name: string, change: Partial<SourceInfo>) => {
    setSources((prev) => prev.map((s) => (s.name === name ? { ...s, ...change } : s)));
  };

  const handleToggle = async (s: SourceInfo, next: boolean) => {
    patch(s.name, { enabled: next });
    try {
      const updated = await setSourceEnabled(s.name, next);
      patch(s.name, { enabled: updated.enabled, health: updated.health });
    } catch (e) {
      patch(s.name, { enabled: s.enabled });  // rollback
      setError(e instanceof Error ? e.message : `Failed to toggle ${s.name}`);
    }
  };

  const handleUpdate = async (name: string) => {
    setBusyName(name);
    try {
      const updated = await updateSource(name);
      patch(name, { health: updated.health });
    } catch (e) {
      setError(e instanceof Error ? e.message : `Failed to update ${name}`);
    } finally {
      setBusyName(null);
    }
  };

  const handleRefreshAll = async () => {
    setRefreshingAll(true);
    try {
      await updateDbStream(() => {});
      await fetchSources();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Refresh all failed");
    } finally {
      setRefreshingAll(false);
    }
  };

  const grouped = CATEGORY_ORDER
    .map((cat) => ({ cat, items: sources.filter((s) => s.category === cat) }))
    .filter((g) => g.items.length > 0);

  return (
    <section className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-medium text-zinc-400">
          {sources.length > 0 ? `Sources (${sources.length})` : "Sources"}
        </h2>
        <button
          onClick={handleRefreshAll}
          disabled={refreshingAll || loading}
          className="rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-1.5 text-sm text-zinc-200 transition-colors hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {refreshingAll ? "Refreshing all..." : "Refresh all"}
        </button>
      </div>

      {error && (
        <div className="rounded-lg border border-red-400/30 bg-red-400/10 px-4 py-2 text-sm text-red-400">
          {error}
        </div>
      )}

      {loading ? (
        <div className="space-y-2">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="h-12 animate-pulse rounded-lg bg-zinc-900" />
          ))}
        </div>
      ) : grouped.length === 0 ? (
        <div className="flex h-48 items-center justify-center rounded-lg border border-zinc-800 text-sm text-zinc-600">
          No sources discovered
        </div>
      ) : (
        grouped.map(({ cat, items }) => (
          <div key={cat}>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-zinc-600">
              {CATEGORY_LABELS[cat]}
            </h3>
            <motion.ul
              initial={reduce ? false : { opacity: 0 }}
              animate={{ opacity: 1 }}
              className="divide-y divide-zinc-900 overflow-hidden rounded-lg border border-zinc-800"
            >
              {items.map((s) => {
                const st = statusOf(s);
                const busy = busyName === s.name;
                return (
                  <li key={s.name} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
                    <span className="w-32 shrink-0 font-mono text-sm text-zinc-200">{s.name}</span>
                    <span className="w-16 shrink-0 text-xs text-zinc-500">{s.fields[0] ?? s.archetype}</span>
                    <span className="w-16 shrink-0 text-right font-mono text-sm tabular-nums text-zinc-300">
                      {formatCount(s.health.record_count)}
                    </span>
                    <span className="w-24 shrink-0 text-xs text-zinc-500">{timeAgo(s.health.last_updated)}</span>
                    <span className={`w-24 shrink-0 rounded-md border px-2 py-0.5 text-center text-xs ${st.className}`}>
                      {st.label}
                    </span>
                    <div className="ml-auto flex items-center gap-3">
                      <Toggle
                        on={s.enabled}
                        disabled={busy}
                        onChange={(v) => handleToggle(s, v)}
                        label={`Toggle ${s.name}`}
                      />
                      <button
                        onClick={() => handleUpdate(s.name)}
                        disabled={busy || refreshingAll}
                        className="rounded-md border border-zinc-700 px-2.5 py-1 text-xs text-zinc-200 transition-colors hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        {busy ? "Updating..." : "Update"}
                      </button>
                    </div>
                  </li>
                );
              })}
            </motion.ul>
          </div>
        ))
      )}
    </section>
  );
}
