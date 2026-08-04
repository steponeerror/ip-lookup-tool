import { useCallback, useEffect, useState } from "react";
import { motion, useReducedMotion } from "motion/react";
import {
  enqueueBatch,
  enqueueSingle,
  getSources,
  setSourceEnabled,
} from "../api";
import type { SourceInfo, TaskState } from "../api";
import { useI18n } from "../i18n";
import { useTasks } from "../tasks/TaskProvider";

const CATEGORY_ORDER = ["geo_asn", "threat", "asset", "other"];

function formatCount(n: number): string {
  if (n <= 0) return "-";
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1).replace(/\.0$/, "") + "M";
  if (n >= 1_000) return Math.round(n / 1_000) + "K";
  return String(n);
}

function timeAgo(iso: string | null): { key: string; vars?: Record<string, string | number> } {
  if (!iso) return { key: "sources.timeAgo.onDemand" };
  const ms = Date.now() - Date.parse(iso);
  if (Number.isNaN(ms)) return { key: "sources.timeAgo.unknown" };
  const min = Math.floor(ms / 60000);
  if (min < 1) return { key: "sources.timeAgo.justNow" };
  if (min < 60) return { key: "sources.timeAgo.minutes", vars: { n: min } };
  const hr = Math.floor(min / 60);
  if (hr < 24) return { key: "sources.timeAgo.hours", vars: { n: hr } };
  return { key: "sources.timeAgo.days", vars: { n: Math.floor(hr / 24) } };
}

function statusOf(s: SourceInfo): { key: string; className: string } {
  if (s.health.error) return { key: "sources.status.error", className: "text-red-400 border-red-400/30 bg-red-400/10" };
  if (!s.enabled) return { key: "sources.status.off", className: "text-zinc-500 border-zinc-700 bg-zinc-800/50" };
  if (s.archetype === "online") return { key: "sources.status.onDemand", className: "text-emerald-400 border-emerald-500/20 bg-emerald-500/5" };
  if (!s.health.loaded) return { key: "sources.status.notLoaded", className: "text-amber-400 border-amber-400/30 bg-amber-400/10" };
  if (s.health.is_stale) return { key: "sources.status.stale", className: "text-amber-400 border-amber-400/30 bg-amber-400/10" };
  return { key: "sources.status.fresh", className: "text-emerald-400 border-emerald-500/20 bg-emerald-500/5" };
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
      <span className={`absolute left-0.5 top-0.5 h-4 w-4 rounded-full bg-white transition-transform ${
        on ? "translate-x-4" : "translate-x-0"
      }`} />
    </button>
  );
}

export default function SourcesPage() {
  const { t } = useI18n();
  const { tasks, batch } = useTasks();
  const [sources, setSources] = useState<SourceInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const reduce = useReducedMotion();

  const fmtTime = (iso: string | null) => {
    const ta = timeAgo(iso);
    return t(ta.key, ta.vars);
  };

  const fetchSources = useCallback(async () => {
    setError(null);
    try {
      setSources(await getSources());
    } catch (e) {
      setError(e instanceof Error ? e.message : t("sources.loadFailed"));
    } finally {
      setLoading(false);
    }
  }, [t]);

  // Initial fetch: setState is reached only after `await getSources()` inside the
  // async callback, but react-hooks/set-state-in-effect is a heuristic flag.
  // Same idiom as ResultTable.tsx (pre-existing); pattern mandated by task brief.
  // eslint-disable-next-line react-hooks/set-state-in-effect
  useEffect(() => { fetchSources(); }, [fetchSources]);

  // Debounce-refetch: when the count of finished tasks (done/failed/cancelled)
  // changes, re-sync the source list after 500ms so health/record_count updates.
  const doneCount = tasks.filter(
    (tk) => tk.state === "done" || tk.state === "failed" || tk.state === "cancelled",
  ).length;
  useEffect(() => {
    if (doneCount === 0) return;
    const id = setTimeout(() => { void fetchSources(); }, 500);
    return () => clearTimeout(id);
  }, [doneCount, fetchSources]);

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
      setError(e instanceof Error ? e.message : t("sources.toggleFailed", { name: s.name }));
    }
  };

  const handleUpdate = async (name: string) => {
    try {
      await enqueueSingle(name);
    } catch (e) {
      setError(e instanceof Error ? e.message : t("sources.updateOneFailed", { name }));
    }
  };

  const handleRefreshAll = async () => {
    setInfo(null);
    try {
      const { refreshed } = await enqueueBatch();
      if (refreshed === 0) setInfo(t("sources.allFresh"));
    } catch (e) {
      setError(e instanceof Error ? e.message : t("sources.refreshAllFailed"));
    }
  };

  // Batch active → global "refreshing" indicator (disables per-row Update + the
  // Refresh-all button). Derived from context, no local state.
  const refreshingAll = batch?.state === "running";

  const grouped = CATEGORY_ORDER
    .map((cat) => ({ cat, items: sources.filter((s) => s.category === cat) }))
    .filter((g) => g.items.length > 0);

  // tasks arrive oldest-first and a source accumulates terminal tasks across
  // batches; the last state seen per source is the current one. Index once so
  // re-updating a previously-updated source still reflects its live phase
  // (regression: `find()` returned the stale first task and hid the progress).
  const phaseBySource = new Map<string, TaskState["state"]>();
  for (const tk of tasks) phaseBySource.set(tk.source, tk.state);

  return (
    <section className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-medium text-zinc-400">
          {sources.length > 0 ? t("sources.titleCount", { n: sources.length }) : t("sources.title")}
        </h2>
        <button
          onClick={handleRefreshAll}
          disabled={refreshingAll || loading}
          className="rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-1.5 text-sm text-zinc-200 transition-colors hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {refreshingAll ? t("sources.refreshingAll") : t("sources.refreshAll")}
        </button>
      </div>

      {error && (
        <div className="rounded-lg border border-red-400/30 bg-red-400/10 px-4 py-2 text-sm text-red-400">
          {error}
        </div>
      )}

      {info && !error && (
        <div className="rounded-lg border border-emerald-400/30 bg-emerald-400/10 px-4 py-2 text-sm text-emerald-400">
          {info}
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
          {t("sources.none")}
        </div>
      ) : (
        grouped.map(({ cat, items }) => (
          <div key={cat}>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-zinc-600">
              {t(`sources.cat.${cat}`)}
            </h3>
            <motion.ul
              initial={reduce ? false : { opacity: 0 }}
              animate={{ opacity: 1 }}
              className="divide-y divide-zinc-900 overflow-hidden rounded-lg border border-zinc-800"
            >
              {items.map((s) => {
                const st = statusOf(s);
                // Per-row phase comes from the tasks context (SSE-driven), not
                // local state. A row is "busy" only when a task for this source
                // is queued / downloading / loading.
                const phase = phaseBySource.get(s.name);
                const busy =
                  phase === "queued" ||
                  phase === "downloading" ||
                  phase === "loading";
                return (
                  <li key={s.name} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
                    <span className="w-32 shrink-0 font-mono text-sm text-zinc-200">{s.name}</span>
                    <span className="w-16 shrink-0 text-xs text-zinc-500">{s.fields[0] ?? s.archetype}</span>
                    <span className="w-16 shrink-0 text-right font-mono text-sm tabular-nums text-zinc-300">
                      {formatCount(s.health.record_count)}
                    </span>
                    <span className="w-24 shrink-0 text-xs text-zinc-500">{fmtTime(s.health.last_updated)}</span>
                    <span className={`w-24 shrink-0 rounded-md border px-2 py-0.5 text-center text-xs ${st.className}`}>
                      {t(st.key)}
                    </span>
                    <div className="ml-auto flex items-center gap-3">
                      <Toggle
                        on={s.enabled}
                        disabled={busy}
                        onChange={(v) => handleToggle(s, v)}
                        label={t("sources.toggleAria", { name: s.name })}
                      />
                      {s.archetype === "online" ? null : (
                        <button
                          onClick={() => handleUpdate(s.name)}
                          disabled={busy || refreshingAll}
                          className="rounded-md border border-zinc-700 px-2.5 py-1 text-xs text-zinc-200 transition-colors hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-50"
                        >
                          {phase === "loading"
                            ? t("sources.loading")
                            : phase === "downloading"
                              ? t("sources.downloading")
                              : t("sources.update")}
                        </button>
                      )}
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
