import { useEffect, useRef, useState } from "react";
import { getDbStatus, type DbStatus } from "../api";
import { useTasks } from "../tasks/TaskProvider";
import { useI18n } from "../i18n";
import { stagedFrac, isIndeterminate } from "../tasks/progress";

const BADGE: Record<string, string> = {
  queued: "text-zinc-400 border-zinc-700 bg-zinc-800/50",
  throttled: "text-zinc-400 border-zinc-700 bg-zinc-800/50",
  downloading: "text-emerald-400 border-emerald-500/20 bg-emerald-500/5",
  loading: "text-emerald-400 border-emerald-500/20 bg-emerald-500/5",
  done: "text-emerald-400 border-emerald-500/20 bg-emerald-500/5",
  failed: "text-red-400 border-red-400/30 bg-red-400/10",
  cancelled: "text-zinc-500 border-zinc-700 bg-zinc-800/50",
};

const ACTIVE_TASK_STATES = ["queued", "throttled", "downloading", "loading"];

export const fmtBytes = (n: number): string => {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
};

export const fmtRows = (n: number): string => {
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(0)}K`;
  return `${n}`;
};

export function DbStatusBar() {
  const { t } = useI18n();
  const { tasks, batch, enqueueBatch, cancelTask, cancelBatch, pause, resume } = useTasks();
  const [status, setStatus] = useState<DbStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState(true);
  const [updating, setUpdating] = useState(false);
  // Keep the active panel mounted for ~5s after the batch finishes so the
  // user sees the final state before the bar collapses back to idle.
  const [recentlyDone, setRecentlyDone] = useState(false);
  // Last observed batch state this session. The backend keeps the finished
  // batch referenced after it completes, so a cold snapshot can already report
  // state "done" — that must not re-trigger the celebration on every page load.
  // Only an in-session transition running/paused → done counts as "recent".
  const prevBatchState = useRef<string | undefined>(undefined);

  useEffect(() => {
    getDbStatus()
      .then(setStatus)
      .catch((e) => setError(e instanceof Error ? e.message : t("dbStatus.statusUnavailable")));
  }, [t, batch?.state]);

  useEffect(() => {
    const cur = batch?.state;
    const prev = prevBatchState.current;
    prevBatchState.current = cur;
    if (cur === "done" && (prev === "running" || prev === "paused")) {
      setRecentlyDone(true);
      setExpanded(true);
      const id = setTimeout(() => {
        setRecentlyDone(false);
        setExpanded(false);
      }, 5000);
      return () => clearTimeout(id);
    }
  }, [batch?.state]);

  const handleUpdate = async () => {
    setUpdating(true);
    try {
      await enqueueBatch();
    } catch (e) {
      setError(e instanceof Error ? e.message : t("dbStatus.updateFailed"));
    } finally {
      setUpdating(false);
    }
  };

  const taskActive = tasks.some((t) => ACTIVE_TASK_STATES.includes(t.state));
  const active = taskActive
    || (batch != null && batch.state !== "done")
    || (recentlyDone && batch?.state === "done");

  if (!active) {
    return (
      <IdleBar
        status={status}
        error={error}
        updating={updating}
        onUpdate={handleUpdate}
      />
    );
  }

  // Show only tasks relevant to the current view: when a batch is active
  // (running/paused, or lingering done via recentlyDone), show that batch's
  // tasks; when batchless (a single-source update), show only currently-active
  // tasks so terminal tasks accumulated from prior batches don't clutter the panel.
  const visibleTasks = batch
    ? tasks.filter((t) => t.batch_id === batch.id)
    : tasks.filter((t) => ACTIVE_TASK_STATES.includes(t.state));

  // Overall progress across visible tasks: averages each task's staged
  // fraction (download 0→0.5, rebuild 0.5→1) so the top bar moves
  // DURING downloads and rebuilds — not only when a whole source completes.
  const overallPct = visibleTasks.length > 0
    ? Math.round((visibleTasks.reduce((s, t) => s + stagedFrac(t), 0) / visibleTasks.length) * 100)
    : 0;
  const headerLabel = batch?.state === "paused" ? t("dbStatus.paused") : t("dbStatus.updating");
  return (
    <div className="fixed bottom-0 inset-x-0 border-t border-emerald-500/30 bg-zinc-950/90 backdrop-blur-sm">
      <div className="mx-auto max-w-7xl px-4 py-2 text-xs font-mono">
        <div className="flex items-center justify-between text-emerald-400">
          <span>
            {headerLabel}{batch != null && ` · ${batch.done}/${batch.total}`} · {overallPct}%
          </span>
          <span className="flex gap-2">
            {batch?.state === "paused" ? (
              <button
                onClick={() => resume()}
                className="rounded px-2 py-0.5 text-emerald-400 hover:bg-zinc-800 hover:text-emerald-300"
                aria-label={t("dbStatus.resume")}
              >
                ▶ {t("dbStatus.resume")}
              </button>
            ) : (
              <button
                onClick={() => pause()}
                disabled={batch?.state === "done"}
                className="rounded px-2 py-0.5 text-emerald-400 hover:bg-zinc-800 hover:text-emerald-300 disabled:opacity-50"
                aria-label={t("dbStatus.pause")}
              >
                ⏸ {t("dbStatus.pause")}
              </button>
            )}
            <button
              onClick={() => cancelBatch()}
              className="rounded px-2 py-0.5 text-red-400 hover:bg-zinc-800 hover:text-red-300"
              aria-label={t("dbStatus.abort")}
            >
              ✕ {t("dbStatus.abort")}
            </button>
            <button
              onClick={() => setExpanded((e) => !e)}
              className="rounded px-2 py-0.5 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200"
              aria-label={expanded ? "Collapse" : "Expand"}
            >
              {expanded ? "▴" : "▾"}
            </button>
          </span>
        </div>
        <div className="mt-1 h-1 overflow-hidden rounded-full bg-zinc-800">
          <div
            className="h-full rounded-full bg-emerald-500 transition-all duration-300"
            style={{ width: `${overallPct}%` }}
          />
        </div>
        {expanded && (
          <div className="mt-1 max-h-40 overflow-y-auto">
            {visibleTasks.map((task) => (
              <div key={task.id} className="flex items-center gap-2 py-0.5">
                <span className="w-32 truncate font-mono text-zinc-300" title={task.source}>
                  {task.source}
                </span>
                <span
                  className={`rounded-md border px-2 text-[10px] ${BADGE[task.state] ?? ""}`}
                >
                  {task.state}
                </span>
                <div className="h-1 flex-1 overflow-hidden rounded-full bg-zinc-800">
                  {(() => {
                    if (task.state === "failed") {
                      return <div className="h-full w-full rounded-full bg-red-500" />;
                    }
                    if (isIndeterminate(task)) {
                      return <div className="h-full w-1/3 rounded-full bg-emerald-500 animate-pulse" />;
                    }
                    const f = stagedFrac(task);
                    if (f > 0 || task.state === "done") {
                      return (
                        <div
                          className="h-full rounded-full bg-emerald-500 transition-all duration-150"
                          style={{ width: `${Math.min(100, Math.round(f * 100))}%` }}
                        />
                      );
                    }
                    return null;
                  })()}
                </div>
                <span className="w-10 shrink-0 text-right font-mono text-[10px] tabular-nums text-zinc-500">
                  {isIndeterminate(task) ? "--%" : `${Math.round(stagedFrac(task) * 100)}%`}
                </span>
                {(task.state === "downloading" || task.state === "loading") && (task.received ?? 0) > 0 && (
                  <span className="shrink-0 font-mono text-[10px] tabular-nums text-zinc-500">
                    {task.state === "downloading"
                      ? `${fmtBytes(task.received!)}${(task.total ?? 0) > 0 ? `/${fmtBytes(task.total!)}` : ""}`
                      : `${fmtRows(task.received!)}${(task.total ?? 0) > 0 ? `/${fmtRows(task.total!)}` : ""} ${t("dbStatus.rows")}`}
                  </span>
                )}
                {task.error && (
                  <span className="truncate text-red-400/80" title={task.error}>
                    {task.error}
                  </span>
                )}
                <button
                  className="text-zinc-500 hover:text-red-400 disabled:opacity-30"
                  onClick={() => cancelTask(task.id)}
                  disabled={!ACTIVE_TASK_STATES.includes(task.state)}
                  aria-label={`Cancel ${task.source}`}
                >
                  ✕
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function IdleBar({
  status,
  error,
  updating,
  onUpdate,
}: {
  status: DbStatus | null;
  error: string | null;
  updating: boolean;
  onUpdate: () => void;
}) {
  const { t } = useI18n();

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
            onClick={onUpdate}
            disabled={updating}
            className="rounded px-3 py-1 text-red-400 transition-colors hover:bg-zinc-800 hover:text-red-300 disabled:opacity-50"
          >
            {updating ? t("dbStatus.retrying") : t("dbStatus.retry")}
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
              {t("dbStatus.records", { n: status.total_records.toLocaleString() })}
            </span>
          </div>
          <button
            onClick={onUpdate}
            disabled={updating}
            className="rounded px-3 py-1 text-amber-400 transition-colors hover:bg-zinc-800 hover:text-amber-300 disabled:opacity-50"
          >
            {updating ? t("dbStatus.updating") : t("dbStatus.retry")}
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
          <span>{t("dbStatus.records", { n: status.total_records.toLocaleString() })}</span>
          <span className="text-zinc-700">|</span>
          <span className="text-zinc-500 tabular-nums">
            {status.scalar_records.toLocaleString()} {t("dbStatus.scalar")}
          </span>
          <span className="text-zinc-600">·</span>
          <span className="text-zinc-500 tabular-nums">
            {status.threat_records.toLocaleString()} {t("dbStatus.threat")}
          </span>
          <span className="text-zinc-600">·</span>
          <span className="text-zinc-500 tabular-nums">
            {status.asset_records.toLocaleString()} {t("dbStatus.asset")}
          </span>
          <span className="text-zinc-700">|</span>
          <span>{t("dbStatus.updated", { time: status.last_updated })}</span>
          {status.is_stale && (
            <span className="text-yellow-500">({t("dbStatus.stale")})</span>
          )}
        </div>
        <button
          onClick={onUpdate}
          disabled={updating}
          className="rounded px-3 py-1 text-zinc-400 transition-colors hover:bg-zinc-800 hover:text-emerald-400 disabled:opacity-50"
        >
          {updating ? t("dbStatus.updating") : t("dbStatus.update")}
        </button>
      </div>
    </div>
  );
}
