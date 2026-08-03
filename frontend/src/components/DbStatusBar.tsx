import { useEffect, useState } from "react";
import { getDbStatus, updateDbStream } from "../api";
import type { DbStatus, UpdateProgress } from "../api";
import { useI18n } from "../i18n";

export function DbStatusBar() {
  const { t } = useI18n();
  const [status, setStatus] = useState<DbStatus | null>(null);
  const [updating, setUpdating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<UpdateProgress | null>(null);

  useEffect(() => {
    getDbStatus()
      .then(setStatus)
      .catch((e) => setError(e instanceof Error ? e.message : t("dbStatus.statusUnavailable")));
  }, [t]);

  const handleUpdate = async () => {
    setUpdating(true);
    setError(null);
    setProgress(null);
    try {
      const s = await updateDbStream(setProgress);
      setStatus(s);
    } catch (e) {
      setError(e instanceof Error ? e.message : t("dbStatus.updateFailed"));
    } finally {
      setUpdating(false);
      setProgress(null);
    }
  };

  if (!status && !error) return null;

  // Updating with progress
  if (updating && progress) {
    const pct = progress.total > 0 ? Math.round((progress.done / progress.total) * 100) : 0;
    const stepLabel = progress.stepStatus === "downloading"
      ? t("dbStatus.downloading", { step: progress.currentStep })
      : progress.stepStatus === "loading"
        ? t("dbStatus.loading")
        : progress.currentStep
          ? `${progress.currentStep} ${progress.stepStatus}`
          : t("dbStatus.starting");
    return (
      <div className="fixed bottom-0 inset-x-0 border-t border-emerald-500/30 bg-zinc-950/90 backdrop-blur-sm">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-2 text-xs font-mono">
          <div className="flex flex-1 flex-col gap-1">
            <div className="flex items-center justify-between text-emerald-400">
              <span className="flex items-center gap-2">
                <svg className="h-3.5 w-3.5 animate-spin" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                {stepLabel}
                <span className="text-zinc-600">{progress.done}/{progress.total}</span>
              </span>
              <span className="text-zinc-500 tabular-nums">{pct}%</span>
            </div>
            <div className="h-1 overflow-hidden rounded-full bg-zinc-800">
              <div
                className="h-full rounded-full bg-emerald-500 transition-all duration-300 ease-out"
                style={{ width: `${pct}%` }}
              />
            </div>
          </div>
        </div>
      </div>
    );
  }

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
            onClick={handleUpdate}
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
          onClick={handleUpdate}
          disabled={updating}
          className="rounded px-3 py-1 text-zinc-400 transition-colors hover:bg-zinc-800 hover:text-emerald-400 disabled:opacity-50"
        >
          {updating ? t("dbStatus.updating") : t("dbStatus.update")}
        </button>
      </div>
    </div>
  );
}
