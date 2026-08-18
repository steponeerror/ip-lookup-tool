import { useEffect, useRef, useState } from "react";
import { getDbStatus, type DbStatus } from "../api";
import { useTasks } from "../tasks/TaskProvider";
import { useI18n } from "../i18n";

const fmtBytes = (n: number): string => {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
};

export function WarmupBanner() {
  const { t } = useI18n();
  const { tasks, batch, enqueueBatch } = useTasks();
  const [status, setStatus] = useState<DbStatus | null>(null);
  // 失败态去抖:batch 已 settle 但零源加载(仍 warming)时,等 3s 才切失败态,
  // 避免冷启动线程尚未 enqueue 的启动瞬态(batch==null && warming)闪成失败。
  const [showFailure, setShowFailure] = useState(false);

  useEffect(() => {
    let alive = true;
    let timer: number | undefined;
    const poll = () => getDbStatus().then(s => {
      if (!alive) return;
      setStatus(s);
      // warming_up 进程内只会 true→false;首个 false 即停轮(稳态零轮询)。
      if (!s.warming_up && timer !== undefined) {
        clearInterval(timer);
        timer = undefined;
      }
    }).catch(() => {});
    poll();
    // 兜底 5s 轮询(SSE 断连时也能解锁)
    timer = setInterval(poll, 5000);
    return () => { alive = false; if (timer !== undefined) clearInterval(timer); };
  }, []);

  // batch done → 重拉 db-status(warming_up 可能翻 false)
  const prevBatchState = useRef<string | undefined>(undefined);
  useEffect(() => {
    const cur = batch?.state;
    const prev = prevBatchState.current;
    prevBatchState.current = cur;
    if (cur === "done" && (prev === "running" || prev === "paused")) {
      getDbStatus().then(setStatus).catch(() => {});
    }
  }, [batch?.state]);

  const warming = !!status?.warming_up;
  const batchRunning = batch != null && batch.state !== "done";

  // 去抖:进入「warming && batch 不在跑」后 3s 仍保持 → 失败态;离开该状态即重置。
  // setTimeout 在 vitest fake timers 下由 advanceTimersByTime 精确推进。
  useEffect(() => {
    if (!warming || batchRunning) {
      setShowFailure(false);
      return;
    }
    const id = setTimeout(() => setShowFailure(true), 3000);
    return () => clearTimeout(id);
  }, [warming, batchRunning]);

  if (!status || !status.warming_up) return null;

  const currentTask = tasks.find(tk => tk.state === "downloading");
  const retry = async () => { await enqueueBatch(); };

  return (
    <div data-warmup className="mb-4 rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-4">
      {showFailure ? (
        <div className="flex items-center justify-between">
          <span className="text-amber-400">{t("warmup.failed")}</span>
          <button onClick={retry}
            className="rounded-md bg-zinc-800 px-3 py-1.5 text-sm text-emerald-400 hover:bg-zinc-700">
            {t("warmup.retry")}
          </button>
        </div>
      ) : (
        <div>
          <div className="flex items-center gap-2">
            <span className="animate-spin inline-block h-4 w-4 border-2 border-emerald-400 border-t-transparent rounded-full" />
            <span className="text-zinc-200 font-medium">{t("warmup.title")}</span>
            {batch && (
              <span className="text-zinc-400 text-sm">
                {t("warmup.progress", { done: batch.done, total: batch.total })}
              </span>
            )}
          </div>
          {currentTask && (
            <div className="mt-2 text-sm text-zinc-400">
              {currentTask.total && currentTask.total > 0
                ? t("warmup.current", {
                    source: currentTask.source,
                    pct: `${Math.round(((currentTask.received ?? 0) * 100) / currentTask.total)}%`,
                  })
                : t("warmup.currentBytes", {
                    source: currentTask.source,
                    bytes: fmtBytes(currentTask.received ?? 0),
                  })}
            </div>
          )}
          <div className="mt-2 text-xs text-zinc-500">{t("warmup.hint")}</div>
        </div>
      )}
    </div>
  );
}
