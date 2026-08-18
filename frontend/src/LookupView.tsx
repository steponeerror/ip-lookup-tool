import { useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { IpInput } from "./components/IpInput";
import { FileUpload } from "./components/FileUpload";
import { ResultTable } from "./components/ResultTable";
import { ExportCsv } from "./components/ExportCsv";
import { Modal } from "./components/Modal";
import { WarmupBanner } from "./components/WarmupBanner";
import { WarmingProvider, useWarming } from "./warming";
import { queryIpsStream, uploadFileStream } from "./api";
import type { LookupResult, Progress, StreamOutcome } from "./api";
import { useI18n } from "./i18n";

type InputTab = "text" | "file";

// api 层非 2xx 抛错统一带 e.status + e.reason(见 api.ts throwApiError);
// 503 且 reason==="warming" 才是 warming 门(no-sources 是另一种 503)。
const isWarming503 = (e: unknown) =>
  (e as any)?.status === 503 && (e as any)?.reason === "warming";

export default function LookupView() {
  return (
    <WarmingProvider>
      <LookupViewInner />
    </WarmingProvider>
  );
}

function LookupViewInner() {
  const { t } = useI18n();
  const [tab, setTab] = useState<InputTab>("text");
  const [results, setResults] = useState<LookupResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [enrichError, setEnrichError] = useState<string | null>(null);
  const [skipped, setSkipped] = useState<{ invalid: number; ipv6: number } | null>(null);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [csvModal, setCsvModal] = useState<{
    open: boolean;
    count: number;
    invalid: number;
    ipv6: number;
  } | null>(null);
  const reduce = useReducedMotion();
  const { warming, recheck } = useWarming();

  const applyOutcome = (r: StreamOutcome) => {
    if (r.invalidLines > 0 || r.ipv6Unsupported > 0) {
      setSkipped({ invalid: r.invalidLines, ipv6: r.ipv6Unsupported });
    }
    if (r.csvDownloaded) {
      setResults([]);
      setCsvModal({
        open: true,
        count: r.total,
        invalid: r.invalidLines,
        ipv6: r.ipv6Unsupported,
      });
      if (r.error != null) setError(r.error);
    } else {
      setResults(r.results);
      if (r.enrichError) setEnrichError(r.enrichError);
      if (r.error != null) setError(r.error);
    }
  };

  // 503 自纠:乐观提交漏过初始加载窗口撞上 warming 门时,recheck 确认 —
  // 仍在 warming 则横幅接管(recheck 同时重臂轮询,后端重启亦能恢复);
  // 门已开则原样重试一次(503 在依赖处抛出,服务端零副作用,重试安全)。
  // 第二次仍 503 不再重试(防乒乓)。no-sources 是配置态非瞬时门:本地化
  // 提示、不重试。
  const runLookup = async (fetcher: () => Promise<StreamOutcome>, failMsg: string) => {
    setLoading(true);
    setError(null);
    setEnrichError(null);
    setSkipped(null);
    setProgress(null);
    try {
      for (let attempt = 0; ; attempt++) {
        try {
          applyOutcome(await fetcher());
          break;
        } catch (e) {
          if (e instanceof Error && e.name === "AbortError") {
            setError(t("lookup.cancelled"));
            break;
          }
          if ((e as any)?.status === 503 && (e as any)?.reason === "no-sources") {
            setError(t("lookup.noSources"));
            break;
          }
          if (!isWarming503(e)) {
            setError(e instanceof Error ? e.message : failMsg);
            break;
          }
          if (await recheck()) {
            break;
          }
          if (attempt > 0) {
            setError(e instanceof Error ? e.message : failMsg);
            break;
          }
          // 503 与重拉之间门恰好开合 — 重试一次
        }
      }
    } finally {
      setLoading(false);
      setProgress(null);
    }
  };

  const handleQuery = (ips: string[]) =>
    runLookup(() => queryIpsStream(ips, setProgress), t("lookup.queryFailed"));

  const handleUpload = (file: File) =>
    runLookup(() => uploadFileStream(file, setProgress), t("lookup.uploadFailed"));

  return (
    <div className="space-y-6">
      {/* Input Section */}
      <section>
        <WarmupBanner />
        <div className="flex items-center gap-3">
          <div className="flex gap-1 rounded-lg bg-zinc-900 p-1">
            {(["text", "file"] as const).map((tabKey) => (
              <button
                key={tabKey}
                onClick={() => setTab(tabKey)}
                className={`rounded-md px-4 py-2 text-sm font-medium transition-colors ${
                  tab === tabKey
                    ? "bg-zinc-800 text-emerald-400"
                    : "text-zinc-500 hover:text-zinc-300"
                }`}
              >
                {tabKey === "text" ? t("lookup.tab.text") : t("lookup.tab.file")}
              </button>
            ))}
          </div>
        </div>

        <div className="mt-3">
          <AnimatePresence mode="wait">
            {tab === "text" ? (
              <motion.div
                key="text"
                initial={reduce ? false : { opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.15 }}
              >
                <IpInput onQuery={handleQuery} loading={loading} progress={progress} disabled={warming} />
              </motion.div>
            ) : (
              <motion.div
                key="file"
                initial={reduce ? false : { opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.15 }}
              >
                <FileUpload onUpload={handleUpload} loading={loading} progress={progress} disabled={warming} />
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </section>

      {/* Results Section */}
      <section>
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-sm font-medium text-zinc-400">
            {results.length > 0
              ? t("lookup.resultsCount", { n: results.length.toLocaleString() })
              : t("lookup.results")}
          </h2>
          <ExportCsv results={results} />
        </div>

        {loading && progress && (
          <div className="mb-3 space-y-1.5">
            <div className="flex items-center justify-between text-sm">
              <span className="flex items-center gap-2 text-emerald-400">
                <svg className="h-3.5 w-3.5 animate-spin" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                {progress.phase === "enrich"
                  ? t("lookup.enriching")
                  : t("lookup.lookingUp", { done: progress.done.toLocaleString(), total: progress.total.toLocaleString() })}
              </span>
              <span className="text-zinc-500 tabular-nums">
                {progress.total > 0 ? Math.round((progress.done / progress.total) * 100) : 0}%
              </span>
            </div>
            <div className="h-1 overflow-hidden rounded-full bg-zinc-800">
              <div
                className="h-full rounded-full bg-emerald-500 transition-all duration-300 ease-out"
                style={{ width: `${progress.total > 0 ? (progress.done / progress.total) * 100 : 0}%` }}
              />
            </div>
          </div>
        )}
        {loading && !progress && (
          <div className="mb-3 flex items-center gap-2 rounded-lg border border-emerald-500/20 bg-emerald-500/5 px-4 py-2 text-sm text-emerald-400">
            <svg className="h-3.5 w-3.5 animate-spin" viewBox="0 0 24 24" fill="none">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            {t("lookup.connecting")}
          </div>
        )}

        {error && (
          <div className="mb-3 rounded-lg border border-red-400/30 bg-red-400/10 px-4 py-2 text-sm text-red-400">
            {error}
          </div>
        )}

        {enrichError && (
          <div className="mb-3 rounded-lg border border-amber-400/30 bg-amber-400/10 px-4 py-2 text-sm text-amber-400">
            {enrichError}
          </div>
        )}

        {skipped && (skipped.invalid > 0 || skipped.ipv6 > 0) && (
          <div className="mb-3 rounded-lg border border-amber-400/30 bg-amber-400/10 px-4 py-2 text-sm text-amber-400">
            {skipped.invalid > 0 && <div>{t("csvExport.invalidLines", { n: skipped.invalid })}</div>}
            {skipped.ipv6 > 0 && <div>{t("csvExport.ipv6Unsupported", { n: skipped.ipv6 })}</div>}
          </div>
        )}

        {loading && results.length === 0 ? (
          <div className="flex h-48 flex-col items-center justify-center gap-3 rounded-lg border border-zinc-800">
            <div className="h-5 w-5 animate-spin rounded-full border-2 border-emerald-500 border-t-transparent" />
            <span className="text-sm text-zinc-500">{t("lookup.waiting")}</span>
          </div>
        ) : results.length > 0 ? (
          <ResultTable results={results} />
        ) : (
          <div className="flex h-48 items-center justify-center rounded-lg border border-zinc-800 text-sm text-zinc-600">
            {t("lookup.noResults")}
          </div>
        )}
      </section>

      <Modal
        open={csvModal?.open ?? false}
        title={t("csvExport.modalTitle")}
        onClose={() => setCsvModal(null)}
      >
        <p>{t("csvExport.modalBody", { n: csvModal?.count ?? 0 })}</p>
        {csvModal && csvModal.invalid > 0 && (
          <p className="mt-2 text-xs text-amber-400">
            {t("csvExport.invalidLines", { n: csvModal.invalid })}
          </p>
        )}
        {csvModal && csvModal.ipv6 > 0 && (
          <p className="mt-1 text-xs text-amber-400">
            {t("csvExport.ipv6Unsupported", { n: csvModal.ipv6 })}
          </p>
        )}
      </Modal>
    </div>
  );
}
