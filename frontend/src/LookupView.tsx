import { useEffect, useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { IpInput } from "./components/IpInput";
import { FileUpload } from "./components/FileUpload";
import { ResultTable } from "./components/ResultTable";
import { ExportCsv } from "./components/ExportCsv";
import { Modal } from "./components/Modal";
import { WarmupBanner } from "./components/WarmupBanner";
import { getDbStatus, queryIpsStream, uploadFileStream } from "./api";
import type { LookupResult, Progress } from "./api";
import { useI18n } from "./i18n";

type InputTab = "text" | "file";

// api 层对非 200 抛 plain Error(detail)(无 status 字段);503 的 detail 恒为
// "database is warming up",按 message 识别即可。status 检查留作前向兼容。
const isWarming503 = (e: unknown) =>
  (e as any)?.status === 503 || /warming up/i.test((e as any)?.message ?? "");

export default function LookupView() {
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
  const [warming, setWarming] = useState(false);

  // 查询控件置灰联动:与 WarmupBanner 的轮询解耦(各持一份,避免跨组件状态提升)
  useEffect(() => {
    let alive = true;
    const poll = () => getDbStatus().then(s => { if (alive) setWarming(s.warming_up); })
                                .catch(() => {});
    poll();
    // 兜底 5s 轮询(与 WarmupBanner 一致,失败/断连时也能解锁)
    const id = setInterval(poll, 5000);
    return () => { alive = false; clearInterval(id); };
  }, []);

  const handleQuery = async (ips: string[]) => {
    setLoading(true);
    setError(null);
    setEnrichError(null);
    setSkipped(null);
    setProgress(null);
    try {
      const r = await queryIpsStream(ips, setProgress);
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
      } else {
        setResults(r.results);
        if (r.enrichError) setEnrichError(r.enrichError);
      }
    } catch (e) {
      if (e instanceof Error && e.name === "AbortError") {
        setError(t("lookup.cancelled"));
      } else if (isWarming503(e)) {
        // 503 自纠:查询漏过初始加载窗口撞上后端 warming 门 — 重拉 db-status
        // 置 warming;横幅接管,抑制通用错误显示。
        const s = await getDbStatus().catch(() => null);
        setWarming(!!s?.warming_up);
      } else {
        setError(e instanceof Error ? e.message : t("lookup.queryFailed"));
      }
    } finally {
      setLoading(false);
      setProgress(null);
    }
  };

  const handleUpload = async (file: File) => {
    setLoading(true);
    setError(null);
    setEnrichError(null);
    setSkipped(null);
    setProgress(null);
    try {
      const r = await uploadFileStream(file, setProgress);
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
      } else {
        setResults(r.results);
        if (r.enrichError) setEnrichError(r.enrichError);
      }
    } catch (e) {
      if (e instanceof Error && e.name === "AbortError") {
        setError(t("lookup.cancelled"));
      } else if (isWarming503(e)) {
        const s = await getDbStatus().catch(() => null);
        setWarming(!!s?.warming_up);
      } else {
        setError(e instanceof Error ? e.message : t("lookup.uploadFailed"));
      }
    } finally {
      setLoading(false);
      setProgress(null);
    }
  };

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
