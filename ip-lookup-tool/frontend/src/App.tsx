import { useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { IpInput } from "./components/IpInput";
import { FileUpload } from "./components/FileUpload";
import { ResultTable } from "./components/ResultTable";
import { ExportCsv } from "./components/ExportCsv";
import { DbStatusBar } from "./components/DbStatusBar";
import { queryIps, uploadFile } from "./api";
import type { LookupResult } from "./api";

type InputTab = "text" | "file";

export default function App() {
  const [tab, setTab] = useState<InputTab>("text");
  const [results, setResults] = useState<LookupResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const reduce = useReducedMotion();

  const handleQuery = async (ips: string[]) => {
    setLoading(true);
    setError(null);
    try {
      const r = await queryIps(ips);
      setResults(r);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Query failed");
    } finally {
      setLoading(false);
    }
  };

  const handleUpload = async (file: File) => {
    setLoading(true);
    setError(null);
    try {
      const r = await uploadFile(file);
      setResults(r);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Upload failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="dot-grid min-h-screen pb-14">
      <div className="mx-auto max-w-7xl px-4 py-8 lg:px-8">
        <header className="mb-8">
          <h1 className="text-2xl font-bold tracking-tight text-zinc-100">
            IP Lookup Tool
          </h1>
          <p className="mt-1 text-sm text-zinc-500">
            Batch IP to ASN lookup for threat analysis
          </p>
        </header>

        <div className="grid grid-cols-1 gap-8 lg:grid-cols-2">
          {/* Input Section */}
          <section>
            <div className="mb-4 flex gap-1 rounded-lg bg-zinc-900 p-1">
              {(["text", "file"] as const).map((t) => (
                <button
                  key={t}
                  onClick={() => setTab(t)}
                  className={`flex-1 rounded-md px-4 py-2 text-sm font-medium transition-colors ${
                    tab === t
                      ? "bg-zinc-800 text-emerald-400"
                      : "text-zinc-500 hover:text-zinc-300"
                  }`}
                >
                  {t === "text" ? "Text Input" : "File Upload"}
                </button>
              ))}
            </div>

            <AnimatePresence mode="wait">
              {tab === "text" ? (
                <motion.div
                  key="text"
                  initial={reduce ? false : { opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.15 }}
                >
                  <IpInput onQuery={handleQuery} loading={loading} />
                </motion.div>
              ) : (
                <motion.div
                  key="file"
                  initial={reduce ? false : { opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.15 }}
                >
                  <FileUpload onUpload={handleUpload} loading={loading} />
                </motion.div>
              )}
            </AnimatePresence>
          </section>

          {/* Results Section */}
          <section>
            <div className="mb-3 flex items-center justify-between">
              <h2 className="text-sm font-medium text-zinc-400">
                {results.length > 0
                  ? `Results (${results.length})`
                  : "Results"}
              </h2>
              <ExportCsv results={results} />
            </div>

            {error && (
              <div className="mb-3 rounded-lg border border-red-400/30 bg-red-400/10 px-4 py-2 text-sm text-red-400">
                {error}
              </div>
            )}

            {results.length > 0 ? (
              <ResultTable results={results} />
            ) : (
              <div className="flex h-48 items-center justify-center rounded-lg border border-zinc-800 text-sm text-zinc-600">
                No results yet
              </div>
            )}
          </section>
        </div>
      </div>

      <DbStatusBar />
    </div>
  );
}
