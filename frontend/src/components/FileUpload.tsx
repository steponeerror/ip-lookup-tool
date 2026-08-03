import { useCallback, useState } from "react";
import { useI18n } from "../i18n";

interface FileUploadProps {
  onUpload: (file: File) => void;
  loading: boolean;
  progress?: { done: number; total: number; phase: string } | null;
}

export function FileUpload({ onUpload, loading, progress }: FileUploadProps) {
  const { t } = useI18n();
  const [dragOver, setDragOver] = useState(false);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      const file = e.dataTransfer.files[0];
      if (!file) return;
      const validExtensions = [".txt", ".csv"];
      const ext = file.name.substring(file.name.lastIndexOf(".")).toLowerCase();
      if (!validExtensions.includes(ext)) {
        alert(t("fileUpload.invalidType"));
        return;
      }
      if (file.size > 50 * 1024 * 1024) {
        alert(t("fileUpload.tooLarge"));
        return;
      }
      onUpload(file);
    },
    [onUpload]
  );

  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) onUpload(file);
    },
    [onUpload]
  );

  return (
    <div
      onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
      onDragLeave={() => setDragOver(false)}
      onDrop={handleDrop}
      className={`relative flex flex-col items-center justify-center gap-3 rounded-lg border-2 border-dashed p-10 transition-colors ${
        dragOver
          ? "border-emerald-500 bg-emerald-500/5"
          : loading
          ? "border-zinc-700 bg-zinc-900"
          : "border-zinc-800 bg-zinc-900"
      }`}
    >
      {loading && (
        <div className="absolute inset-x-0 top-0 h-0.5 overflow-hidden rounded-t-lg">
          <div className="h-full w-1/3 animate-[shimmer_1.5s_ease-in-out_infinite] rounded-full bg-emerald-500" />
        </div>
      )}

      {loading ? (
        <>
          <div className="flex items-center gap-2 text-sm text-zinc-300">
            <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            {progress
              ? progress.phase === "enrich"
                ? t("fileUpload.enriching", { done: progress.done.toLocaleString(), total: progress.total.toLocaleString() })
                : t("fileUpload.lookingUp", { done: progress.done.toLocaleString(), total: progress.total.toLocaleString() })
              : t("fileUpload.uploading")}
          </div>
          {progress ? (
            <div className="w-56 h-1 overflow-hidden rounded-full bg-zinc-800">
              <div
                className="h-full rounded-full bg-emerald-500 transition-all duration-300 ease-out"
                style={{ width: `${progress.total > 0 ? (progress.done / progress.total) * 100 : 0}%` }}
              />
            </div>
          ) : (
            <p className="text-xs text-zinc-500">{t("fileUpload.waiting")}</p>
          )}
        </>
      ) : (
        <>
          <p className="text-sm text-zinc-400">{t("fileUpload.dropHint")}</p>
          <label className="cursor-pointer rounded-lg bg-emerald-500 px-5 py-2 text-sm font-semibold text-zinc-950 transition-transform hover:scale-[1.02] active:scale-[0.98]">
            {t("fileUpload.choose")}
            <input
              type="file"
              accept=".txt,.csv"
              onChange={handleChange}
              className="hidden"
            />
          </label>
        </>
      )}
    </div>
  );
}
