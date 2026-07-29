import { useMemo } from "react";
import type { LookupResult } from "../api";
import { buildCsv } from "./csvExport";
import { useI18n } from "../i18n";

interface ExportCsvProps {
  results: LookupResult[];
}

export function ExportCsv({ results }: ExportCsvProps) {
  const { t } = useI18n();
  const disabled = results.length === 0;
  const csv = useMemo(() => (disabled ? "" : buildCsv(results)), [results, disabled]);

  const handleExport = () => {
    if (!csv) return;
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ip-lookup-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <button
      onClick={handleExport}
      disabled={disabled}
      className="rounded-lg bg-emerald-500 px-5 py-2 text-sm font-semibold text-zinc-950 transition-transform hover:scale-[1.02] active:scale-[0.98] disabled:opacity-40 disabled:cursor-not-allowed"
    >
      {t("exportCsv.button", { n: results.length.toLocaleString() })}
    </button>
  );
}
