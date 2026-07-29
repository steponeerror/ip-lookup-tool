import type { ClassificationAssessment } from "../api";
import {
  classLabel, verdictLabelKey, VERDICT_STYLE, confTextColor, ALGORITHM_ICONS,
} from "./threatDisplay";
import { useI18n } from "../i18n";
import { SourceDetailRow } from "./SourceDetailRow";

export function ClassificationBlock({ type, ca }: { type: string; ca: ClassificationAssessment }) {
  const { t } = useI18n();
  return (
    <div>
      <div className="flex items-center gap-1.5 flex-wrap">
        <span className={`inline-block h-1.5 w-1.5 rounded-full ${ca.detected ? "bg-orange-400" : "bg-zinc-600"}`} />
        <span className="text-[11px] text-zinc-400 font-medium">{classLabel(type, t)}</span>
        <span className={`rounded px-1 py-px text-[10px] font-medium ${VERDICT_STYLE[ca.verdict] ?? VERDICT_STYLE.informational}`}>
          {t(verdictLabelKey(ca.verdict))}
        </span>
        <span className={`text-[10px] ${confTextColor(ca.confidence)}`}>{ca.confidence}</span>
        <span className="text-[10px] text-zinc-600">{ALGORITHM_ICONS[ca.algorithm] ?? ca.algorithm}</span>
        {ca.corroborated && (
          <span className="text-[10px] text-amber-400" title={t("common.corroboratedTitle")}>{t("common.corroborated")}</span>
        )}
        {ca.verdict_conflict && (
          <span className="text-[10px] text-red-400" title={t("common.conflictTitle")}>{t("common.conflict")}</span>
        )}
        {ca.reporter_total > 0 && (
          <span className="text-[10px] text-zinc-500">·{t("classification.reporters", { n: ca.reporter_total })}</span>
        )}
      </div>

      {ca.malware_names.length > 0 && (
        <div className="ml-3 mt-1 flex flex-wrap gap-1">
          {ca.malware_names.map((m) => (
            <span key={m} className="rounded bg-purple-500/10 px-1 py-px text-[10px] text-purple-400 font-mono">{m}</span>
          ))}
        </div>
      )}

      {ca.details.length > 0 && (
        <div className="ml-3 mt-1 space-y-1">
          {ca.details.map((d, idx) => (
            <SourceDetailRow key={`${d.source}#${idx}`} detail={d} />
          ))}
        </div>
      )}
    </div>
  );
}
