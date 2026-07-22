import type { ClassificationAssessment } from "../api";
import {
  classLabel, VERDICT_LABEL, VERDICT_STYLE, confTextColor, ALGORITHM_ICONS,
} from "./threatDisplay";
import { SourceDetailRow } from "./SourceDetailRow";

export function ClassificationBlock({ type, ca }: { type: string; ca: ClassificationAssessment }) {
  return (
    <div>
      <div className="flex items-center gap-1.5 flex-wrap">
        <span className={`inline-block h-1.5 w-1.5 rounded-full ${ca.detected ? "bg-orange-400" : "bg-zinc-600"}`} />
        <span className="text-[11px] text-zinc-400 font-medium">{classLabel(type)}</span>
        <span className={`rounded px-1 py-px text-[10px] font-medium ${VERDICT_STYLE[ca.verdict] ?? VERDICT_STYLE.informational}`}>
          {VERDICT_LABEL[ca.verdict] ?? ca.verdict}
        </span>
        <span className={`text-[10px] ${confTextColor(ca.confidence)}`}>{ca.confidence}</span>
        <span className="text-[10px] text-zinc-600">{ALGORITHM_ICONS[ca.algorithm] ?? ca.algorithm}</span>
        {ca.corroborated && (
          <span className="text-[10px] text-amber-400" title="2+ 独立源印证">已印证</span>
        )}
        {ca.verdict_conflict && (
          <span className="text-[10px] text-red-400" title="源之间判定冲突">判定冲突</span>
        )}
        {ca.reporter_total > 0 && (
          <span className="text-[10px] text-zinc-500">·{ca.reporter_total}上报</span>
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
