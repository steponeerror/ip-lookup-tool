import { useState } from "react";
import type { ClassificationDetail } from "../api";

function fmtRel(r: number): string {
  return String(Math.round(r * 100) / 100);
}

function fmtDate(iso: string): string {
  return iso.slice(0, 10);
}

export function SourceDetailRow({ detail: d }: { detail: ClassificationDetail }) {
  const [showExtra, setShowExtra] = useState(false);
  const nativeType = d.extra?.native_type;
  const extraKeys = d.extra ? Object.keys(d.extra) : [];
  const hasExtra = extraKeys.length > 0;
  const hasTags = !!(d.tags && d.tags.length > 0);

  return (
    <div className="text-[10px] leading-relaxed">
      <div>
        <span className="text-zinc-600">{d.source}</span>
        <span className="text-zinc-700"> · rel {fmtRel(d.reliability)}</span>
        {nativeType != null && (
          <span className="text-zinc-500 ml-1" title="源原生类型">[{String(nativeType)}]</span>
        )}
        {d.native_confidence != null && (
          <span className="text-zinc-500 ml-1">native {d.native_confidence}</span>
        )}
        {d.first_seen && (
          <span className="text-zinc-700 ml-1">first {fmtDate(d.first_seen)}</span>
        )}
      </div>

      {(d.malware_name || d.comment) && (
        <div className="ml-3">
          {d.malware_name && (
            <span className="text-purple-400 font-mono">malware: {d.malware_name} </span>
          )}
          {d.comment && (
            <span className="text-zinc-500" title={d.comment}>
              comment: "{d.comment.length > 40 ? d.comment.slice(0, 40) + "…" : d.comment}"
            </span>
          )}
        </div>
      )}

      {(hasTags || d.reporter_count != null) && (
        <div className="ml-3">
          {hasTags && (
            <span className="mr-2">
              {d.tags!.map((t) => (
                <span key={t} className="rounded bg-zinc-700/40 px-1 py-px mr-0.5 text-zinc-400">[{t}]</span>
              ))}
            </span>
          )}
          {d.reporter_count != null && (
            <span className="text-zinc-500">reporters: {d.reporter_count}</span>
          )}
        </div>
      )}

      {hasExtra && (
        <div className="ml-3">
          <button
            type="button"
            onClick={() => setShowExtra((v) => !v)}
            className="text-zinc-600 hover:text-zinc-400"
          >
            {showExtra ? "▾" : "▸"} extra {extraKeys.length} keys
          </button>
          {showExtra && (
            <pre className="mt-0.5 text-zinc-500 whitespace-pre-wrap break-all">
              {JSON.stringify(d.extra, null, 2)}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}
