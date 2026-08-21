import { useState } from "react";
import type { ClassificationDetail } from "../api";
import { useI18n } from "../i18n";

function fmtRel(r: number): string {
  return String(Math.round(r * 100) / 100);
}

function fmtDate(iso: string): string {
  return iso.slice(0, 10);
}

function extraHref(key: string, v: unknown): string | null {
  if (typeof v === "string" && /^https?:\/\//.test(v)) return v;
  if (key === "sbl_id" && typeof v === "string" && /^SBL\d+$/.test(v))
    return `https://check.spamhaus.org/sbl/query/${v}`;
  return null;
}

export function SourceDetailRow({ detail: d }: { detail: ClassificationDetail }) {
  const { t } = useI18n();
  const [showExtra, setShowExtra] = useState(false);
  const nativeChips: string[] = d.native_categories ?? [];
  const extraKeys = d.extra ? Object.keys(d.extra) : [];
  const hasExtra = extraKeys.length > 0;
  const hasTags = !!(d.tags && d.tags.length > 0);

  return (
    <div className="text-[10px] leading-relaxed">
      <div>
        <span className="text-zinc-600">{d.source}</span>
        <span className="text-zinc-700"> · rel {fmtRel(d.reliability)}</span>
        {nativeChips.map((c, i) => (
          <span key={`nc-${i}`} className="rounded bg-sky-800/40 px-1 py-px mr-0.5 ml-1 text-sky-300" title={t("sourceDetail.nativeTypeTitle")}>[{c}]</span>
        ))}
        {d.native_confidence != null && (
          <span className="text-zinc-500 ml-1">native {d.native_confidence}</span>
        )}
        {d.first_seen && (
          <span className="text-zinc-700 ml-1">first {fmtDate(d.first_seen)}</span>
        )}
        {d.last_seen && (
          <span className="text-zinc-700 ml-1">last {fmtDate(d.last_seen)}</span>
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
            {showExtra ? "▾" : "▸"} {t("sourceDetail.extraKeys", { n: extraKeys.length })}
          </button>
          {showExtra && (
            <div className="mt-0.5 text-zinc-500">
              {extraKeys.map((k) => {
                const href = extraHref(k, d.extra![k]);
                return (
                  <div key={k} className="break-all">
                    <span className="text-zinc-600">{k}: </span>
                    {href ? (
                      <a href={href} target="_blank" rel="noopener" className="text-sky-400 hover:underline">
                        {String(d.extra![k])}
                      </a>
                    ) : (
                      <span>{JSON.stringify(d.extra![k])}</span>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
