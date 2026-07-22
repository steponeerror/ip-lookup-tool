import type { LookupResult, MergedField } from "../api";
import { confColor, confTextColor, ALGORITHM_ICONS } from "./threatDisplay";
import { ClassificationBlock } from "./ClassificationBlock";

function FieldDetail<T>({
  label,
  field,
  format,
}: {
  label: string;
  field: MergedField<T>;
  format: (v: T) => string;
}) {
  const entries = field.sources;
  if (entries.length === 0) return null;
  return (
    <div>
      <div className="flex items-center gap-2 mb-1">
        <span className="text-xs font-medium text-zinc-300">{label}</span>
        <span className="text-[10px] text-zinc-500">{format(field.value)}</span>
        <span className={`inline-block h-1.5 w-1.5 rounded-full ${confColor(field.confidence)}`} />
        <span className={`text-[10px] ${confTextColor(field.confidence)}`}>{field.confidence}</span>
        <span className="text-[10px] text-zinc-600">{ALGORITHM_ICONS[field.algorithm] ?? field.algorithm}</span>
      </div>
      {entries.length > 0 && (
        <div className="ml-3 flex flex-wrap gap-x-4 gap-y-0.5">
          {entries.map((s) => (
            <span key={s.source} className="text-[11px]">
              <span className="text-zinc-500">{s.source}</span>
              {s.authoritative && (
                <span className="text-amber-400 ml-0.5" title="authoritative">★</span>
              )}
              <span className="text-zinc-700 mx-1">:</span>
              <span className="text-zinc-400">{format(s.value)}</span>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

export function IpDetailPanel({ r }: { r: LookupResult }) {
  const classKeys = Object.keys(r.classifications);
  return (
    <div className="grid gap-2.5">
      <FieldDetail label="国家" field={r.country} format={String} />
      <FieldDetail label="ASN" field={r.asn} format={(v) => String(v)} />
      <FieldDetail label="机构 / ISP" field={r.as_name} format={String} />
      <div>
        <span className="text-xs font-medium text-zinc-300">威胁明细</span>
        {classKeys.length === 0 ? (
          <div className="ml-3 mt-1 text-[11px] text-zinc-600">未命中</div>
        ) : (
          <div className="ml-3 mt-1 space-y-2.5">
            {classKeys.map((type) => (
              <ClassificationBlock key={type} type={type} ca={r.classifications[type]} />
            ))}
          </div>
        )}
      </div>
      <FieldDetail label="网段" field={r.ip_range} format={String} />
    </div>
  );
}
