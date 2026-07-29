import { useI18n, type Locale } from "../i18n";

const OPTIONS: { value: Locale; label: string }[] = [
  { value: "en", label: "EN" },
  { value: "zh-CN", label: "简体" },
  { value: "zh-TW", label: "繁體" },
];

export function LocaleSwitcher() {
  const { locale, setLocale } = useI18n();
  return (
    <div role="group" aria-label="language" className="flex gap-1 rounded-lg bg-zinc-900 p-1">
      {OPTIONS.map((o) => {
        const active = locale === o.value;
        return (
          <button
            key={o.value}
            type="button"
            aria-pressed={active}
            onClick={() => setLocale(o.value)}
            className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
              active ? "bg-zinc-800 text-emerald-400" : "text-zinc-500 hover:text-zinc-300"
            }`}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}
