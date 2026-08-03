import { motion } from "motion/react";
import { useI18n, type Locale } from "../i18n";

const OPTIONS: { value: Locale; label: string }[] = [
  { value: "en", label: "EN" },
  { value: "zh-CN", label: "简体" },
  { value: "zh-TW", label: "繁體" },
];

export function LocaleSwitcher() {
  const { locale, setLocale } = useI18n();
  return (
    <div
      role="group"
      aria-label="language"
      className="relative flex gap-1 rounded-lg bg-zinc-900 p-1"
    >
      {OPTIONS.map((o) => {
        const active = locale === o.value;
        return (
          <button
            key={o.value}
            type="button"
            aria-pressed={active}
            onClick={() => setLocale(o.value)}
            className={`relative rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
              active ? "text-emerald-400" : "text-zinc-500 hover:text-zinc-300"
            }`}
          >
            {active && (
              <motion.span
                layoutId="locale-pill"
                className="absolute inset-0 rounded-md bg-zinc-800 ring-1 ring-emerald-500/30 shadow-[0_0_10px_-2px_rgba(16,185,129,0.45)]"
                transition={{ type: "spring", stiffness: 400, damping: 32 }}
              />
            )}
            <span className="relative z-10">{o.label}</span>
          </button>
        );
      })}
    </div>
  );
}
