import type { Locale } from "./translate";

const STORAGE_KEY = "iplookup.locale";

export function readPresetLocale(): Locale | undefined {
  const v = (globalThis as { __LOCALE__?: unknown }).__LOCALE__;
  if (v === "en" || v === "zh-CN" || v === "zh-TW") return v as Locale;
  return undefined;
}

export function detectLocale(): Locale {
  const preset = readPresetLocale();
  if (preset) return preset;
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === "en" || saved === "zh-CN" || saved === "zh-TW") return saved;
  } catch { /* localStorage may be unavailable */ }
  const nav = (typeof navigator !== "undefined" ? navigator.language : "en").toLowerCase();
  if (nav.startsWith("zh-tw") || nav.startsWith("zh-hk") || nav.startsWith("zh-mo") || nav.startsWith("zh-hant"))
    return "zh-TW";
  if (nav.startsWith("zh")) return "zh-CN";
  return "en";
}

export function persistLocale(l: Locale): void {
  try { localStorage.setItem(STORAGE_KEY, l); } catch { /* ignore */ }
}
