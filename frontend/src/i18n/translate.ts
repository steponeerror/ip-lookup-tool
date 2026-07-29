import en from "./locales/en.json";
import zhCN from "./locales/zh-CN.json";
import { toTraditional } from "./opencc";

export type Locale = "en" | "zh-CN" | "zh-TW";

type Vars = Record<string, string | number>;

const DICTS: Record<Locale, Record<string, string>> = {
  "en": en as Record<string, string>,
  "zh-CN": zhCN as Record<string, string>,
  "zh-TW": zhCN as Record<string, string>, // zh-TW derives from zh-CN via toTraditional()
};

function lookup(locale: Locale, key: string): string | undefined {
  const chain: Locale[] =
    locale === "zh-TW" ? ["zh-TW", "zh-CN", "en"]
    : locale === "zh-CN" ? ["zh-CN", "en"]
    : ["en"];
  for (const l of chain) {
    const v = DICTS[l][key];
    if (v !== undefined) return v;
  }
  return undefined;
}

export function translate(locale: Locale, key: string, vars?: Vars): string {
  let raw = lookup(locale, key);
  if (raw === undefined) {
    if (import.meta.env?.DEV) console.warn(`[i18n] missing key: ${key}`);
    return key;
  }
  if (locale === "zh-TW") raw = toTraditional(raw);
  if (vars) {
    for (const [k, v] of Object.entries(vars)) {
      raw = raw!.split(`{${k}}`).join(String(v));
    }
  }
  return raw!;
}
