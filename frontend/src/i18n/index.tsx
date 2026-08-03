import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { translate, type Locale } from "./translate";
import { detectLocale, persistLocale } from "./detect";
import { ensureOpenCC } from "./opencc";

type Vars = Record<string, string | number>;
type TFn = (key: string, vars?: Vars) => string;

interface I18nContextValue {
  locale: Locale;
  setLocale: (l: Locale) => void;
  t: TFn;
}

const I18nContext = createContext<I18nContextValue | null>(null);

export function I18nProvider({ children, defaultLocale }: { children: ReactNode; defaultLocale?: Locale }) {
  const [locale, setLocaleState] = useState<Locale>(() => defaultLocale ?? detectLocale());
  const [openccReady, setOpenccReady] = useState(false);

  useEffect(() => {
    if (locale !== "zh-TW") return;
    let cancelled = false;
    ensureOpenCC().then(() => { if (!cancelled) setOpenccReady(true); });
    return () => { cancelled = true; };
  }, [locale]);

  const setLocale = useCallback((l: Locale) => {
    setLocaleState(l);
    persistLocale(l);
    document.documentElement.lang = l;
  }, []);

  const t = useCallback(
    (key: string, vars?: Vars) => translate(locale, key, vars),
    // openccReady is read indirectly via translate()/toTraditional when locale === "zh-TW";
    // including it forces consumers to re-render once the converter is loaded.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [locale, openccReady],
  );

  return (
    <I18nContext.Provider value={{ locale, setLocale, t }}>
      {children}
    </I18nContext.Provider>
  );
}

export function useI18n(): I18nContextValue {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error("useI18n must be used within an I18nProvider");
  return ctx;
}

export type { Locale };
