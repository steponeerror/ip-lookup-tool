import type { ReactElement } from "react";
import { render, type RenderOptions } from "@testing-library/react";
import { I18nProvider, type Locale } from "../i18n";

export function renderWithI18n(
  ui: ReactElement,
  { locale = "en" as Locale, ...rest }: RenderOptions & { locale?: Locale } = {},
) {
  return render(ui, {
    wrapper: ({ children }) => <I18nProvider defaultLocale={locale}>{children}</I18nProvider>,
    ...rest,
  });
}
