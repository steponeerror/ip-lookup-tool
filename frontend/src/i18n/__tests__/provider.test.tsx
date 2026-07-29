import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { useI18n } from "../index";
import { renderWithI18n } from "../../test/i18nTestUtils";

function Consumer() {
  const { t, locale } = useI18n();
  return <p data-testid="x">{locale}:{t("verdict.malicious")}</p>;
}

describe("I18nProvider", () => {
  it("provides t() bound to the default locale", () => {
    renderWithI18n(<Consumer />, { locale: "en" });
    expect(screen.getByTestId("x").textContent).toBe("en:Malicious");
  });
  it("respects zh-CN default", () => {
    renderWithI18n(<Consumer />, { locale: "zh-CN" });
    expect(screen.getByTestId("x").textContent).toBe("zh-CN:恶意");
  });
  it("throws when useI18n is used outside a provider", () => {
    // React logs the error to console.error as well; silence it for this case.
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(() => render(<Consumer />)).toThrow(/useI18n must be used within an I18nProvider/);
    spy.mockRestore();
  });
});
