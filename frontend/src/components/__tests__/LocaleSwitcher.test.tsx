import { describe, it, expect } from "vitest";
import { screen, fireEvent } from "@testing-library/react";
import { renderWithI18n } from "../../test/i18nTestUtils";
import { LocaleSwitcher } from "../LocaleSwitcher";

describe("LocaleSwitcher", () => {
  it("renders the three locale options", () => {
    renderWithI18n(<LocaleSwitcher />);
    expect(screen.getByRole("button", { name: "EN" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "简体" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "繁體" })).toBeInTheDocument();
  });

  it("marks the active locale and moves it on click", () => {
    renderWithI18n(<LocaleSwitcher />, { locale: "en" });
    expect(screen.getByRole("button", { name: "EN" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "简体" })).toHaveAttribute("aria-pressed", "false");

    fireEvent.click(screen.getByRole("button", { name: "简体" }));
    expect(screen.getByRole("button", { name: "简体" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "EN" })).toHaveAttribute("aria-pressed", "false");
  });
});
