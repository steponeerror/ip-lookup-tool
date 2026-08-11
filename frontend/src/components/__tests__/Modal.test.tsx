import { describe, it, expect, vi } from "vitest";
import { screen, fireEvent } from "@testing-library/react";
import { renderWithI18n } from "../../test/i18nTestUtils";
import { Modal } from "../Modal";

describe("Modal", () => {
  it("renders title and children when open", () => {
    renderWithI18n(
      <Modal open={true} title="Done" onClose={() => {}}>
        <p>body text</p>
      </Modal>,
    );
    expect(screen.getByRole("dialog")).toHaveAttribute("aria-modal", "true");
    expect(screen.getByText("Done")).toBeInTheDocument();
    expect(screen.getByText("body text")).toBeInTheDocument();
  });

  it("renders nothing when closed", () => {
    renderWithI18n(
      <Modal open={false} title="Done" onClose={() => {}}>
        <p>body</p>
      </Modal>,
    );
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("calls onClose when Esc is pressed", () => {
    const onClose = vi.fn();
    renderWithI18n(
      <Modal open={true} title="Done" onClose={onClose}>
        <p>body</p>
      </Modal>,
    );
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("calls onClose when the backdrop is clicked", () => {
    const onClose = vi.fn();
    renderWithI18n(
      <Modal open={true} title="Done" onClose={onClose}>
        <p>body</p>
      </Modal>,
    );
    // backdrop is the outer element with role=None; click the dialog container's parent
    fireEvent.click(screen.getByRole("dialog").parentElement!);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("does NOT call onClose when the panel is clicked", () => {
    const onClose = vi.fn();
    renderWithI18n(
      <Modal open={true} title="Done" onClose={onClose}>
        <p>body</p>
      </Modal>,
    );
    fireEvent.click(screen.getByRole("dialog"));
    expect(onClose).not.toHaveBeenCalled();
  });

  it("calls onClose when the close button is clicked", () => {
    const onClose = vi.fn();
    renderWithI18n(
      <Modal open={true} title="Done" onClose={onClose}>
        <p>body</p>
      </Modal>,
    );
    fireEvent.click(screen.getByRole("button", { name: "OK" }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
