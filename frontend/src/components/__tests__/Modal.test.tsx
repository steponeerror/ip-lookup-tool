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

  it("restores focus to trigger on close", () => {
    // Create a trigger button that opens the modal
    const onClose = vi.fn();
    const { container } = renderWithI18n(
      <div>
        <button type="button" id="trigger">
          Trigger
        </button>
        <Modal open={true} title="Done" onClose={onClose}>
          <p>body</p>
        </Modal>
      </div>,
    );

    // Simulate trigger having focus before modal opens
    const trigger = container.querySelector("#trigger") as HTMLElement;
    trigger.focus();
    expect(document.activeElement).toBe(trigger);

    // Close the modal
    fireEvent.click(screen.getByRole("button", { name: "OK" }));

    // Focus should be restored to the trigger
    expect(document.activeElement).toBe(trigger);
  });

  it("wraps Tab focus within the dialog", () => {
    renderWithI18n(
      <Modal open={true} title="Done" onClose={() => {}}>
        <button type="button">First button</button>
        <button type="button">Last button</button>
      </Modal>,
    );

    const buttons = screen.getAllByRole("button");
    // buttons[0] and buttons[1] are the children buttons, buttons[2] is the close button
    const firstChildButton = buttons[0];
    const lastChildButton = buttons[1];
    const closeButton = buttons[2];

    // Focus the close button (last focusable)
    closeButton.focus();
    expect(document.activeElement).toBe(closeButton);

    // Press Tab (forward) - should wrap to first
    fireEvent.keyDown(document, { key: "Tab" });
    expect(document.activeElement).toBe(firstChildButton);

    // Press Tab again to get to the last focusable
    fireEvent.keyDown(document, { key: "Tab" });
    expect(document.activeElement).toBe(lastChildButton);

    // Press Tab again to get to the close button
    fireEvent.keyDown(document, { key: "Tab" });
    expect(document.activeElement).toBe(closeButton);

    // Press Shift+Tab (backward) from close button - should wrap to last child
    fireEvent.keyDown(document, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(lastChildButton);
  });
});
