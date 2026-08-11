import { describe, it, expect, vi } from "vitest";
import { screen, fireEvent } from "@testing-library/react";
import { useState } from "react";
import userEvent from "@testing-library/user-event";
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

  it("restores focus to the trigger element on close", async () => {
    const user = userEvent.setup();

    function Harness() {
      const [open, setOpen] = useState(false);
      return (
        <>
          <button onClick={() => setOpen(true)}>open modal</button>
          <Modal open={open} title="Test" onClose={() => setOpen(false)}>
            <p>body</p>
          </Modal>
        </>
      );
    }
    renderWithI18n(<Harness />);

    const trigger = screen.getByRole("button", { name: "open modal" });
    // focus the trigger, THEN open — so the Modal's effect captures it as triggerRef
    trigger.focus();
    expect(document.activeElement).toBe(trigger);

    await user.click(trigger); // opens modal; effect runs, captures trigger
    // focus has moved into the dialog (to the first focusable / panel)
    expect(document.activeElement).not.toBe(trigger);

    await user.keyboard("{Escape}"); // closes modal; cleanup runs, restores focus
    expect(document.activeElement).toBe(trigger);
  });

  it("wraps Tab focus within the dialog", async () => {
    const user = userEvent.setup();

    renderWithI18n(
      <Modal open={true} title="Done" onClose={() => {}}>
        <button type="button">First button</button>
        <button type="button">Last button</button>
      </Modal>,
    );

    const buttons = screen.getAllByRole("button");
    // DOM order: child buttons first, then close button
    // buttons[0] = first child button, buttons[1] = last child button, buttons[2] = close button
    const firstChildButton = buttons[0];
    const lastChildButton = buttons[1];
    const closeButton = buttons[2];

    // Modal's open-effect focuses the first focusable (first child button, not close button)
    expect(document.activeElement).toBe(firstChildButton);

    // Tab forward: first child button → last child button
    await user.tab();
    expect(document.activeElement).toBe(lastChildButton);

    // Tab forward: last child button → close button
    await user.tab();
    expect(document.activeElement).toBe(closeButton);

    // Tab forward: at last focusable (close button), trap wraps to first
    await user.tab();
    expect(document.activeElement).toBe(firstChildButton);

    // Tab backward (Shift+Tab): at first focusable, trap wraps to last
    await user.tab({ shift: true });
    expect(document.activeElement).toBe(closeButton);
  });
});
