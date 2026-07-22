import { describe, it, expect } from "vitest";

describe("sanity", () => {
  it("vitest + jsdom works", () => {
    const el = document.createElement("div");
    el.textContent = "ok";
    document.body.appendChild(el);
    expect(el).toBeInTheDocument();
    expect(el.textContent).toBe("ok");
  });
});
