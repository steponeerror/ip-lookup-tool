import { describe, it, expect, vi } from "vitest";
import { translate } from "../translate";

describe("translate", () => {
  it("returns the en string for an en locale key", () => {
    expect(translate("en", "verdict.malicious")).toBe("Malicious");
  });
  it("returns the zh-CN string for a zh-CN locale key", () => {
    expect(translate("zh-CN", "verdict.malicious")).toBe("恶意");
  });
  it("prefers zh-CN over en when the key exists in both", () => {
    expect(translate("zh-CN", "verdict.suspicious")).toBe("可疑");
    expect(translate("en", "verdict.suspicious")).toBe("Suspicious");
  });
  it("interpolates {var} placeholders", () => {
    expect(translate("en", "lookup.lookingUp", { done: 3, total: 10 })).toBe("Looking up 3 / 10 IPs");
    expect(translate("zh-CN", "lookup.lookingUp", { done: 3, total: 10 })).toBe("查询中 3 / 10");
  });
  it("returns the key literal (and warns in dev) when key missing in all locales", () => {
    const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
    expect(translate("en", "no.such.key")).toBe("no.such.key");
    expect(spy).toHaveBeenCalled();
    spy.mockRestore();
  });
});
