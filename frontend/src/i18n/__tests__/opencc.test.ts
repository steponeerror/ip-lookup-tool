import { describe, it, expect } from "vitest";
import { ensureOpenCC, toTraditional } from "../opencc";

describe("opencc s2t", () => {
  it("converts simplified to traditional after ensureOpenCC resolves", async () => {
    await ensureOpenCC();
    expect(toTraditional("国家")).toBe("國家");
    expect(toTraditional("威胁")).toBe("威脅");
    expect(toTraditional("恶意软件")).toBe("惡意軟件");
  });
  it("memoizes: repeated calls return the same converted string", async () => {
    await ensureOpenCC();
    expect(toTraditional("代理")).toBe(toTraditional("代理"));
  });
});
