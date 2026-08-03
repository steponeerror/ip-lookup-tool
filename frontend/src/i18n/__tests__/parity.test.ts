import { describe, it, expect } from "vitest";
import en from "../locales/en.json";
import zhCN from "../locales/zh-CN.json";

describe("locale parity", () => {
  it("en and zh-CN have identical key sets", () => {
    expect(Object.keys(zhCN).sort()).toEqual(Object.keys(en).sort());
  });
  it("no empty string values in either locale", () => {
    for (const [k, v] of Object.entries(en)) expect(v, `en.${k}`).not.toBe("");
    for (const [k, v] of Object.entries(zhCN)) expect(v, `zh-CN.${k}`).not.toBe("");
  });
});
