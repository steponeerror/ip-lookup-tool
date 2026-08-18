import { describe, it, expect, vi, afterEach } from "vitest";
import { act } from "@testing-library/react";
import { WarmingProvider, useWarming } from "../warming";
import { getDbStatus } from "../api";
import { renderWithI18n } from "../test/i18nTestUtils";

afterEach(() => { vi.useRealTimers(); });

vi.mock("../api", () => ({
  getDbStatus: vi.fn(),
}));

describe("WarmingProvider", () => {
  it("stops polling after the first warming_up=false (steady state is silent)", async () => {
    vi.useFakeTimers();
    (getDbStatus as any).mockClear();
    let warming = true;
    (getDbStatus as any).mockImplementation(() => Promise.resolve({ warming_up: warming }));
    renderWithI18n(<WarmingProvider><span>probe</span></WarmingProvider>);
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });   // 初始 poll
    expect(getDbStatus).toHaveBeenCalledTimes(1);
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    expect(getDbStatus).toHaveBeenCalledTimes(3);   // 初始 + 2 个 tick
    warming = false;
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });  // 翻 false → 停轮
    expect(getDbStatus).toHaveBeenCalledTimes(4);
    await act(async () => { await vi.advanceTimersByTimeAsync(15000); });
    expect(getDbStatus).toHaveBeenCalledTimes(4);
  });

  it("recheck re-arms polling when warming reappears (backend restart, F2)", async () => {
    vi.useFakeTimers();
    (getDbStatus as any).mockClear();
    let warming = false;
    (getDbStatus as any).mockImplementation(() => Promise.resolve({ warming_up: warming }));
    let recheck: (() => Promise<boolean>) | null = null;
    function Probe() {
      const w = useWarming();
      recheck = w.recheck;
      return null;
    }
    renderWithI18n(<WarmingProvider><Probe /></WarmingProvider>);
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(getDbStatus).toHaveBeenCalledTimes(1);   // 挂载 poll 后停轮
    warming = true;
    await act(async () => { await recheck!(); });   // 503 自纠路径调用
    expect(getDbStatus).toHaveBeenCalledTimes(2);
    // 轮询已重臂:下一个 5s tick 继续拉取
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    expect(getDbStatus).toHaveBeenCalledTimes(3);
  });
});
