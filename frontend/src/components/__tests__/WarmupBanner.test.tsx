import { describe, it, expect, vi, afterEach } from "vitest";
import { screen, waitFor, act, fireEvent } from "@testing-library/react";
import { WarmupBanner } from "../WarmupBanner";
import { TaskProvider } from "../../tasks/TaskProvider";
import { renderWithI18n } from "../../test/i18nTestUtils";
import { getDbStatus, enqueueBatch } from "../../api";

// fake timers 若因断言失败泄漏(afterEach 兜底恢复,防污染后续测试)
afterEach(() => { vi.useRealTimers(); });

const sse = vi.hoisted(() => ({ onEvent: null as ((e: any) => void) | null }));

vi.mock("../../api", async () => {
  const real = await vi.importActual<any>("../../api");
  return {
    ...real,
    getDbStatus: vi.fn(),
    getTasks: vi.fn().mockResolvedValue({ tasks: [], batch: null }),
    subscribeTasks: vi.fn((onEvent: (e: any) => void) => {
      sse.onEvent = onEvent;
      return () => {};
    }),
    enqueueBatch: vi.fn().mockResolvedValue({ batch_id: "b2" }),
  };
});

function render(el: React.ReactElement) {
  return renderWithI18n(<TaskProvider>{el}</TaskProvider>);
}

describe("WarmupBanner", () => {
  it("renders nothing when not warming up", async () => {
    (getDbStatus as any).mockResolvedValue({ warming_up: false, total_records: 0 });
    const { container } = render(<WarmupBanner />);
    await waitFor(() => expect(container.querySelector("[data-warmup]")).toBeNull());
  });

  it("shows progress when warming + batch running", async () => {
    (getDbStatus as any).mockResolvedValue({ warming_up: true, total_records: 0 });
    // 通过 SSE 注入 batch + downloading task
    render(<WarmupBanner />);
    act(() => {
      sse.onEvent?.({ type: "snapshot", data: {
        tasks: [{ id: "t1", source: "firehol_level2", host: null,
                  state: "downloading", error: null, batch_id: "b1",
                  received: 500000, total: 1000000 }],
        batch: { id: "b1", state: "running", done: 14, total: 28 },
      }});
    });
    expect(await screen.findByText(/14\/28/)).toBeInTheDocument();
    expect(screen.getByText(/firehol_level2/)).toBeInTheDocument();
  });

  it("shows failure + retry when warming + batch settled with zero sources (after 3s debounce)", async () => {
    vi.useFakeTimers();
    (getDbStatus as any).mockResolvedValue({ warming_up: true, total_records: 0 });
    render(<WarmupBanner />);
    // flush 初始 db-status 轮询的微任务,让 warming 状态先落地
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    // batch settle(done) 但仍 warming(零源)
    act(() => {
      sse.onEvent?.({ type: "done", batch: { id: "b1", state: "done", done: 0, total: 28 }});
    });
    // 3s 去抖前不显示失败
    expect(screen.queryByText(/失败|failed/i)).toBeNull();
    // 快进 3s(异步推进:debounce 的 setTimeout 触发 + 状态更新 flush)
    await act(async () => { await vi.advanceTimersByTimeAsync(3100); });
    expect(screen.getByText(/失败|failed/i)).toBeInTheDocument();
    // 点重试(fireEvent 同步派发,避开 userEvent 在 fake timers 下的内部延迟)
    fireEvent.click(screen.getByRole("button", { name: /重试|retry/i }));
    expect(enqueueBatch).toHaveBeenCalled();
  });

  it("disappears when warming_up flips to false on batch done", async () => {
    let warming = true;
    (getDbStatus as any).mockImplementation(() => Promise.resolve({
      warming_up: warming, total_records: 100,
    }));
    const { container } = render(<WarmupBanner />);
    act(() => {
      sse.onEvent?.({ type: "batch", batch: { id: "b1", state: "running", done: 1, total: 2 }});
    });
    expect(await screen.findByText(/1\/2/)).toBeInTheDocument();
    // batch done 触发重拉 db-status → warming 翻 false
    warming = false;
    act(() => {
      sse.onEvent?.({ type: "done", batch: { id: "b1", state: "done", done: 2, total: 2 }});
    });
    await waitFor(() => expect(container.querySelector("[data-warmup]")).toBeNull());
  });

  it("stops polling db-status after the first warming_up=false (review #8)", async () => {
    vi.useFakeTimers();
    (getDbStatus as any).mockClear();
    let warming = true;
    (getDbStatus as any).mockImplementation(() => Promise.resolve({
      warming_up: warming, total_records: 0,
    }));
    render(<WarmupBanner />);
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });   // 初始 poll
    expect(getDbStatus).toHaveBeenCalledTimes(1);
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    expect(getDbStatus).toHaveBeenCalledTimes(3);   // 初始 + 2 个 tick
    warming = false;
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });  // 翻 false → 停轮
    expect(getDbStatus).toHaveBeenCalledTimes(4);
    await act(async () => { await vi.advanceTimersByTimeAsync(15000); });
    expect(getDbStatus).toHaveBeenCalledTimes(4);   // 稳态零轮询
  });
});
