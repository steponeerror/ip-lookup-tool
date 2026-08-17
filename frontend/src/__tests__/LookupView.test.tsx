import { describe, it, expect, vi } from "vitest";
import { screen, waitFor, fireEvent } from "@testing-library/react";
import LookupView from "../LookupView";
import { TaskProvider } from "../tasks/TaskProvider";
import { renderWithI18n } from "../test/i18nTestUtils";
import { getDbStatus, queryIpsStream } from "../api";

vi.mock("../api", async () => {
  const real = await vi.importActual<any>("../api");
  return {
    ...real,
    getDbStatus: vi.fn(),
    getTasks: vi.fn().mockResolvedValue({ tasks: [], batch: null }),
    subscribeTasks: vi.fn(() => () => {}),
    enqueueBatch: vi.fn().mockResolvedValue({ batch_id: "b2" }),
    queryIpsStream: vi.fn(),
    uploadFileStream: vi.fn(),
  };
});

function renderLookup() {
  return renderWithI18n(
    <TaskProvider>
      <LookupView />
    </TaskProvider>
  );
}

describe("LookupView warmup integration", () => {
  it("renders WarmupBanner above the query controls while warming", async () => {
    (getDbStatus as any).mockResolvedValue({ warming_up: true, total_records: 0 });
    const { container } = renderLookup();
    await waitFor(() => expect(container.querySelector("[data-warmup]")).not.toBeNull());
    const banner = container.querySelector("[data-warmup]")!;
    const textarea = container.querySelector("textarea")!;
    // 横幅在查询控件之前(文档顺序)
    expect(
      banner.compareDocumentPosition(textarea) & Node.DOCUMENT_POSITION_FOLLOWING
    ).toBeTruthy();
  });

  it("disables IP input, file upload and query button while warming", async () => {
    (getDbStatus as any).mockResolvedValue({ warming_up: true, total_records: 0 });
    const { container } = renderLookup();
    // text tab: textarea + 查询按钮置灰
    await waitFor(() => expect((container.querySelector("textarea") as HTMLTextAreaElement).disabled).toBe(true));
    expect(screen.getByRole("button", { name: "Query" })).toBeDisabled();
    // file tab: 文件选择置灰
    fireEvent.click(screen.getByRole("button", { name: "File Upload" }));
    const fileInput = await screen.findByLabelText("Choose File");
    expect(fileInput).toBeDisabled();
  });

  it("keeps controls enabled and hides banner when not warming", async () => {
    (getDbStatus as any).mockResolvedValue({ warming_up: false, total_records: 100 });
    const { container } = renderLookup();
    await waitFor(() => expect(container.querySelector("textarea")).not.toBeNull());
    expect((container.querySelector("textarea") as HTMLTextAreaElement).disabled).toBe(false);
    expect(screen.getByRole("button", { name: "Query" })).toBeEnabled();
    expect(container.querySelector("[data-warmup]")).toBeNull();
  });
});

describe("LookupView 503 self-correction", () => {
  it("a warming 503 from a query suppresses the generic error and reveals the banner + disables controls", async () => {
    // 所有 getDbStatus 调用共享一个 deferred:挂载期轮询保持 pending
    // (控件可用);查询撞 503 后 resolve warming_up=true,LookupView 的
    // 重拉与 WarmupBanner 的轮询拿到同一份结果(横幅不必等 5s 轮询)。
    let resolveStatus!: (v: any) => void;
    const pending = new Promise<any>(r => { resolveStatus = r; });
    (getDbStatus as any).mockReturnValue(pending);
    (queryIpsStream as any).mockRejectedValue(new Error("database is warming up"));

    const { container } = renderLookup();
    const textarea = await waitFor(() => {
      const el = container.querySelector("textarea") as HTMLTextAreaElement;
      expect(el).not.toBeNull();
      return el;
    });
    fireEvent.change(textarea, { target: { value: "1.1.1.1" } });
    fireEvent.click(screen.getByRole("button", { name: "Query" }));

    resolveStatus({ warming_up: true, total_records: 0 });

    await waitFor(() => expect(container.querySelector("[data-warmup]")).not.toBeNull());
    expect(screen.queryByText("database is warming up")).toBeNull();
    expect(screen.getByRole("button", { name: "Query" })).toBeDisabled();
  });

  it("a non-warming error still shows the generic error box without the banner", async () => {
    (getDbStatus as any).mockResolvedValue({ warming_up: false, total_records: 100 });
    (queryIpsStream as any).mockRejectedValue(new Error("boom"));

    const { container } = renderLookup();
    const textarea = await waitFor(() => {
      const el = container.querySelector("textarea") as HTMLTextAreaElement;
      expect(el).not.toBeNull();
      return el;
    });
    fireEvent.change(textarea, { target: { value: "1.1.1.1" } });
    fireEvent.click(screen.getByRole("button", { name: "Query" }));

    await waitFor(() => expect(screen.getByText("boom")).not.toBeNull());
    expect(container.querySelector("[data-warmup]")).toBeNull();
    expect(screen.getByRole("button", { name: "Query" })).toBeEnabled();
  });
});
