import { describe, it, expect, vi } from "vitest";
import { screen, waitFor, fireEvent, act } from "@testing-library/react";
import SourcesPage from "../SourcesPage";
import { TaskProvider } from "../../tasks/TaskProvider";
import { renderWithI18n } from "../../test/i18nTestUtils";
import {
  enqueueSingle,
  enqueueBatch,
  getSources,
  subscribeTasks,
} from "../../api";

vi.mock("../../api", async () => {
  const real = await vi.importActual<any>("../../api");
  return {
    ...real,
    getSources: vi.fn().mockResolvedValue([
      {
        name: "feodo",
        enabled: true,
        category: "threat",
        archetype: "offline",
        fields: ["ip"],
        reliability: 0.5,
        authoritative_for: [],
        classification_type: null,
        url: null,
        stale_days: null,
        health: {
          name: "feodo",
          loaded: true,
          record_count: 10,
          covered_ips: 10,
          last_updated: null,
          is_stale: true,
          error: null,
        },
      },
      {
        name: "on_demand",
        enabled: true,
        category: "other",
        archetype: "online",
        fields: ["x"],
        reliability: 0.5,
        authoritative_for: [],
        classification_type: null,
        url: null,
        stale_days: null,
        health: {
          name: "on_demand",
          loaded: true,
          record_count: 0,
          covered_ips: 0,
          last_updated: null,
          is_stale: false,
          error: null,
        },
      },
    ]),
    getTasks: vi.fn().mockResolvedValue({ tasks: [], batch: null }),
    subscribeTasks: vi.fn(() => () => {}),
    enqueueSingle: vi.fn().mockResolvedValue({ task_id: "t1" }),
    enqueueBatch: vi.fn().mockResolvedValue({ batch_id: "b1" }),
  };
});

function render(el: React.ReactElement) {
  return renderWithI18n(<TaskProvider>{el}</TaskProvider>);
}

describe("SourcesPage", () => {
  it("hides Update for online source, shows for offline", async () => {
    render(<SourcesPage />);
    await screen.findByText("feodo");
    // offline row has an Update button
    expect(screen.getByRole("button", { name: /Update/i })).toBeInTheDocument();
    // online row renders but has NO Update button (only one Update button total)
    expect(screen.getAllByRole("button", { name: /Update/i }).length).toBe(1);
    // both rows render
    expect(screen.getAllByRole("listitem").length).toBe(2);
    expect(screen.getByText("on_demand")).toBeInTheDocument();
  });

  it("timeAgo shows 'no data' (not 'on-demand') for an offline source missing its raw file", async () => {
    vi.mocked(getSources).mockResolvedValueOnce([
      {
        name: "abuseipdb",
        enabled: true,
        category: "threat",
        archetype: "offline",
        fields: ["is_malicious"],
        reliability: 0.75,
        authoritative_for: ["is_malicious"],
        classification_type: null,
        url: null,
        stale_days: null,
        health: {
          name: "abuseipdb",
          loaded: false,
          record_count: 0,
          covered_ips: 0,
          last_updated: null,
          is_stale: true,
          error: null,
        },
      },
    ]);
    render(<SourcesPage />);
    await screen.findByText("abuseipdb");
    // Regression: offline + no last_updated used to show the misleading
    // "on-demand" timeAgo. An offline source with a missing raw file is NOT
    // on-demand (on-demand = ApiSource only); it must show "no data".
    expect(screen.getByText("no data")).toBeInTheDocument();
  });

  it("Update button enqueues single-source task", async () => {
    render(<SourcesPage />);
    const btn = await screen.findByRole("button", { name: /Update/i });
    fireEvent.click(btn);
    await waitFor(() => expect(enqueueSingle).toHaveBeenCalledWith("feodo"));
  });

  it("Refresh all enqueues batch", async () => {
    render(<SourcesPage />);
    const btn = await screen.findByRole("button", { name: /Refresh all/i });
    fireEvent.click(btn);
    await waitFor(() => expect(enqueueBatch).toHaveBeenCalled());
  });

  it("debounce-refetches sources when a task reaches done", async () => {
    render(<SourcesPage />);
    await screen.findByText("feodo");
    const initialCalls = (getSources as any).mock.calls.length;

    // Drive SSE: announce one done task. TaskProvider's applyEvent will run
    // setTasks, the doneCount changes from 0 → 1, and SourcesPage's effect
    // schedules a 500ms debounce-refetch. Use the LATEST subscribeTasks call
    // (mocks accumulate across tests; earlier providers are unmounted).
    const calls = (subscribeTasks as any).mock.calls;
    const cb = calls[calls.length - 1][0] as (e: any) => void;
    act(() => {
      cb({
        type: "snapshot",
        data: {
          tasks: [
            {
              id: "t1",
              source: "feodo",
              host: null,
              state: "done",
              error: null,
              batch_id: null,
            },
          ],
          batch: null,
        },
      });
    });

    // After 600ms (real timers), the 500ms debounce has fired.
    await waitFor(
      () => expect((getSources as any).mock.calls.length).toBeGreaterThan(initialCalls),
      { timeout: 2000 },
    );
  });

  it("shows progress from the latest task when a source has stale history", async () => {
    // Regression: tasks arrive oldest-first and a source accumulates terminal
    // tasks across batches. Picking the first match masked the current phase,
    // so re-updating a previously-updated source showed "Update" instead of
    // "Downloading". The latest task per source must win.
    render(<SourcesPage />);
    await screen.findByText("feodo");
    const calls = (subscribeTasks as any).mock.calls;
    const cb = calls[calls.length - 1][0] as (e: any) => void;
    act(() => {
      cb({
        type: "snapshot",
        data: {
          tasks: [
            { id: "t-old", source: "feodo", host: null, state: "done", error: null, batch_id: null },
            { id: "t-new", source: "feodo", host: null, state: "downloading", error: null, batch_id: null },
          ],
          batch: null,
        },
      });
    });
    expect(await screen.findByRole("button", { name: /Downloading/i })).toBeInTheDocument();
  });

  it("renders covered_ips with a B tier for geo-scale sources", async () => {
    vi.mocked(getSources).mockResolvedValueOnce([
      {
        name: "ipinfo_lite",
        enabled: true,
        category: "geo_asn",
        archetype: "offline",
        fields: ["country_code"],
        reliability: 0.9,
        authoritative_for: [],
        classification_type: null,
        url: null,
        stale_days: null,
        health: {
          name: "ipinfo_lite",
          loaded: true,
          record_count: 3600000,
          covered_ips: 3_700_000_000,
          last_updated: null,
          is_stale: false,
          error: null,
        },
      },
    ]);
    render(<SourcesPage />);
    expect(await screen.findByText("3.7B")).toBeInTheDocument();
  });
});
