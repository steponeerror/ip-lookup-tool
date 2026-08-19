import type { TaskState } from "../api";

// 分段加权模型(spec §3):下载 0→0.5,重建 0.5→1;未知 total 取段内锚点
// (downloading 0.25 / loading 0.5,后者为段起点 — 保证相位边界无下跳)。
export function stagedFrac(t: TaskState): number {
  if (t.state === "done") return 1;
  if (t.state === "failed" || t.state === "cancelled") return t.frozenFrac ?? 0;
  const known = (t.total ?? 0) > 0;
  const frac = known ? Math.min(1, (t.received ?? 0) / (t.total as number)) : null;
  if (t.state === "downloading") return frac !== null ? 0.5 * frac : 0.25;
  if (t.state === "loading") return frac !== null ? 0.5 + 0.5 * frac : 0.5;
  return 0; // queued / throttled / 未知状态兜底
}

export function isIndeterminate(t: TaskState): boolean {
  return (t.state === "downloading" || t.state === "loading") && !(t.total ?? 0);
}
