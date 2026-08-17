import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import {
  getTasks, subscribeTasks, enqueueBatch as apiEnqueueBatch, enqueueSingle as apiEnqueueSingle,
  cancelTask as apiCancelTask, cancelBatch as apiCancelBatch, pauseBatch, resumeBatch,
  type TaskState, type BatchState,
} from "../api";

type Ctx = {
  tasks: TaskState[];
  batch: BatchState | null;
  enqueueSingle: (name: string) => Promise<void>;
  enqueueBatch: () => Promise<{ batch_id: string | null; refreshed?: number }>;
  cancelTask: (id: string) => Promise<void>;
  cancelBatch: () => Promise<void>;
  pause: () => Promise<void>;
  resume: () => Promise<void>;
};

const TasksContext = createContext<Ctx | null>(null);

export function TaskProvider({ children }: { children: ReactNode }) {
  const [tasks, setTasks] = useState<TaskState[]>([]);
  const [batch, setBatch] = useState<BatchState | null>(null);
  const tasksRef = useRef<Record<string, TaskState>>({});
  // True while a getTasks() fetch is in flight AND an SSE event has since
  // arrived. Prevents a slow getTasks() snapshot (e.g. cold-start first load)
  // from overwriting a fresher SSE event with stale state. Reset at every
  // fetch start so reconnect-time resyncs still apply when no SSE interleaves.
  const sseSawRef = useRef(false);

  const applyEvent = (e: any) => {
    sseSawRef.current = true;
    if (e.type === "snapshot" && e.data) {
      tasksRef.current = Object.fromEntries(e.data.tasks.map((t: TaskState) => [t.id, t]));
      setTasks(Object.values(tasksRef.current));
      setBatch(e.data.batch ?? null);
    } else if (e.type === "task" && e.task) {
      tasksRef.current[e.task.id] = e.task;
      setTasks(Object.values(tasksRef.current));
    } else if (e.type === "task_progress" && e.task_id) {
      const ex = tasksRef.current[e.task_id];
      if (ex) {
        tasksRef.current[e.task_id] = { ...ex, received: e.received, total: e.total };
        setTasks(Object.values(tasksRef.current));
      }
    } else if (e.type === "batch" && e.batch) {
      setBatch(e.batch);
    } else if (e.type === "done") {
      setBatch(e.batch ?? null);
    }
  };

  useEffect(() => {
    let alive = true;
    const resync = async () => {
      sseSawRef.current = false; // this fetch wins unless SSE interleaves
      const snap = await getTasks();
      if (!alive) return;
      if (sseSawRef.current) return; // an SSE event landed mid-fetch — it's fresher
      tasksRef.current = Object.fromEntries(snap.tasks.map((t) => [t.id, t]));
      setTasks(Object.values(tasksRef.current));
      setBatch(snap.batch);
    };
    resync();
    const unsub = subscribeTasks(applyEvent, resync);
    return () => { alive = false; unsub(); };
  }, []);

  const value: Ctx = {
    tasks, batch,
    enqueueSingle: async (n) => { await apiEnqueueSingle(n); },
    enqueueBatch: async () => { return apiEnqueueBatch(); },
    cancelTask: async (id) => { await apiCancelTask(id); },
    cancelBatch: async () => { await apiCancelBatch(); },
    pause: async () => { await pauseBatch(); },
    resume: async () => { await resumeBatch(); },
  };

  return <TasksContext.Provider value={value}>{children}</TasksContext.Provider>;
}

export function useTasks(): Ctx {
  const c = useContext(TasksContext);
  if (!c) throw new Error("useTasks must be used within TaskProvider");
  return c;
}
