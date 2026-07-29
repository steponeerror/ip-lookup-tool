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
  enqueueBatch: () => Promise<void>;
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

  const applyEvent = (e: any) => {
    if (e.type === "snapshot" && e.data) {
      tasksRef.current = Object.fromEntries(e.data.tasks.map((t: TaskState) => [t.id, t]));
      setTasks(Object.values(tasksRef.current));
      setBatch(e.data.batch ?? null);
    } else if (e.type === "task" && e.task) {
      tasksRef.current[e.task.id] = e.task;
      setTasks(Object.values(tasksRef.current));
    } else if (e.type === "batch" && e.batch) {
      setBatch(e.batch);
    } else if (e.type === "done") {
      setBatch(e.batch ?? null);
    }
  };

  useEffect(() => {
    let alive = true;
    const resync = async () => {
      const snap = await getTasks();
      if (!alive) return;
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
    enqueueBatch: async () => { await apiEnqueueBatch(); },
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
