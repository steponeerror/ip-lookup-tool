import { createContext, useContext, useState, useCallback, useEffect, useRef, type ReactNode } from "react";
import { getDbStatus } from "./api";

type WarmingStatus = {
  warming: boolean;
  /** 立即拉取 db-status;warming 重现为 true 时重新武装轮询。 */
  recheck: () => Promise<boolean>;
};

const WarmingCtx = createContext<WarmingStatus | null>(null);

export function WarmingProvider({ children }: { children: ReactNode }) {
  const [warming, setWarming] = useState(false);
  const timerRef = useRef<number | undefined>(undefined);
  const aliveRef = useRef(false);

  const poll = useCallback(async (): Promise<boolean> => {
    const s = await getDbStatus().catch(() => null);
    if (!aliveRef.current || !s) return false;
    setWarming(s.warming_up);
    // warming_up 在后端进程生命周期内只会 true→false,首个 false 即停轮
    // (稳态零轮询);recheck() 发现 warming 重现(后端重启进入新冷启动)
    // 时重新武装轮询 — 否则控件锁死且横幅永不出现。
    if (!s.warming_up && timerRef.current !== undefined) {
      clearInterval(timerRef.current);
      timerRef.current = undefined;
    } else if (s.warming_up && timerRef.current === undefined) {
      timerRef.current = setInterval(poll, 5000);
    }
    return s.warming_up;
  }, []);

  useEffect(() => {
    aliveRef.current = true;
    poll();
    timerRef.current = setInterval(poll, 5000);
    return () => {
      aliveRef.current = false;
      if (timerRef.current !== undefined) clearInterval(timerRef.current);
      timerRef.current = undefined;
    };
  }, [poll]);

  return (
    <WarmingCtx.Provider value={{ warming, recheck: poll }}>
      {children}
    </WarmingCtx.Provider>
  );
}

export function useWarming(): WarmingStatus {
  const c = useContext(WarmingCtx);
  if (!c) throw new Error("useWarming must be used within WarmingProvider");
  return c;
}
