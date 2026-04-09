import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { AiStatus } from "../types";

export function useAiStatus() {
  const [status, setStatus] = useState<AiStatus | null>(null);

  useEffect(() => {
    invoke<AiStatus>("get_ai_status").then(setStatus).catch(() => {});
    const interval = setInterval(() => {
      invoke<AiStatus>("get_ai_status").then(setStatus).catch(() => {});
    }, 30000);
    return () => clearInterval(interval);
  }, []);

  return {
    status,
    localActive: status?.local.active ?? false,
    cloudActive: status?.cloud.active ?? false,
    canInvestigate: status?.cloud.active ?? false,
    canScan: (status?.local.active || status?.cloud.active) ?? false,
    canAskClaw: (status?.local.active || status?.cloud.active) ?? false,
  };
}
