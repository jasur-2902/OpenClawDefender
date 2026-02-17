import { useState, useCallback } from "react";
import { useEventStore } from "../stores/eventStore";
import { useTauriEvent } from "../hooks/useTauriEvent";
import { PromptQueue } from "./PromptQueue";
import { AutoBlockToast } from "./AutoBlockToast";
import { AlertWindow } from "./AlertWindow";
import type { PendingPrompt } from "../types";
import type { AutoBlockInfo } from "./AutoBlockToast";
import type { AlertData } from "./AlertWindow";

export function NotificationLayer() {
  const addPrompt = useEventStore((s) => s.addPrompt);
  const [toasts, setToasts] = useState<AutoBlockInfo[]>([]);
  const [alerts, setAlerts] = useState<AlertData[]>([]);
  const pendingPrompts = useEventStore((s) => s.pendingPrompts);

  // Listen for prompt events
  const handlePrompt = useCallback(
    (payload: PendingPrompt) => {
      addPrompt(payload);
    },
    [addPrompt]
  );
  useTauriEvent<PendingPrompt>("clawdefender://prompt", handlePrompt);

  // Listen for auto-block events
  const handleAutoBlock = useCallback((payload: AutoBlockInfo) => {
    setToasts((prev) => [...prev, payload]);
  }, []);
  useTauriEvent<AutoBlockInfo>("clawdefender://auto-block", handleAutoBlock);

  // Listen for alert events
  const handleAlert = useCallback((payload: AlertData) => {
    setAlerts((prev) => [...prev, payload]);
  }, []);
  useTauriEvent<AlertData>("clawdefender://alert", handleAlert);

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const handleReview = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
    // Navigate to timeline in the future
  }, []);

  const handleTrust = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
    // Add trust rule in the future
  }, []);

  const dismissAlert = useCallback((id: string) => {
    setAlerts((prev) => prev.filter((a) => a.id !== id));
  }, []);

  const handleKillProcess = useCallback((id: string) => {
    setAlerts((prev) => prev.filter((a) => a.id !== id));
    // Kill process via Tauri command in the future
  }, []);

  const handleViewTimeline = useCallback((id: string) => {
    setAlerts((prev) => prev.filter((a) => a.id !== id));
    // Navigate to timeline in the future
  }, []);

  const hasPrompts = pendingPrompts.length > 0;
  const hasAlerts = alerts.length > 0;

  return (
    <>
      {/* Prompt overlay */}
      {hasPrompts && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <PromptQueue />
        </div>
      )}

      {/* Alert overlay */}
      {hasAlerts && !hasPrompts && (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/50 backdrop-blur-sm">
          <AlertWindow
            alert={alerts[0]}
            onKillProcess={handleKillProcess}
            onViewTimeline={handleViewTimeline}
            onDismiss={dismissAlert}
          />
        </div>
      )}

      {/* Toast area - top right */}
      {toasts.length > 0 && (
        <div className="fixed top-4 right-4 z-50 space-y-2">
          {toasts.map((block) => (
            <AutoBlockToast
              key={block.id}
              block={block}
              onDismiss={dismissToast}
              onReview={handleReview}
              onTrust={handleTrust}
            />
          ))}
        </div>
      )}
    </>
  );
}
