import { useEffect, useState, useRef, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useAppStore } from "../stores/appStore";

type ConnectionState = "connected" | "reconnecting" | "disconnected";

const INITIAL_RETRY_MS = 5_000;
const MAX_RETRY_MS = 60_000;
const BACKOFF_FACTOR = 2;

export function ConnectionStatus() {
  const daemonRunning = useAppStore((s) => s.daemonStatus.running);
  const setDaemonStatus = useAppStore((s) => s.setDaemonStatus);

  const [connectionState, setConnectionState] = useState<ConnectionState>(
    daemonRunning ? "connected" : "disconnected"
  );
  const [lastConnected, setLastConnected] = useState<Date | null>(null);
  const [retryIn, setRetryIn] = useState(0);

  const retryDelayRef = useRef(INITIAL_RETRY_MS);
  const retryTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const countdownRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Sync from daemon status changes
  useEffect(() => {
    if (daemonRunning) {
      setConnectionState("connected");
      setLastConnected(null);
      retryDelayRef.current = INITIAL_RETRY_MS;
      if (retryTimerRef.current) clearTimeout(retryTimerRef.current);
      if (countdownRef.current) clearInterval(countdownRef.current);
    } else {
      if (connectionState === "connected") {
        setConnectionState("reconnecting");
        setLastConnected(new Date());
      }
    }
  }, [daemonRunning]); // eslint-disable-line react-hooks/exhaustive-deps

  const attemptReconnect = useCallback(async () => {
    try {
      const status = await invoke<{ running: boolean; version?: string }>(
        "get_daemon_status"
      );
      if (status.running) {
        setDaemonStatus(status);
        setConnectionState("connected");
        retryDelayRef.current = INITIAL_RETRY_MS;
        return;
      }
    } catch {
      // Still disconnected
    }

    // Schedule next retry with exponential backoff
    setConnectionState("reconnecting");
    const nextDelay = Math.min(
      retryDelayRef.current * BACKOFF_FACTOR,
      MAX_RETRY_MS
    );
    retryDelayRef.current = nextDelay;

    setRetryIn(Math.ceil(nextDelay / 1000));

    if (countdownRef.current) clearInterval(countdownRef.current);
    countdownRef.current = setInterval(() => {
      setRetryIn((prev) => {
        if (prev <= 1) {
          if (countdownRef.current) clearInterval(countdownRef.current);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    retryTimerRef.current = setTimeout(attemptReconnect, nextDelay);
  }, [setDaemonStatus]);

  // Start retry loop when disconnected
  useEffect(() => {
    if (connectionState === "reconnecting" && !retryTimerRef.current) {
      retryTimerRef.current = setTimeout(attemptReconnect, retryDelayRef.current);
      setRetryIn(Math.ceil(retryDelayRef.current / 1000));

      countdownRef.current = setInterval(() => {
        setRetryIn((prev) => {
          if (prev <= 1) {
            if (countdownRef.current) clearInterval(countdownRef.current);
            return 0;
          }
          return prev - 1;
        });
      }, 1000);
    }

    return () => {
      if (retryTimerRef.current) {
        clearTimeout(retryTimerRef.current);
        retryTimerRef.current = null;
      }
      if (countdownRef.current) {
        clearInterval(countdownRef.current);
        countdownRef.current = null;
      }
    };
  }, [connectionState, attemptReconnect]);

  // Don't render when connected
  if (connectionState === "connected") return null;

  const timeAgo = lastConnected
    ? formatTimeAgo(lastConnected)
    : null;

  return (
    <div
      role="status"
      aria-live="polite"
      className="flex items-center gap-3 px-4 py-2.5 border-b"
      style={{
        backgroundColor: "var(--color-warning-subtle)",
        borderColor: "var(--color-warning-border)",
      }}
    >
      {/* Pulsing indicator */}
      <span className="relative flex h-2 w-2 shrink-0" aria-hidden="true">
        <span
          className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-75"
          style={{ backgroundColor: "var(--color-warning)" }}
        />
        <span
          className="relative inline-flex rounded-full h-2 w-2"
          style={{ backgroundColor: "var(--color-warning)" }}
        />
      </span>

      <p
        className="flex-1 text-sm"
        style={{ color: "var(--color-text-primary)" }}
      >
        {connectionState === "reconnecting"
          ? "Reconnecting to monitoring service..."
          : "Live updates paused"}
        {timeAgo && (
          <span
            className="ml-2 text-xs"
            style={{ color: "var(--color-text-secondary)" }}
          >
            Last updated: {timeAgo}
          </span>
        )}
      </p>

      {retryIn > 0 && (
        <span
          className="text-xs tabular-nums shrink-0"
          style={{ color: "var(--color-text-muted)" }}
        >
          Retrying in {retryIn}s
        </span>
      )}

      <button
        onClick={() => {
          if (retryTimerRef.current) clearTimeout(retryTimerRef.current);
          retryTimerRef.current = null;
          retryDelayRef.current = INITIAL_RETRY_MS;
          attemptReconnect();
        }}
        className="shrink-0 text-xs font-medium px-3 py-1 rounded-md transition-colors duration-100"
        style={{
          backgroundColor: "var(--color-bg-tertiary)",
          color: "var(--color-text-secondary)",
        }}
      >
        Retry now
      </button>
    </div>
  );
}

function formatTimeAgo(date: Date): string {
  const diffMs = Date.now() - date.getTime();
  const diffSec = Math.floor(diffMs / 1000);
  if (diffSec < 60) return "just now";
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  return `${diffHr}h ago`;
}
