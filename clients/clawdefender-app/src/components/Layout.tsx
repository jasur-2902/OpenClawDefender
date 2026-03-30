import { useEffect, useState, useRef } from "react";
import { Outlet, useLocation } from "react-router-dom";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
import { Sidebar } from "./Sidebar";
import { ConnectionStatus } from "./ConnectionStatus";
import { UpdateBanner } from "./UpdateBanner";
import { useEventStore } from "../stores/eventStore";
import { useAppStore } from "../stores/appStore";
import { useAlertStore } from "../stores/alertStore";
import { GuidanceToastContainer } from "./guidance/GuidanceToast";
import { PromptOverlay } from "./guidance/PromptOverlay";
import type { AuditEvent, PendingPrompt } from "../types";

interface GuidanceMilestone {
  id: string;
  title: string;
  message: string;
  delivery: string;
  delivery_meta: Record<string, string> | null;
}

interface GuidanceEvent {
  milestone: GuidanceMilestone;
}

function RestartReminderBanner() {
  const visible = useAppStore((s) => s.restartReminderVisible);
  const message = useAppStore((s) => s.restartReminderMessage);
  const setRestartReminder = useAppStore((s) => s.setRestartReminder);

  if (!visible) return null;

  return (
    <div
      role="alert"
      aria-label="Restart reminder"
      className="flex items-center gap-3 px-4 py-3 border-b"
      style={{
        backgroundColor: "var(--color-info-subtle)",
        borderColor: "var(--color-info-border)",
      }}
    >
      <span
        className="shrink-0 text-sm font-semibold"
        style={{ color: "var(--color-accent)" }}
        aria-hidden="true"
      >
        C
      </span>
      <p className="flex-1 text-sm" style={{ color: "var(--color-text-primary)" }}>
        {message ||
          "Your AI apps need to restart to pick up protection. They have not reconnected yet."}
      </p>
      <button
        onClick={() => setRestartReminder(false)}
        className="shrink-0 text-xs font-medium px-3 py-1 rounded-md"
        style={{
          backgroundColor: "var(--color-bg-tertiary)",
          color: "var(--color-text-secondary)",
        }}
      >
        Dismiss
      </button>
    </div>
  );
}

export function Layout() {
  const location = useLocation();
  const addRawEvent = useEventStore((s) => s.addRawEvent);
  const addPrompt = useEventStore((s) => s.addPrompt);
  const setDaemonStatus = useAppStore((s) => s.setDaemonStatus);
  const fetchAlerts = useAlertStore((s) => s.fetchAlerts);
  const addGuidanceHint = useAppStore((s) => s.addGuidanceHint);
  const setGuidanceOverlay = useAppStore((s) => s.setGuidanceOverlay);
  const setRestartReminder = useAppStore((s) => s.setRestartReminder);

  const [visible, setVisible] = useState(true);
  const prevPathRef = useRef(location.pathname);

  // Page crossfade transition
  useEffect(() => {
    if (prevPathRef.current !== location.pathname) {
      setVisible(false);
      const timer = setTimeout(() => {
        setVisible(true);
      }, 20);
      prevPathRef.current = location.pathname;
      return () => clearTimeout(timer);
    }
  }, [location.pathname]);

  // Fetch alerts on initial load for sidebar badge
  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  // Record page visits for guidance nudge tracking
  useEffect(() => {
    const pageName = location.pathname === "/"
      ? "home"
      : location.pathname.replace(/^\//, "").split("/")[0];
    invoke("record_page_visit", { page: pageName }).catch(() => {});
  }, [location.pathname]);

  // Subscribe to Tauri events
  useEffect(() => {
    const unlisteners: (() => void)[] = [];

    listen<AuditEvent>("clawdefender://event", (e) => {
      addRawEvent(e.payload);
    }).then((fn) => unlisteners.push(fn));

    listen<{ daemon_running: boolean }>("clawdefender://status-change", (e) => {
      setDaemonStatus({ running: e.payload.daemon_running });
      useEventStore.getState().setDaemonRunning(e.payload.daemon_running);
    }).then((fn) => unlisteners.push(fn));

    listen<PendingPrompt>("clawdefender://prompt", (e) => {
      addPrompt(e.payload);
    }).then((fn) => unlisteners.push(fn));

    listen("clawdefender://alert", () => {
      fetchAlerts();
    }).then((fn) => unlisteners.push(fn));

    // Guidance event listeners
    listen<GuidanceEvent>("clawdefender://guidance-hint", (e) => {
      const { milestone } = e.payload;
      const meta = milestone.delivery_meta;
      const anchorId = meta?.anchor || milestone.id;
      addGuidanceHint({
        milestoneId: milestone.id,
        message: milestone.message,
        anchorId,
        actionLabel: meta?.action_label,
        actionRoute: meta?.action_route,
      });
    }).then((fn) => unlisteners.push(fn));

    listen<GuidanceEvent>("clawdefender://guidance-overlay", (e) => {
      const { milestone } = e.payload;
      setGuidanceOverlay({
        milestoneId: milestone.id,
        title: milestone.title,
        message: milestone.message,
      });
    }).then((fn) => unlisteners.push(fn));

    // Restart reminder: triggered by the restart_reminder milestone via toast
    // but we also listen for a dedicated event if the backend emits one
    listen<GuidanceEvent>("clawdefender://guidance-toast", (e) => {
      const { milestone } = e.payload;
      if (milestone.id === "restart_reminder") {
        setRestartReminder(true, milestone.message);
      }
    }).then((fn) => unlisteners.push(fn));

    return () => {
      for (const fn of unlisteners) fn();
    };
  }, [addRawEvent, addPrompt, setDaemonStatus, fetchAlerts, addGuidanceHint, setGuidanceOverlay, setRestartReminder]);

  return (
    <div className="flex h-screen bg-[var(--color-bg-primary)]">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:z-[100] focus:px-4 focus:py-2 focus:bg-[var(--color-accent)] focus:text-white focus:rounded-md focus:m-2"
      >
        Skip to main content
      </a>
      <Sidebar />
      <main className="flex-1 flex flex-col overflow-hidden" id="main-content" aria-label="Main content">
        <ConnectionStatus />
        <UpdateBanner />
        <RestartReminderBanner />
        <div
          className="flex-1 overflow-y-auto p-6"
          style={{
            opacity: visible ? 1 : 0,
            transition: "opacity 150ms ease-out",
          }}
        >
          <Outlet />
        </div>
      </main>
      {/* Global guidance components */}
      <GuidanceToastContainer />
      <PromptOverlay />
    </div>
  );
}
