import { useEffect, useState, useRef, useCallback } from "react";
import { Outlet, useLocation } from "react-router-dom";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
import { Sidebar } from "./Sidebar";
import { StatusHeader } from "./StatusHeader";
import { TrayMenu } from "./TrayMenu";
import { useEventStore } from "../stores/eventStore";
import { useAppStore } from "../stores/appStore";
import { useAlertStore } from "../stores/alertStore";
import { GuidanceToastContainer } from "./guidance/GuidanceToast";
import { PromptOverlay } from "./guidance/PromptOverlay";
import type { PendingPrompt } from "../types";
import type { Posture } from "./design";

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

/** Derive a page key from a pathname for the StatusHeader title. */
function pageKeyFromPath(pathname: string): string {
  if (pathname === "/") return "home";
  const seg = pathname.replace(/^\//, "").split("/")[0];
  // Handle sub-routes like /alerts/:id => "alertDetail", /activity/:id => "event"
  const parts = pathname.replace(/^\//, "").split("/");
  if (parts[0] === "alerts" && parts.length > 1) return "alertDetail";
  if (parts[0] === "activity" && parts.length > 1) return "event";
  return seg;
}

export function Layout() {
  const location = useLocation();
  const addPrompt = useEventStore((s) => s.addPrompt);
  const setDaemonStatus = useAppStore((s) => s.setDaemonStatus);
  const fetchAlerts = useAlertStore((s) => s.fetchAlerts);
  const addGuidanceHint = useAppStore((s) => s.addGuidanceHint);
  const setGuidanceOverlay = useAppStore((s) => s.setGuidanceOverlay);
  const setRestartReminder = useAppStore((s) => s.setRestartReminder);

  const sidebarCollapsed = useAppStore((s) => s.sidebarCollapsed);
  const setSidebarCollapsed = useAppStore((s) => s.setSidebarCollapsed);

  const [trayOpen, setTrayOpen] = useState(false);
  const [posture, setPosture] = useState<Posture>("normal");

  const [visible, setVisible] = useState(true);
  const prevPathRef = useRef(location.pathname);

  const currentPage = pageKeyFromPath(location.pathname);

  // Page crossfade transition
  useEffect(() => {
    if (prevPathRef.current !== location.pathname) {
      setVisible(false);
      const timer = setTimeout(() => setVisible(true), 20);
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
    const pageName =
      location.pathname === "/"
        ? "home"
        : location.pathname.replace(/^\//, "").split("/")[0];
    invoke("record_page_visit", { page: pageName }).catch(() => {});
  }, [location.pathname]);

  // Fetch posture periodically
  useEffect(() => {
    async function loadPosture() {
      try {
        const info = await invoke<{ level_name: string }>("get_threat_posture");
        const level = info.level_name?.toLowerCase() as Posture;
        if (["low", "normal", "elevated", "high", "critical"].includes(level)) {
          setPosture(level);
        }
      } catch {
        /* ignore */
      }
    }
    loadPosture();
    const interval = setInterval(loadPosture, 60_000);
    return () => clearInterval(interval);
  }, []);

  // Subscribe to Tauri events
  useEffect(() => {
    const unlisteners: (() => void)[] = [];

    listen<{ daemon_running: boolean }>("rookbot://status-change", (e) => {
      setDaemonStatus({ running: e.payload.daemon_running });
      useEventStore.getState().setDaemonRunning(e.payload.daemon_running);
    }).then((fn) => unlisteners.push(fn));

    listen<PendingPrompt>("rookbot://prompt", (e) => {
      addPrompt(e.payload);
    }).then((fn) => unlisteners.push(fn));

    listen("rookbot://alert", () => {
      fetchAlerts();
    }).then((fn) => unlisteners.push(fn));

    listen<GuidanceEvent>("rookbot://guidance-hint", (e) => {
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

    listen<GuidanceEvent>("rookbot://guidance-overlay", (e) => {
      const { milestone } = e.payload;
      setGuidanceOverlay({
        milestoneId: milestone.id,
        title: milestone.title,
        message: milestone.message,
      });
    }).then((fn) => unlisteners.push(fn));

    listen<GuidanceEvent>("rookbot://guidance-toast", (e) => {
      const { milestone } = e.payload;
      if (milestone.id === "restart_reminder") {
        setRestartReminder(true, milestone.message);
      }
    }).then((fn) => unlisteners.push(fn));

    return () => {
      for (const fn of unlisteners) fn();
    };
  }, [addPrompt, setDaemonStatus, fetchAlerts, addGuidanceHint, setGuidanceOverlay, setRestartReminder]);

  const handleToggleSidebar = useCallback(() => {
    setSidebarCollapsed(!sidebarCollapsed);
  }, [sidebarCollapsed, setSidebarCollapsed]);

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: sidebarCollapsed ? "60px 1fr" : "220px 1fr",
        height: "100vh",
        background: "var(--bg-0)",
        transition: "grid-template-columns 0.2s ease",
        position: "relative",
      }}
    >
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:z-[100] focus:px-4 focus:py-2 focus:bg-[var(--color-accent)] focus:text-white focus:rounded-md focus:m-2"
      >
        Skip to main content
      </a>

      <Sidebar collapsed={sidebarCollapsed} onToggle={handleToggleSidebar} />

      <div
        style={{
          display: "grid",
          gridTemplateRows: "auto 1fr",
          overflow: "hidden",
          position: "relative",
        }}
      >
        <StatusHeader
          currentPage={currentPage}
          posture={posture}
          onTrayOpen={() => setTrayOpen((v) => !v)}
        />

        <main
          id="main-content"
          aria-label="Main content"
          className="cd-scroll"
          style={{
            overflowY: "auto",
            padding: 24,
            opacity: visible ? 1 : 0,
            transition: "opacity 150ms ease-out",
          }}
        >
          <Outlet />
        </main>

        <TrayMenu
          open={trayOpen}
          onClose={() => setTrayOpen(false)}
          posture={posture}
          setPosture={setPosture}
        />
      </div>

      {/* Global guidance components */}
      <GuidanceToastContainer />
      <PromptOverlay />
    </div>
  );
}
