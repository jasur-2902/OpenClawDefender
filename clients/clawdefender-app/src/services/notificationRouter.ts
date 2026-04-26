import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { sendNotification, isPermissionGranted, requestPermission } from "@tauri-apps/plugin-notification";
import { useToastStore } from "../components/notifications/ToastContainer";
import { NOTIFICATION_BATCH } from "../constants/messages";

interface HumanizedEvent {
  event_id: string;
  one_liner: string;
  risk_level: string;
  action_taken: string;
  is_notable: boolean;
  server_display_name: string;
}

interface IntelligentAlert {
  id: string;
  severity: string;
  title: string;
  narrative: string;
}

interface RoutingEvent {
  event?: HumanizedEvent;
  alert?: IntelligentAlert;
}

// Rate tracking for batch suppression
let eventTimestamps: number[] = [];
const RATE_WINDOW_MS = 5000;
const RATE_THRESHOLD = 10;

// Track which page is visible for foreground suppression
let currentVisiblePage: string | null = null;

export function setVisiblePage(page: string | null) {
  currentVisiblePage = page;
}

function isRateLimited(): boolean {
  const now = Date.now();
  eventTimestamps = eventTimestamps.filter((t) => now - t < RATE_WINDOW_MS);
  eventTimestamps.push(now);
  return eventTimestamps.length > RATE_THRESHOLD;
}

let batchNotificationPending = false;

function sendBatchNotification(count: number) {
  if (batchNotificationPending) return;
  batchNotificationPending = true;
  setTimeout(() => {
    batchNotificationPending = false;
    const addToast = useToastStore.getState().addToast;
    addToast({
      title: `${NOTIFICATION_BATCH.title} -- ${count} events in the last few seconds`,
      severity: "info",
      duration: 8000,
      action: {
        label: NOTIFICATION_BATCH.action,
        onClick: () => {
          window.location.hash = "#/activity";
        },
      },
    });
  }, RATE_WINDOW_MS);
}

async function ensureNotificationPermission(): Promise<boolean> {
  try {
    let granted = await isPermissionGranted();
    if (!granted) {
      const permission = await requestPermission();
      granted = permission === "granted";
    }
    return granted;
  } catch {
    return false;
  }
}

function isWindowFocused(): boolean {
  return document.hasFocus();
}

function routeEvent(data: RoutingEvent) {
  const addToast = useToastStore.getState().addToast;
  const { event, alert } = data;

  // Rate limiting check
  if (isRateLimited()) {
    sendBatchNotification(eventTimestamps.length);
    return;
  }

  // Priority 1: Policy prompt — handled by PromptContainer via rookbot://prompt event
  // No routing needed here since prompts go through eventStore.addPrompt

  // Priority 2: Dangerous alert
  if (alert && alert.severity === "dangerous") {
    // macOS notification (with sound) unless window focused
    if (!isWindowFocused()) {
      ensureNotificationPermission().then((granted) => {
        if (granted) {
          sendNotification({ title: "Security Alert", body: alert.title });
        }
      });
    }
    // In-app alert card is handled by existing AlertWindow in NotificationLayer
    return;
  }

  // Priority 3: Suspicious alert
  if (alert && alert.severity === "suspicious") {
    if (!isWindowFocused()) {
      ensureNotificationPermission().then((granted) => {
        if (granted) {
          sendNotification({ title: "Suspicious Activity", body: alert.title });
        }
      });
    }
    return;
  }

  // Priority 4: Auto-blocked
  if (event && event.action_taken === "AutoBlocked") {
    // Suppress toast if Activity page is visible
    if (currentVisiblePage === "activity") return;

    addToast({
      title: event.one_liner,
      severity: "warning",
      duration: 5000,
    });
    return;
  }

  // Priority 5: Informational alert
  if (alert && alert.severity === "info") {
    if (currentVisiblePage === "alerts") return;

    addToast({
      title: alert.title,
      severity: "info",
      duration: 8000,
    });
    return;
  }

  // Priority 6: Unusual — feed entry only (handled by eventStore)
  // Priority 7: Normal — feed entry only (handled by eventStore)
  // Priority 8: Silent — no action needed
}

export function startNotificationRouter(): () => void {
  const unlisteners: UnlistenFn[] = [];

  // Listen for humanized events
  listen<HumanizedEvent>("rookbot://humanized-event", (e) => {
    routeEvent({ event: e.payload });
  }).then((fn) => unlisteners.push(fn));

  // Listen for intelligent alerts
  listen<IntelligentAlert>("rookbot://intelligent-alert", (e) => {
    routeEvent({ alert: e.payload });
  }).then((fn) => unlisteners.push(fn));

  // Listen for legacy alert events (backward compatibility)
  listen<IntelligentAlert>("rookbot://alert", (e) => {
    routeEvent({
      alert: {
        id: e.payload.id,
        severity: e.payload.severity === "critical" ? "dangerous" : e.payload.severity,
        title: e.payload.title || e.payload.narrative,
        narrative: e.payload.narrative,
      },
    });
  }).then((fn) => unlisteners.push(fn));

  return () => {
    for (const fn of unlisteners) {
      fn();
    }
  };
}
