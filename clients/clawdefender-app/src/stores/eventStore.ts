import { create } from "zustand";
import type { AuditEvent, HumanizedEvent, PendingPrompt } from "../types";

const MAX_EVENTS = 10_000;

interface EventStore {
  events: HumanizedEvent[];
  pendingPrompts: PendingPrompt[];
  daemonRunning: boolean;
  onlyNotable: boolean;

  addEvent: (event: HumanizedEvent) => void;
  /** Add a raw AuditEvent by wrapping it as a minimal HumanizedEvent. */
  addRawEvent: (event: AuditEvent) => void;
  addPrompt: (prompt: PendingPrompt) => void;
  removePrompt: (id: string) => void;
  setDaemonRunning: (running: boolean) => void;
  setEvents: (events: HumanizedEvent[]) => void;
  setOnlyNotable: (value: boolean) => void;
}

/** Convert a raw AuditEvent to a minimal HumanizedEvent for live display. */
function wrapRawEvent(event: AuditEvent): HumanizedEvent {
  const actionTaken = (() => {
    const d = event.decision.toLowerCase();
    if (d === "prompted" || d === "prompt") return "Prompted" as const;
    if (d === "blocked" || d === "denied" || d === "block") {
      if (event.details.toLowerCase().includes("auto")) return "AutoBlocked" as const;
      return "Blocked" as const;
    }
    return "Allowed" as const;
  })();

  const isNotable =
    actionTaken === "Blocked" ||
    actionTaken === "AutoBlocked" ||
    event.risk_level === "high" ||
    event.risk_level === "critical";

  return {
    event_id: event.id,
    timestamp: event.timestamp,
    server_display_name: event.server_name,
    client_name: null,
    one_liner: `${event.tool_name ?? event.action} on ${event.server_name}`,
    expanded_explanation: event.details,
    educational_aside: null,
    behavioral_context: "",
    risk_level: event.risk_level,
    risk_explanation: "",
    action_taken: actionTaken,
    action_reason: "",
    is_notable: isNotable,
    correlation_id: null,
    kill_chain_id: null,
    raw_event: event,
  };
}

export const useEventStore = create<EventStore>((set) => ({
  events: [],
  pendingPrompts: [],
  daemonRunning: false,
  onlyNotable: false,

  addEvent: (event) =>
    set((state) => {
      const events = [event, ...state.events];
      if (events.length > MAX_EVENTS) {
        events.length = MAX_EVENTS;
      }
      return { events };
    }),

  addRawEvent: (event) =>
    set((state) => {
      const humanized = wrapRawEvent(event);
      const events = [humanized, ...state.events];
      if (events.length > MAX_EVENTS) {
        events.length = MAX_EVENTS;
      }
      return { events };
    }),

  addPrompt: (prompt) =>
    set((state) => ({
      pendingPrompts: [...state.pendingPrompts, prompt],
    })),

  removePrompt: (id) =>
    set((state) => ({
      pendingPrompts: state.pendingPrompts.filter((p) => p.id !== id),
    })),

  setDaemonRunning: (running) => set({ daemonRunning: running }),

  setEvents: (events) => set({ events }),

  setOnlyNotable: (value) => set({ onlyNotable: value }),
}));
