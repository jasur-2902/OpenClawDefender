import { create } from "zustand";
import type { AuditEvent, PendingPrompt } from "../types";

const MAX_EVENTS = 10_000;

interface EventStore {
  events: AuditEvent[];
  pendingPrompts: PendingPrompt[];
  daemonRunning: boolean;
  addEvent: (event: AuditEvent) => void;
  addPrompt: (prompt: PendingPrompt) => void;
  removePrompt: (id: string) => void;
  setDaemonRunning: (running: boolean) => void;
  setEvents: (events: AuditEvent[]) => void;
}

export const useEventStore = create<EventStore>((set) => ({
  events: [],
  pendingPrompts: [],
  daemonRunning: false,

  addEvent: (event) =>
    set((state) => {
      const events = [event, ...state.events];
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
}));
