import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";
import type { IntelligentAlert, AlertStats } from "../types";

interface AlertStore {
  alerts: IntelligentAlert[];
  stats: AlertStats | null;
  loading: boolean;
  unresolvedCount: number;

  fetchAlerts: () => Promise<void>;
  fetchStats: () => Promise<void>;
  dismissAlert: (id: string) => Promise<void>;
  resolveAlert: (id: string, resolution: string) => Promise<void>;
  dismissAll: (maxSeverity: string) => Promise<number>;
  fetchHistory: (days: number) => Promise<IntelligentAlert[]>;
}

export const useAlertStore = create<AlertStore>((set, get) => ({
  alerts: [],
  stats: null,
  loading: false,
  unresolvedCount: 0,

  fetchAlerts: async () => {
    set({ loading: true });
    try {
      const alerts = await invoke<IntelligentAlert[]>("get_active_alerts_cmd");
      set({ alerts, unresolvedCount: alerts.length, loading: false });
    } catch {
      set({ loading: false });
    }
  },

  fetchStats: async () => {
    try {
      const stats = await invoke<AlertStats>("get_alert_stats_cmd");
      set({ stats });
    } catch {
      // stats are non-critical
    }
  },

  dismissAlert: async (id: string) => {
    try {
      await invoke("dismiss_alert_cmd", { alertId: id });
      await get().fetchAlerts();
    } catch {
      // ignore
    }
  },

  resolveAlert: async (id: string, resolution: string) => {
    try {
      await invoke("resolve_alert_cmd", { alertId: id, resolution });
      await get().fetchAlerts();
    } catch {
      // ignore
    }
  },

  dismissAll: async (maxSeverity: string) => {
    try {
      const count = await invoke<number>("dismiss_all_alerts", { maxSeverity });
      await get().fetchAlerts();
      return count;
    } catch {
      return 0;
    }
  },

  fetchHistory: async (days: number) => {
    try {
      return await invoke<IntelligentAlert[]>("get_alert_history_cmd", { days });
    } catch {
      return [];
    }
  },
}));
