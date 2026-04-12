import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";
import { invoke } from "@tauri-apps/api/core";
import type { ProtectionScore, ScoreSnapshot } from "../types";
import { tauriStorage } from "./tauriStorage";

export type ConnectionState = "connected" | "reconnecting" | "disconnected";

const SCORE_TTL_MS = 30_000; // 30s TTL for cached score data

interface DaemonStatus {
  running: boolean;
  version?: string;
}

/** Guidance hint data stored for rendering by GuidanceAnchor components. */
export interface GuidanceHintData {
  milestoneId: string;
  message: string;
  anchorId: string;
  actionLabel?: string;
  actionRoute?: string;
}

/** Guidance overlay data stored for rendering by PromptOverlay. */
export interface GuidanceOverlayData {
  milestoneId: string;
  title: string;
  message: string;
}

interface AppStore {
  daemonStatus: DaemonStatus;
  connectionState: ConnectionState;
  protectionScore: number;
  /** Full backend protection score (null until first load). */
  protectionScoreFull: ProtectionScore | null;
  /** Score history snapshots for sparkline. */
  scoreHistory: ScoreSnapshot[];
  /** Timestamps for TTL cache invalidation. */
  _scoreFetchedAt: number;
  _historyFetchedAt: number;
  activePage: string;
  sidebarCollapsed: boolean;
  /** Active inline guidance hints keyed by anchor ID. */
  guidanceHints: Record<string, GuidanceHintData>;
  /** Active guidance overlay (for prompt overlay). */
  guidanceOverlay: GuidanceOverlayData | null;
  /** Whether the restart reminder banner should be visible. */
  restartReminderVisible: boolean;
  restartReminderMessage: string;

  setDaemonStatus: (status: DaemonStatus) => void;
  setConnectionState: (state: ConnectionState) => void;
  setProtectionScore: (score: number) => void;
  setProtectionScoreFull: (score: ProtectionScore) => void;
  setActivePage: (page: string) => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
  addGuidanceHint: (hint: GuidanceHintData) => void;
  removeGuidanceHint: (anchorId: string) => void;
  setGuidanceOverlay: (overlay: GuidanceOverlayData | null) => void;
  setRestartReminder: (visible: boolean, message?: string) => void;
  /** Fetch score with TTL cache. Pass force=true to bypass cache. */
  fetchScore: (force?: boolean) => Promise<void>;
  /** Fetch score history with TTL cache. */
  fetchScoreHistory: (force?: boolean) => Promise<void>;
}

export const useAppStore = create<AppStore>()(
  persist(
    (set, get) => ({
  daemonStatus: { running: false },
  connectionState: "disconnected",
  protectionScore: 0,
  protectionScoreFull: null,
  scoreHistory: [],
  _scoreFetchedAt: 0,
  _historyFetchedAt: 0,
  activePage: "/",
  sidebarCollapsed: false,
  guidanceHints: {},
  guidanceOverlay: null,
  restartReminderVisible: false,
  restartReminderMessage: "",

  setDaemonStatus: (status) =>
    set({
      daemonStatus: status,
      connectionState: status.running ? "connected" : "reconnecting",
    }),
  setConnectionState: (connectionState) => set({ connectionState }),
  setProtectionScore: (score) => set({ protectionScore: score }),
  setProtectionScoreFull: (score) =>
    set({ protectionScoreFull: score, protectionScore: score.total }),
  setActivePage: (page) => set({ activePage: page }),
  setSidebarCollapsed: (collapsed) => set({ sidebarCollapsed: collapsed }),
  addGuidanceHint: (hint) =>
    set((state) => ({
      guidanceHints: { ...state.guidanceHints, [hint.anchorId]: hint },
    })),
  removeGuidanceHint: (anchorId) =>
    set((state) => {
      const next = { ...state.guidanceHints };
      delete next[anchorId];
      return { guidanceHints: next };
    }),
  setGuidanceOverlay: (overlay) => set({ guidanceOverlay: overlay }),
  setRestartReminder: (visible, message) =>
    set({
      restartReminderVisible: visible,
      restartReminderMessage: message ?? "",
    }),

  fetchScore: async (force) => {
    const now = Date.now();
    if (!force && now - get()._scoreFetchedAt < SCORE_TTL_MS && get().protectionScoreFull) return;
    try {
      const result = await invoke<ProtectionScore>("get_protection_score");
      set({
        protectionScoreFull: result,
        protectionScore: result.total,
        _scoreFetchedAt: Date.now(),
      });
    } catch {
      // Keep previous state
    }
  },

  fetchScoreHistory: async (force) => {
    const now = Date.now();
    if (!force && now - get()._historyFetchedAt < SCORE_TTL_MS && get().scoreHistory.length > 0) return;
    try {
      const result = await invoke<ScoreSnapshot[]>("get_score_history", { days: 7 });
      set({ scoreHistory: result, _historyFetchedAt: Date.now() });
    } catch {
      // History unavailable
    }
  },
}),
    {
      name: "app-store",
      storage: createJSONStorage(() => tauriStorage),
      partialize: (state) => ({
        sidebarCollapsed: state.sidebarCollapsed,
      }) as unknown as AppStore,
    }
  )
);
