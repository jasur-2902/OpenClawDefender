import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";
import type { ScanProgress } from "../types";
import { tauriStorage } from "./tauriStorage";

// ---------------------------------------------------------------------------
// Shared types (exported for Scanner.tsx and other consumers)
// ---------------------------------------------------------------------------

export interface ScanHistoryEntry {
  scan_id: string;
  scan_type: "quick" | "ai";
  status: string;
  findings_count: number;
  started_at: string;
}

export interface ActivityItem {
  id: string;
  type: "finding" | "stage" | "info";
  message: string;
  severity?: string;
  timestamp: number;
}

export interface LiveFinding {
  id: string;
  severity: string;
  title: string;
  stage: string;
}

interface ScanResult {
  scan_id: string;
  status: string;
  started_at: string;
  completed_at: string | null;
  modules: ScanModuleResult[];
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
}

interface ScanModuleResult {
  module_id: string;
  module_name: string;
  status: string;
  findings: ScanFinding[];
  summary: string;
}

interface ScanFinding {
  severity: string;
  category: string;
  module: string;
  description: string;
  affected_resource: string;
  fix_suggestion: string;
  fix_action: {
    action_type: string;
    client: string | null;
    server: string | null;
    rule_name: string | null;
    rule_resource: string | null;
    rule_action: string | null;
  } | null;
}

type AiScanPhase = "select" | "scanning" | "results";
export type ScanTabType = "quick" | "ai" | "history";

interface ScanStore {
  // AI Scan state
  aiScanPhase: AiScanPhase;
  aiScanId: string | null;
  aiScanError: string | null;

  // Quick Scan state
  quickScanActiveScan: ScanProgress | null;
  quickScanResult: ScanResult | null;

  // Live feed state (in-memory, survives tab switches)
  quickScanActivity: ActivityItem[];
  quickScanLiveFindings: LiveFinding[];
  quickScanCurrentId: string | null;

  // Unified scan history (persisted)
  scanHistory: ScanHistoryEntry[];

  // Shared
  activeTab: ScanTabType;

  // Actions — tabs
  setActiveTab: (tab: ScanTabType) => void;

  // Actions — AI scan
  setAiScanPhase: (phase: AiScanPhase) => void;
  setAiScanId: (id: string | null) => void;
  setAiScanError: (error: string | null) => void;
  startNewAiScan: (scanId: string) => void;
  resetAiScan: () => void;

  // Actions — Quick scan
  setQuickScanActiveScan: (scan: ScanProgress | null) => void;
  setQuickScanResult: (result: ScanResult | null) => void;
  setQuickScanCurrentId: (id: string | null) => void;

  // Actions — Live feed
  addQuickScanActivity: (item: Omit<ActivityItem, "id" | "timestamp">) => void;
  addQuickScanLiveFinding: (finding: LiveFinding) => void;
  clearQuickScanLiveFeed: () => void;

  // Actions — History
  addScanHistory: (entry: ScanHistoryEntry) => void;

  // Back-compat shim
  quickScanHistory: ScanHistoryEntry[];
  addQuickScanHistory: (entry: { scan_id: string; status: ScanProgress["status"]; findings_count: number; started_at: string }) => void;
}

export const useScanStore = create<ScanStore>()(
  persist(
    (set, get) => ({
      // AI scan defaults
      aiScanPhase: "select",
      aiScanId: null,
      aiScanError: null,

      // Quick scan defaults
      quickScanActiveScan: null,
      quickScanResult: null,

      // Live feed defaults
      quickScanActivity: [],
      quickScanLiveFindings: [],
      quickScanCurrentId: null,

      // History
      scanHistory: [],

      // Tab
      activeTab: "ai",

      // --- Tab actions ---
      setActiveTab: (tab) => set({ activeTab: tab }),

      // --- AI scan actions ---
      setAiScanPhase: (phase) => set({ aiScanPhase: phase }),
      setAiScanId: (id) => set({ aiScanId: id }),
      setAiScanError: (error) => set({ aiScanError: error }),
      startNewAiScan: (scanId) =>
        set({
          aiScanId: scanId,
          aiScanPhase: "scanning",
          aiScanError: null,
        }),
      resetAiScan: () =>
        set({
          aiScanId: null,
          aiScanPhase: "select",
          aiScanError: null,
        }),

      // --- Quick scan actions ---
      setQuickScanActiveScan: (scan) => set({ quickScanActiveScan: scan }),
      setQuickScanResult: (result) => set({ quickScanResult: result }),
      setQuickScanCurrentId: (id) => set({ quickScanCurrentId: id }),

      // --- Live feed actions ---
      addQuickScanActivity: (item) =>
        set((state) => {
          // Deduplicate events with same message within 500ms (React StrictMode)
          const now = Date.now();
          const isDuplicate = state.quickScanActivity.some(
            (a) => a.message === item.message && now - a.timestamp < 500
          );
          if (isDuplicate) return state;
          return {
            quickScanActivity: [
              ...state.quickScanActivity,
              { ...item, id: `${now}-${Math.random()}`, timestamp: now },
            ],
          };
        }),
      addQuickScanLiveFinding: (finding) =>
        set((state) => {
          if (state.quickScanLiveFindings.some((f) => f.id === finding.id)) return state;
          return {
            quickScanLiveFindings: [...state.quickScanLiveFindings, finding],
          };
        }),
      clearQuickScanLiveFeed: () =>
        set({ quickScanActivity: [], quickScanLiveFindings: [] }),

      // --- History actions ---
      addScanHistory: (entry) =>
        set((state) => {
          // Prevent duplicate entries for the same scan_id
          if (state.scanHistory.some((h) => h.scan_id === entry.scan_id)) return state;
          return { scanHistory: [entry, ...state.scanHistory] };
        }),

      // Back-compat: quickScanHistory is a derived getter
      get quickScanHistory() {
        return get().scanHistory.filter((e) => e.scan_type === "quick");
      },
      addQuickScanHistory: (entry) =>
        set((state) => {
          if (state.scanHistory.some((h) => h.scan_id === entry.scan_id)) return state;
          return {
            scanHistory: [
              { ...entry, scan_type: "quick" as const },
              ...state.scanHistory,
            ],
          };
        }),
    }),
    {
      name: "scan-store",
      storage: createJSONStorage(() => tauriStorage),
      partialize: (state) =>
        ({
          activeTab: state.activeTab,
          scanHistory: state.scanHistory,
        }) as unknown as ScanStore,
    }
  )
);
