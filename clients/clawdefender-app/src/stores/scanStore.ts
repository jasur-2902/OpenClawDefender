import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { ScanProgress } from "../types";
import { tauriStorage } from "./tauriStorage";

interface ScanHistoryEntry {
  scan_id: string;
  status: ScanProgress["status"];
  findings_count: number;
  started_at: string;
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

interface ScanStore {
  // AI Scan state
  aiScanPhase: AiScanPhase;
  aiScanId: string | null;
  aiScanError: string | null;

  // Quick Scan state
  quickScanActiveScan: ScanProgress | null;
  quickScanResult: ScanResult | null;
  quickScanHistory: ScanHistoryEntry[];

  // Shared
  activeTab: "quick" | "ai";

  // Actions
  setActiveTab: (tab: "quick" | "ai") => void;
  setAiScanPhase: (phase: AiScanPhase) => void;
  setAiScanId: (id: string | null) => void;
  setAiScanError: (error: string | null) => void;
  setQuickScanActiveScan: (scan: ScanProgress | null) => void;
  setQuickScanResult: (result: ScanResult | null) => void;
  addQuickScanHistory: (entry: ScanHistoryEntry) => void;

  // Reset helpers
  startNewAiScan: (scanId: string) => void;
  resetAiScan: () => void;
}

export const useScanStore = create<ScanStore>()(
  persist(
    (set) => ({
  aiScanPhase: "select",
  aiScanId: null,
  aiScanError: null,
  quickScanActiveScan: null,
  quickScanResult: null,
  quickScanHistory: [],
  activeTab: "ai",

  setActiveTab: (tab) => set({ activeTab: tab }),
  setAiScanPhase: (phase) => set({ aiScanPhase: phase }),
  setAiScanId: (id) => set({ aiScanId: id }),
  setAiScanError: (error) => set({ aiScanError: error }),
  setQuickScanActiveScan: (scan) => set({ quickScanActiveScan: scan }),
  setQuickScanResult: (result) => set({ quickScanResult: result }),
  addQuickScanHistory: (entry) =>
    set((state) => ({
      quickScanHistory: [entry, ...state.quickScanHistory],
    })),

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
}),
    {
      name: "scan-store",
      storage: tauriStorage,
      partialize: (state) => ({
        activeTab: state.activeTab,
        quickScanHistory: state.quickScanHistory,
      }),
    }
  )
);
