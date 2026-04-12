import { useState, useEffect, useCallback, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type {
  ScanProgress,
  ScanFindingEvent,
  ScanStageCompleteEvent,
  ScanCompleteEvent,
} from "../types";
import { PlaybookSelector } from "../components/scanner/PlaybookSelector";
import { LiveScanView } from "../components/scanner/LiveScanView";
import { AiScanResults } from "../components/scanner/AiScanResults";
import { useAiStatus } from "../hooks/useAiStatus";
import { useScanStore } from "../stores/scanStore";
import type { ScanHistoryEntry } from "../stores/scanStore";

// ---------------------------------------------------------------------------
// Quick Scan types (existing rule-based scanner)
// ---------------------------------------------------------------------------

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

interface ScanModuleResult {
  module_id: string;
  module_name: string;
  status: string;
  findings: ScanFinding[];
  summary: string;
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

const MODULES = [
  // MCP Security
  { id: "mcp-config-audit", label: "MCP Config Audit", icon: "shield", group: "mcp" },
  { id: "policy-strength", label: "Policy Strength", icon: "lock", group: "mcp" },
  { id: "server-reputation", label: "Server Reputation", icon: "search", group: "mcp" },
  { id: "system-posture", label: "System Posture", icon: "monitor", group: "mcp" },
  { id: "behavioral-anomaly", label: "Behavioral Anomaly", icon: "activity", group: "mcp" },
  // System Security
  { id: "tcc-audit", label: "TCC Permissions", icon: "key", group: "system" },
  { id: "file-integrity", label: "File Integrity", icon: "file-check", group: "system" },
  { id: "cis-benchmark", label: "CIS Compliance", icon: "check-square", group: "system" },
  { id: "browser-audit", label: "Browser Extensions", icon: "globe", group: "system" },
  { id: "clipboard-check", label: "Clipboard Security", icon: "clipboard", group: "system" },
  { id: "memory-scan", label: "Memory Scan", icon: "cpu", group: "system" },
] as const;

const SEVERITY_CONFIG: Record<string, { color: string; bg: string; label: string; order: number }> = {
  critical: { color: "text-red-400", bg: "bg-red-500/20", label: "CRITICAL", order: 0 },
  high: { color: "text-orange-400", bg: "bg-orange-500/20", label: "HIGH", order: 1 },
  medium: { color: "text-yellow-400", bg: "bg-yellow-500/20", label: "MEDIUM", order: 2 },
  low: { color: "text-blue-400", bg: "bg-blue-500/20", label: "LOW", order: 3 },
};

const SEVERITY_ICON: Record<string, string> = {
  critical: "\u{1F534}",
  high: "\u{1F7E0}",
  medium: "\u{1F7E1}",
  low: "\u{1F535}",
};

interface AskClawEntry {
  loading: boolean;
  response: string | null;
  followUp: string;
}

// ---------------------------------------------------------------------------
// Top-level Scanner component
// ---------------------------------------------------------------------------

export function Scanner() {
  const activeTab = useScanStore((s) => s.activeTab);
  const setActiveTab = useScanStore((s) => s.setActiveTab);
  const { cloudActive, localActive } = useAiStatus();

  // ---- Global event listeners for Quick Scan live feed ----
  const addQuickScanActivity = useScanStore((s) => s.addQuickScanActivity);
  const addQuickScanLiveFinding = useScanStore((s) => s.addQuickScanLiveFinding);
  const quickScanCurrentId = useScanStore((s) => s.quickScanCurrentId);
  const currentIdRef = useRef(quickScanCurrentId);
  currentIdRef.current = quickScanCurrentId;

  useEffect(() => {
    const unlisteners: Array<() => void> = [];

    listen<ScanFindingEvent>("clawdefender://scan-finding", (event) => {
      const p = event.payload;
      if (currentIdRef.current && p.scan_id !== currentIdRef.current) return;
      addQuickScanLiveFinding({
        id: p.finding_id,
        severity: p.severity,
        title: p.title,
        stage: p.stage,
      });
      addQuickScanActivity({
        type: "finding",
        message: `${SEVERITY_ICON[p.severity] || ""} ${p.severity.toUpperCase()}: ${p.title}`,
        severity: p.severity,
      });
    }).then((fn) => unlisteners.push(fn));

    listen<ScanStageCompleteEvent>("clawdefender://scan-stage-complete", (event) => {
      const p = event.payload;
      if (currentIdRef.current && p.scan_id !== currentIdRef.current) return;
      addQuickScanActivity({
        type: "stage",
        message: `${p.stage_name} completed (${p.stages_completed}/${p.stages_total})`,
      });
    }).then((fn) => unlisteners.push(fn));

    listen<ScanCompleteEvent>("clawdefender://scan-complete", (event) => {
      const p = event.payload;
      if (currentIdRef.current && p.scan_id !== currentIdRef.current) return;
      addQuickScanActivity({
        type: "info",
        message: `Scan complete: ${p.summary}`,
      });
    }).then((fn) => unlisteners.push(fn));

    return () => {
      unlisteners.forEach((fn) => fn());
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const tabs: { key: typeof activeTab; label: string }[] = [
    { key: "ai", label: "AI Scan" },
    { key: "quick", label: "Quick Scan" },
    { key: "history", label: "Scan History" },
  ];

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Security Scanner</h1>
      </div>

      {/* AI enrichment status */}
      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] px-4 py-3 text-sm text-[var(--color-text-secondary)]">
        {cloudActive
          ? 'Scan findings will be enriched with AI analysis'
          : localActive
            ? 'Basic AI analysis available. Connect Cloud API for deeper scan insights.'
            : 'AI analysis unavailable. Connect an AI backend in Settings.'}
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 border-b border-[var(--color-border)]">
        {tabs.map((t) => (
          <button
            key={t.key}
            onClick={() => setActiveTab(t.key)}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === t.key
                ? "border-[var(--color-accent)] text-[var(--color-accent)]"
                : "border-transparent text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {activeTab === "ai" && <AiScanTab />}
      {activeTab === "quick" && <QuickScanTab />}
      {activeTab === "history" && <ScanHistoryTab />}
    </div>
  );
}

// ---------------------------------------------------------------------------
// AI Scan Tab
// ---------------------------------------------------------------------------

function AiScanTab() {
  const phase = useScanStore((s) => s.aiScanPhase);
  const setPhase = useScanStore((s) => s.setAiScanPhase);
  const scanId = useScanStore((s) => s.aiScanId);
  const error = useScanStore((s) => s.aiScanError);
  const setError = useScanStore((s) => s.setAiScanError);
  const startNewAiScan = useScanStore((s) => s.startNewAiScan);
  const resetAiScan = useScanStore((s) => s.resetAiScan);
  const addScanHistory = useScanStore((s) => s.addScanHistory);
  const [starting, setStarting] = useState(false);

  async function handleStartScan(playbookId: string) {
    setError(null);
    setStarting(true);
    try {
      const result = await invoke<{ scan_id: string }>("start_ai_scan", {
        playbookId,
      });
      startNewAiScan(result.scan_id);
    } catch (e) {
      setError(String(e));
    } finally {
      setStarting(false);
    }
  }

  function handleComplete() {
    // Add to unified scan history
    if (scanId) {
      addScanHistory({
        scan_id: scanId,
        scan_type: "ai",
        status: "completed",
        findings_count: 0, // Will be updated when results load
        started_at: new Date().toISOString(),
      });
    }
    setPhase("results");
  }

  function handleCancel() {
    setPhase("results");
  }

  function handleNewScan() {
    resetAiScan();
  }

  return (
    <div className="space-y-4">
      {error && (
        <div className="rounded-lg border border-[var(--color-danger)] bg-[var(--color-danger)]/10 p-4 text-sm text-[var(--color-danger)]">
          {error}
        </div>
      )}

      {phase === "select" && (
        <div className="space-y-4">
          <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4">
            <div className="flex items-center gap-2 mb-3">
              <span className="text-sm font-medium text-[var(--color-text-primary)]">
                AI-Powered Security Scan
              </span>
              <span className="px-1.5 py-0.5 rounded text-xs bg-[var(--color-accent)]/20 text-[var(--color-accent)]">
                AI
              </span>
            </div>
            <p className="text-xs text-[var(--color-text-secondary)] mb-4">
              Choose a playbook to run an AI-driven security assessment. The AI agent will analyze
              your MCP configuration, system posture, and security policies using real tools and
              evidence collection.
            </p>
            <PlaybookSelector onStart={handleStartScan} disabled={starting} />
          </div>
        </div>
      )}

      {phase === "scanning" && scanId && (
        <LiveScanView
          scanId={scanId}
          onComplete={handleComplete}
          onCancel={handleCancel}
        />
      )}

      {phase === "results" && scanId && (
        <AiScanResults scanId={scanId} onNewScan={handleNewScan} />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Quick Scan Tab
// ---------------------------------------------------------------------------

function QuickScanTab() {
  const [selectedModules, setSelectedModules] = useState<Set<string>>(
    new Set(MODULES.map((m) => m.id))
  );
  const activeScan = useScanStore((s) => s.quickScanActiveScan);
  const setActiveScan = useScanStore((s) => s.setQuickScanActiveScan);
  const scanResult = useScanStore((s) => s.quickScanResult);
  const setScanResult = useScanStore((s) => s.setQuickScanResult);
  const addScanHistory = useScanStore((s) => s.addScanHistory);
  const setQuickScanCurrentId = useScanStore((s) => s.setQuickScanCurrentId);
  const clearQuickScanLiveFeed = useScanStore((s) => s.clearQuickScanLiveFeed);
  const addQuickScanActivity = useScanStore((s) => s.addQuickScanActivity);

  // Live feed from store
  const activity = useScanStore((s) => s.quickScanActivity);
  const liveFindings = useScanStore((s) => s.quickScanLiveFindings);

  const [elapsed, setElapsed] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [expandedModules, setExpandedModules] = useState<Set<string>>(new Set());
  const [fixingAction, setFixingAction] = useState<string | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const activityFeedRef = useRef<HTMLDivElement>(null);

  // Ask Claw state
  const [askClawState, setAskClawState] = useState<Map<string, AskClawEntry>>(new Map());

  // Auto-scroll activity feed
  useEffect(() => {
    if (activityFeedRef.current) {
      activityFeedRef.current.scrollTop = activityFeedRef.current.scrollHeight;
    }
  }, [activity]);

  // Resume polling if there's an active scan (e.g. navigated back)
  useEffect(() => {
    if (activeScan?.status === "running" && !timerRef.current) {
      const startTime = Date.now() - elapsed * 1000;
      timerRef.current = setInterval(() => {
        setElapsed(Math.floor((Date.now() - startTime) / 1000));
        pollScan(activeScan.scan_id);
      }, 500);
    }
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const pollScan = useCallback(async (scanId: string) => {
    try {
      const progress = await invoke<ScanProgress>("get_scan_progress", {
        scanId,
      });
      setActiveScan(progress);
      if (progress.status !== "running") {
        if (timerRef.current) {
          clearInterval(timerRef.current);
          timerRef.current = null;
        }
        addScanHistory({
          scan_id: progress.scan_id,
          scan_type: "quick",
          status: progress.status,
          findings_count: progress.findings_count,
          started_at: new Date().toISOString(),
        });
        // Fetch full results
        try {
          const result = await invoke<ScanResult>("get_scan_results", {
            scanId,
          });
          setScanResult(result);
          const withFindings = new Set(
            result.modules
              .filter((m) => m.findings.length > 0)
              .map((m) => m.module_id)
          );
          setExpandedModules(withFindings);
        } catch {
          // Results may not be ready yet
        }
      }
    } catch (e) {
      setError(String(e));
      if (timerRef.current) {
        clearInterval(timerRef.current);
        timerRef.current = null;
      }
    }
  }, [setActiveScan, addScanHistory, setScanResult]);

  async function startScan() {
    setError(null);
    setElapsed(0);
    setScanResult(null);
    setExpandedModules(new Set());
    clearQuickScanLiveFeed();
    setAskClawState(new Map());
    try {
      const scanId = await invoke<string>("start_scan", {
        serverCommand: "system-scan",
        modules: Array.from(selectedModules),
        timeout: 300,
      });
      setQuickScanCurrentId(scanId);
      setActiveScan({
        scan_id: scanId,
        status: "running",
        progress_percent: 0,
        modules_completed: 0,
        modules_total: selectedModules.size,
        findings_count: 0,
        current_module: null,
      });

      addQuickScanActivity({ type: "info", message: `Scan started with ${selectedModules.size} modules` });

      const startTime = Date.now();
      timerRef.current = setInterval(() => {
        setElapsed(Math.floor((Date.now() - startTime) / 1000));
        pollScan(scanId);
      }, 500);
    } catch (e) {
      setError(String(e));
    }
  }

  function toggleModule(id: string) {
    setSelectedModules((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleExpanded(moduleId: string) {
    setExpandedModules((prev) => {
      const next = new Set(prev);
      if (next.has(moduleId)) next.delete(moduleId);
      else next.add(moduleId);
      return next;
    });
  }

  async function applyFix(finding: ScanFinding) {
    if (!finding.fix_action) return;
    const key = `${finding.fix_action.action_type}:${finding.affected_resource}`;
    setFixingAction(key);
    try {
      const result = await invoke<string>("apply_scan_fix", {
        client: finding.fix_action.client || "",
        server: finding.fix_action.server || "",
        actionType: finding.fix_action.action_type,
      });
      setError(null);
      alert(result);
    } catch (e) {
      setError(String(e));
    } finally {
      setFixingAction(null);
    }
  }

  async function askClawAboutFinding(findingKey: string, finding: ScanFinding, followUpQuestion?: string) {
    setAskClawState((prev) => {
      const next = new Map(prev);
      const existing = next.get(findingKey);
      next.set(findingKey, { loading: true, response: existing?.response ?? null, followUp: "" });
      return next;
    });

    const prompt = followUpQuestion
      ? followUpQuestion
      : `Analyze this security finding:\nSeverity: ${finding.severity} | Category: ${finding.category}\nFinding: ${finding.description}\nAffected: ${finding.affected_resource}\nSuggested fix: ${finding.fix_suggestion}\n\nIs this a real risk? What should I do?`;

    const contextJson = JSON.stringify({
      active_page: "scanner",
      finding_severity: finding.severity,
      finding_category: finding.category,
      finding_description: finding.description,
      affected_resource: finding.affected_resource,
    });

    try {
      const response = await invoke<string>("ask_claw_ai", { input: prompt, contextJson });
      setAskClawState((prev) => {
        const next = new Map(prev);
        next.set(findingKey, { loading: false, response, followUp: "" });
        return next;
      });
    } catch (e) {
      setAskClawState((prev) => {
        const next = new Map(prev);
        next.set(findingKey, { loading: false, response: `Error: ${String(e)}`, followUp: "" });
        return next;
      });
    }
  }

  function toggleAskClaw(findingKey: string) {
    setAskClawState((prev) => {
      const next = new Map(prev);
      if (next.has(findingKey)) next.delete(findingKey);
      else next.set(findingKey, { loading: false, response: null, followUp: "" });
      return next;
    });
  }

  function statusBadge(status: string) {
    const styles: Record<string, string> = {
      running: "bg-[var(--color-accent)]/20 text-[var(--color-accent)]",
      completed: "bg-[var(--color-success)]/20 text-[var(--color-success)]",
      failed: "bg-[var(--color-danger)]/20 text-[var(--color-danger)]",
    };
    return (
      <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${styles[status] || ""}`}>
        {status.charAt(0).toUpperCase() + status.slice(1)}
      </span>
    );
  }

  function severityBadge(severity: string) {
    const config = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.low;
    return (
      <span className={`px-2 py-0.5 rounded text-xs font-bold ${config.color} ${config.bg}`}>
        {config.label}
      </span>
    );
  }

  function moduleStatusIcon(status: string, findingsCount: number) {
    if (status === "completed" && findingsCount === 0)
      return <span className="text-[var(--color-success)] text-lg">&#10003;</span>;
    if (status === "completed" && findingsCount > 0)
      return <span className="text-[var(--color-warning)] text-lg">&#9888;</span>;
    if (status === "skipped")
      return <span className="text-[var(--color-text-secondary)] text-lg">&#8722;</span>;
    return <span className="text-[var(--color-text-secondary)] text-lg">&#8226;</span>;
  }

  const isScanning = activeScan?.status === "running";

  const sortedFindings = (findings: ScanFinding[]) =>
    [...findings].sort(
      (a, b) =>
        (SEVERITY_CONFIG[a.severity]?.order ?? 99) -
        (SEVERITY_CONFIG[b.severity]?.order ?? 99)
    );

  return (
    <div className="space-y-6">
      {error && (
        <div className="rounded-lg border border-[var(--color-danger)] bg-[var(--color-danger)]/10 p-4 text-sm text-[var(--color-danger)]">
          {error}
        </div>
      )}

      {/* Scan Configuration */}
      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">Scan Modules</h2>
          <div className="flex items-center gap-3">
            <button
              onClick={() => setSelectedModules(new Set(MODULES.map((m) => m.id)))}
              disabled={isScanning || selectedModules.size === MODULES.length}
              className="text-xs text-[var(--color-accent)] hover:underline disabled:opacity-50"
            >
              Full Scan
            </button>
            <button
              onClick={() => {
                if (selectedModules.size === MODULES.length) setSelectedModules(new Set());
                else setSelectedModules(new Set(MODULES.map((m) => m.id)));
              }}
              disabled={isScanning}
              className="text-xs text-[var(--color-accent)] hover:underline disabled:opacity-50"
            >
              {selectedModules.size === MODULES.length ? "Deselect All" : "Select All"}
            </button>
          </div>
        </div>

        {/* MCP Security group */}
        <div className="space-y-2">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-[var(--color-text-secondary)]">
            MCP Security
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
            {MODULES.filter((m) => m.group === "mcp").map((mod) => (
              <button
                key={mod.id}
                onClick={() => toggleModule(mod.id)}
                disabled={isScanning}
                className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm border transition-colors text-left ${
                  selectedModules.has(mod.id)
                    ? "border-[var(--color-accent)] bg-[var(--color-accent)]/10 text-[var(--color-accent)]"
                    : "border-[var(--color-border)] text-[var(--color-text-secondary)] hover:border-[var(--color-text-secondary)]"
                }`}
              >
                <span
                  className={`w-4 h-4 rounded border flex items-center justify-center text-xs ${
                    selectedModules.has(mod.id)
                      ? "border-[var(--color-accent)] bg-[var(--color-accent)] text-white"
                      : "border-[var(--color-border)]"
                  }`}
                >
                  {selectedModules.has(mod.id) ? "\u2713" : ""}
                </span>
                {mod.label}
              </button>
            ))}
          </div>
        </div>

        {/* System Security group */}
        <div className="space-y-2">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-[var(--color-text-secondary)]">
            System Security
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
            {MODULES.filter((m) => m.group === "system").map((mod) => (
              <button
                key={mod.id}
                onClick={() => toggleModule(mod.id)}
                disabled={isScanning}
                className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm border transition-colors text-left ${
                  selectedModules.has(mod.id)
                    ? "border-[var(--color-accent)] bg-[var(--color-accent)]/10 text-[var(--color-accent)]"
                    : "border-[var(--color-border)] text-[var(--color-text-secondary)] hover:border-[var(--color-text-secondary)]"
                }`}
              >
                <span
                  className={`w-4 h-4 rounded border flex items-center justify-center text-xs ${
                    selectedModules.has(mod.id)
                      ? "border-[var(--color-accent)] bg-[var(--color-accent)] text-white"
                      : "border-[var(--color-border)]"
                  }`}
                >
                  {selectedModules.has(mod.id) ? "\u2713" : ""}
                </span>
                {mod.label}
              </button>
            ))}
          </div>
        </div>

        <button
          onClick={startScan}
          disabled={isScanning || selectedModules.size === 0}
          className="w-full px-4 py-2.5 rounded-lg bg-[var(--color-accent)] text-white text-sm font-medium hover:bg-[var(--color-accent-hover)] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {isScanning ? "Scanning..." : `Run Security Scan (${selectedModules.size} modules)`}
        </button>
      </div>

      {/* Active Scan Progress with Live Feed */}
      {activeScan && (
        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold">
              {isScanning ? "Scanning..." : "Scan Complete"}
            </h2>
            <div className="flex items-center gap-3">
              {statusBadge(activeScan.status)}
              <span className="text-sm text-[var(--color-text-secondary)]">{elapsed}s</span>
            </div>
          </div>

          <div>
            <div className="flex justify-between text-sm mb-1">
              <span className="text-[var(--color-text-secondary)]">
                {activeScan.current_module
                  ? `Running: ${activeScan.current_module}`
                  : isScanning ? "Initializing..." : "Done"}
              </span>
              <span>
                Modules: {activeScan.modules_completed}/{activeScan.modules_total}
                {" \u00B7 "}
                {Math.round(activeScan.progress_percent)}%
              </span>
            </div>
            <div className="w-full h-2 rounded-full bg-[var(--color-bg-primary)]">
              <div
                className="h-2 rounded-full bg-[var(--color-accent)] transition-all"
                style={{ width: `${activeScan.progress_percent}%` }}
              />
            </div>
          </div>

          <div className="flex gap-6 text-sm">
            <div>
              <span className="text-[var(--color-text-secondary)]">Elapsed: </span>
              <span className="font-medium">{elapsed}s</span>
            </div>
            <div>
              <span className="text-[var(--color-text-secondary)]">Findings: </span>
              <span className={`font-medium ${activeScan.findings_count > 0 ? "text-[var(--color-warning)]" : "text-[var(--color-success)]"}`}>
                {activeScan.findings_count}
              </span>
            </div>
          </div>

          {/* Live Activity Feed + Live Findings split */}
          {(activity.length > 0 || liveFindings.length > 0) && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {/* Activity Feed */}
              <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-primary)] overflow-hidden">
                <div className="px-3 py-2 border-b border-[var(--color-border)] bg-[var(--color-bg-tertiary)]">
                  <span className="text-xs font-semibold uppercase tracking-wider text-[var(--color-text-secondary)]">
                    Activity Feed
                  </span>
                </div>
                <div ref={activityFeedRef} className="max-h-48 overflow-y-auto p-2 space-y-1">
                  {activity.map((item) => (
                    <div
                      key={item.id}
                      className={`text-xs px-2 py-1 rounded ${
                        item.type === "finding"
                          ? "bg-[var(--color-bg-secondary)]"
                          : item.type === "stage"
                            ? "text-[var(--color-success)]"
                            : "text-[var(--color-text-secondary)]"
                      }`}
                    >
                      <span className="opacity-50 mr-1">
                        {new Date(item.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                      </span>
                      {item.message}
                    </div>
                  ))}
                  {isScanning && (
                    <div className="text-xs px-2 py-1 text-[var(--color-text-secondary)] animate-pulse">
                      Scanning...
                    </div>
                  )}
                </div>
              </div>

              {/* Live Findings */}
              <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-primary)] overflow-hidden">
                <div className="px-3 py-2 border-b border-[var(--color-border)] bg-[var(--color-bg-tertiary)]">
                  <span className="text-xs font-semibold uppercase tracking-wider text-[var(--color-text-secondary)]">
                    Live Findings ({liveFindings.length})
                  </span>
                </div>
                <div className="max-h-48 overflow-y-auto p-2 space-y-1">
                  {liveFindings.length === 0 ? (
                    <div className="text-xs text-[var(--color-text-secondary)] px-2 py-1">
                      {isScanning ? "No findings yet..." : "No findings detected"}
                    </div>
                  ) : (
                    liveFindings.map((f) => {
                      const cfg = SEVERITY_CONFIG[f.severity] || SEVERITY_CONFIG.low;
                      return (
                        <div key={f.id} className="text-xs px-2 py-1.5 rounded bg-[var(--color-bg-secondary)] flex items-start gap-2">
                          <span className={`px-1.5 py-0.5 rounded font-bold shrink-0 ${cfg.color} ${cfg.bg}`}>
                            {cfg.label}
                          </span>
                          <div className="min-w-0">
                            <div className="truncate font-medium">{f.title}</div>
                            <div className="text-[var(--color-text-secondary)] truncate">{f.stage}</div>
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Scan Results */}
      {scanResult && <QuickScanResults
        scanResult={scanResult}
        expandedModules={expandedModules}
        toggleExpanded={toggleExpanded}
        sortedFindings={sortedFindings}
        severityBadge={severityBadge}
        moduleStatusIcon={moduleStatusIcon}
        applyFix={applyFix}
        fixingAction={fixingAction}
        askClawState={askClawState}
        toggleAskClaw={toggleAskClaw}
        askClawAboutFinding={askClawAboutFinding}
        setAskClawState={setAskClawState}
      />}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Quick Scan Results (shared between QuickScanTab and ScanHistoryTab)
// ---------------------------------------------------------------------------

function QuickScanResults({
  scanResult,
  expandedModules,
  toggleExpanded,
  sortedFindings,
  severityBadge,
  moduleStatusIcon,
  applyFix,
  fixingAction,
  askClawState,
  toggleAskClaw,
  askClawAboutFinding,
  setAskClawState,
}: {
  scanResult: ScanResult;
  expandedModules: Set<string>;
  toggleExpanded: (id: string) => void;
  sortedFindings: (findings: ScanFinding[]) => ScanFinding[];
  severityBadge: (severity: string) => React.ReactNode;
  moduleStatusIcon: (status: string, count: number) => React.ReactNode;
  applyFix: (finding: ScanFinding) => void;
  fixingAction: string | null;
  askClawState: Map<string, AskClawEntry>;
  toggleAskClaw: (key: string) => void;
  askClawAboutFinding: (key: string, finding: ScanFinding, followUp?: string) => void;
  setAskClawState: React.Dispatch<React.SetStateAction<Map<string, AskClawEntry>>>;
}) {
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Results</h2>
        <div className="flex items-center gap-3 text-sm">
          {scanResult.critical_count > 0 && (
            <span className="text-red-400 font-medium">{scanResult.critical_count} Critical</span>
          )}
          {scanResult.high_count > 0 && (
            <span className="text-orange-400 font-medium">{scanResult.high_count} High</span>
          )}
          {scanResult.medium_count > 0 && (
            <span className="text-yellow-400 font-medium">{scanResult.medium_count} Medium</span>
          )}
          {scanResult.low_count > 0 && (
            <span className="text-blue-400 font-medium">{scanResult.low_count} Low</span>
          )}
          <span className="text-xs text-[var(--color-text-secondary)]">
            {scanResult.completed_at ? new Date(scanResult.completed_at).toLocaleString() : ""}
          </span>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-3">
        <SeverityCard label="Critical" count={scanResult.critical_count} color="red" />
        <SeverityCard label="High" count={scanResult.high_count} color="orange" />
        <SeverityCard label="Medium" count={scanResult.medium_count} color="yellow" />
        <SeverityCard label="Low" count={scanResult.low_count} color="blue" />
      </div>

      {/* Module Results */}
      <div className="space-y-2">
        {scanResult.modules.map((mod) => (
          <div
            key={mod.module_id}
            className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] overflow-hidden"
          >
            <button
              onClick={() => toggleExpanded(mod.module_id)}
              className="w-full flex items-center justify-between px-4 py-3 hover:bg-[var(--color-bg-tertiary)] transition-colors"
            >
              <div className="flex items-center gap-3">
                {moduleStatusIcon(mod.status, mod.findings.length)}
                <span className="font-medium text-sm">{mod.module_name}</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs text-[var(--color-text-secondary)]">{mod.summary}</span>
                {mod.findings.length > 0 && (
                  <span
                    className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                      mod.findings.some((f) => f.severity === "critical")
                        ? "bg-red-500/20 text-red-400"
                        : mod.findings.some((f) => f.severity === "high")
                          ? "bg-orange-500/20 text-orange-400"
                          : "bg-yellow-500/20 text-yellow-400"
                    }`}
                  >
                    {mod.findings.length}
                  </span>
                )}
                <span className={`text-[var(--color-text-secondary)] transition-transform ${expandedModules.has(mod.module_id) ? "rotate-180" : ""}`}>
                  &#9660;
                </span>
              </div>
            </button>

            {expandedModules.has(mod.module_id) && (
              <div className="border-t border-[var(--color-border)]">
                {mod.findings.length === 0 ? (
                  <div className="px-4 py-3 text-sm text-[var(--color-success)]">No issues found</div>
                ) : (
                  <div className="divide-y divide-[var(--color-border)]">
                    {sortedFindings(mod.findings).map((finding, idx) => {
                      const findingKey = `${mod.module_id}-${idx}`;
                      const clawEntry = askClawState.get(findingKey);
                      return (
                        <div key={idx} className="px-4 py-3 space-y-2">
                          <div className="flex items-start justify-between gap-3">
                            <div className="flex items-center gap-2 min-w-0 flex-wrap">
                              {severityBadge(finding.severity)}
                              <span className="px-1.5 py-0.5 rounded text-xs bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)]">
                                {finding.category}
                              </span>
                              <span className="text-sm font-medium truncate">{finding.description}</span>
                            </div>
                            <button
                              onClick={() => toggleAskClaw(findingKey)}
                              className={`shrink-0 px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                                clawEntry
                                  ? "bg-purple-500/20 text-purple-400"
                                  : "bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] hover:text-purple-400 hover:bg-purple-500/10"
                              }`}
                            >
                              Ask Claw
                            </button>
                          </div>
                          <div className="pl-0 space-y-1">
                            <div className="text-xs text-[var(--color-text-secondary)]">
                              <span className="font-medium">Resource:</span>{" "}
                              <span className="font-mono">{finding.affected_resource}</span>
                            </div>
                            <div className="text-xs text-[var(--color-text-secondary)]">
                              <span className="font-medium">Fix:</span> {finding.fix_suggestion}
                            </div>
                            {finding.fix_action && (
                              <button
                                onClick={() => applyFix(finding)}
                                disabled={fixingAction === `${finding.fix_action.action_type}:${finding.affected_resource}`}
                                className="mt-1 px-3 py-1 rounded text-xs font-medium bg-[var(--color-accent)]/20 text-[var(--color-accent)] hover:bg-[var(--color-accent)]/30 disabled:opacity-50 transition-colors"
                              >
                                {fixingAction === `${finding.fix_action.action_type}:${finding.affected_resource}`
                                  ? "Applying..."
                                  : finding.fix_action.action_type === "wrap_server" ? "Wrap Server" : "Apply Fix"}
                              </button>
                            )}
                          </div>

                          {/* Ask Claw inline panel */}
                          {clawEntry && (
                            <AskClawPanel
                              findingKey={findingKey}
                              finding={finding}
                              entry={clawEntry}
                              onAnalyze={askClawAboutFinding}
                              setAskClawState={setAskClawState}
                            />
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Ask Claw inline panel (reusable)
// ---------------------------------------------------------------------------

function AskClawPanel({
  findingKey,
  finding,
  entry,
  onAnalyze,
  setAskClawState,
}: {
  findingKey: string;
  finding: ScanFinding;
  entry: AskClawEntry;
  onAnalyze: (key: string, finding: ScanFinding, followUp?: string) => void;
  setAskClawState: React.Dispatch<React.SetStateAction<Map<string, AskClawEntry>>>;
}) {
  return (
    <div className="mt-2 rounded-lg border border-purple-500/30 bg-purple-500/5 p-3 space-y-2">
      <div className="flex items-center gap-2">
        <span className="text-xs font-semibold text-purple-400">Ask Claw AI</span>
        {entry.loading && (
          <span className="text-xs text-purple-400/60 animate-pulse">Analyzing...</span>
        )}
      </div>

      {!entry.response && !entry.loading && (
        <button
          onClick={() => onAnalyze(findingKey, finding)}
          className="px-3 py-1.5 rounded text-xs font-medium bg-purple-500/20 text-purple-400 hover:bg-purple-500/30 transition-colors"
        >
          Analyze this finding
        </button>
      )}

      {entry.response && (
        <div className="text-xs text-[var(--color-text-primary)] whitespace-pre-wrap leading-relaxed bg-[var(--color-bg-secondary)] rounded p-2">
          {entry.response}
        </div>
      )}

      {entry.response && (
        <div className="flex gap-2">
          <input
            type="text"
            placeholder="Ask a follow-up question..."
            value={entry.followUp}
            onChange={(e) => {
              const val = e.target.value;
              setAskClawState((prev) => {
                const next = new Map(prev);
                const existing = next.get(findingKey);
                if (existing) next.set(findingKey, { ...existing, followUp: val });
                return next;
              });
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter" && entry.followUp.trim()) {
                onAnalyze(findingKey, finding, entry.followUp.trim());
              }
            }}
            disabled={entry.loading}
            className="flex-1 px-2 py-1 rounded text-xs bg-[var(--color-bg-primary)] border border-[var(--color-border)] text-[var(--color-text-primary)] placeholder-[var(--color-text-secondary)] disabled:opacity-50"
          />
          <button
            onClick={() => {
              if (entry.followUp.trim()) onAnalyze(findingKey, finding, entry.followUp.trim());
            }}
            disabled={entry.loading || !entry.followUp.trim()}
            className="px-3 py-1 rounded text-xs font-medium bg-purple-500/20 text-purple-400 hover:bg-purple-500/30 disabled:opacity-50 transition-colors"
          >
            Send
          </button>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Scan History Tab
// ---------------------------------------------------------------------------

function ScanHistoryTab() {
  const scanHistory = useScanStore((s) => s.scanHistory);
  const [selectedEntry, setSelectedEntry] = useState<ScanHistoryEntry | null>(null);
  const [loadedResult, setLoadedResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedModules, setExpandedModules] = useState<Set<string>>(new Set());
  const [fixingAction, setFixingAction] = useState<string | null>(null);
  const [askClawState, setAskClawState] = useState<Map<string, AskClawEntry>>(new Map());

  async function selectEntry(entry: ScanHistoryEntry) {
    if (selectedEntry?.scan_id === entry.scan_id) {
      setSelectedEntry(null);
      setLoadedResult(null);
      return;
    }
    setSelectedEntry(entry);
    setLoadedResult(null);
    setError(null);
    setAskClawState(new Map());
    setLoading(true);
    try {
      if (entry.scan_type === "quick") {
        const result = await invoke<ScanResult>("get_scan_results", { scanId: entry.scan_id });
        setLoadedResult(result);
        const withFindings = new Set(
          result.modules.filter((m) => m.findings.length > 0).map((m) => m.module_id)
        );
        setExpandedModules(withFindings);
      } else {
        // AI scan results use a different structure; just link back
        setError("View AI scan results from the AI Scan tab.");
      }
    } catch (e) {
      setError(`Could not load results: ${String(e)}`);
    } finally {
      setLoading(false);
    }
  }

  function toggleExpanded(moduleId: string) {
    setExpandedModules((prev) => {
      const next = new Set(prev);
      if (next.has(moduleId)) next.delete(moduleId);
      else next.add(moduleId);
      return next;
    });
  }

  async function applyFix(finding: ScanFinding) {
    if (!finding.fix_action) return;
    const key = `${finding.fix_action.action_type}:${finding.affected_resource}`;
    setFixingAction(key);
    try {
      const result = await invoke<string>("apply_scan_fix", {
        client: finding.fix_action.client || "",
        server: finding.fix_action.server || "",
        actionType: finding.fix_action.action_type,
      });
      alert(result);
    } catch (e) {
      setError(String(e));
    } finally {
      setFixingAction(null);
    }
  }

  async function askClawAboutFinding(findingKey: string, finding: ScanFinding, followUpQuestion?: string) {
    setAskClawState((prev) => {
      const next = new Map(prev);
      const existing = next.get(findingKey);
      next.set(findingKey, { loading: true, response: existing?.response ?? null, followUp: "" });
      return next;
    });

    const prompt = followUpQuestion
      ? followUpQuestion
      : `Analyze this security finding:\nSeverity: ${finding.severity} | Category: ${finding.category}\nFinding: ${finding.description}\nAffected: ${finding.affected_resource}\nSuggested fix: ${finding.fix_suggestion}\n\nIs this a real risk? What should I do?`;

    const contextJson = JSON.stringify({
      active_page: "scanner",
      finding_severity: finding.severity,
      finding_category: finding.category,
      finding_description: finding.description,
      affected_resource: finding.affected_resource,
    });

    try {
      const response = await invoke<string>("ask_claw_ai", { input: prompt, contextJson });
      setAskClawState((prev) => {
        const next = new Map(prev);
        next.set(findingKey, { loading: false, response, followUp: "" });
        return next;
      });
    } catch (e) {
      setAskClawState((prev) => {
        const next = new Map(prev);
        next.set(findingKey, { loading: false, response: `Error: ${String(e)}`, followUp: "" });
        return next;
      });
    }
  }

  function toggleAskClaw(findingKey: string) {
    setAskClawState((prev) => {
      const next = new Map(prev);
      if (next.has(findingKey)) next.delete(findingKey);
      else next.set(findingKey, { loading: false, response: null, followUp: "" });
      return next;
    });
  }

  function severityBadge(severity: string) {
    const config = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.low;
    return (
      <span className={`px-2 py-0.5 rounded text-xs font-bold ${config.color} ${config.bg}`}>
        {config.label}
      </span>
    );
  }

  function moduleStatusIcon(status: string, findingsCount: number) {
    if (status === "completed" && findingsCount === 0)
      return <span className="text-[var(--color-success)] text-lg">&#10003;</span>;
    if (status === "completed" && findingsCount > 0)
      return <span className="text-[var(--color-warning)] text-lg">&#9888;</span>;
    if (status === "skipped")
      return <span className="text-[var(--color-text-secondary)] text-lg">&#8722;</span>;
    return <span className="text-[var(--color-text-secondary)] text-lg">&#8226;</span>;
  }

  const sortedFindings = (findings: ScanFinding[]) =>
    [...findings].sort(
      (a, b) =>
        (SEVERITY_CONFIG[a.severity]?.order ?? 99) -
        (SEVERITY_CONFIG[b.severity]?.order ?? 99)
    );

  function statusBadge(status: string) {
    const styles: Record<string, string> = {
      running: "bg-[var(--color-accent)]/20 text-[var(--color-accent)]",
      completed: "bg-[var(--color-success)]/20 text-[var(--color-success)]",
      failed: "bg-[var(--color-danger)]/20 text-[var(--color-danger)]",
    };
    return (
      <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${styles[status] || ""}`}>
        {status.charAt(0).toUpperCase() + status.slice(1)}
      </span>
    );
  }

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold">Scan History</h2>

      {scanHistory.length === 0 ? (
        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-6 text-center">
          <p className="text-sm text-[var(--color-text-secondary)]">
            No scans recorded yet. Run a Quick Scan or AI Scan to see history here.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {scanHistory.map((entry) => (
            <div key={entry.scan_id}>
              <button
                onClick={() => selectEntry(entry)}
                className={`w-full rounded-lg border bg-[var(--color-bg-secondary)] px-4 py-3 text-left transition-colors hover:bg-[var(--color-bg-tertiary)] ${
                  selectedEntry?.scan_id === entry.scan_id
                    ? "border-[var(--color-accent)]"
                    : "border-[var(--color-border)]"
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    {statusBadge(entry.status)}
                    <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${
                      entry.scan_type === "ai"
                        ? "bg-[var(--color-accent)]/20 text-[var(--color-accent)]"
                        : "bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)]"
                    }`}>
                      {entry.scan_type === "ai" ? "AI" : "Quick"}
                    </span>
                    <span className="text-sm font-mono text-[var(--color-text-primary)]">
                      {entry.scan_id.slice(0, 16)}
                    </span>
                  </div>
                  <div className="flex items-center gap-4 text-sm text-[var(--color-text-secondary)]">
                    <span className={entry.findings_count > 0 ? "text-[var(--color-warning)] font-medium" : ""}>
                      {entry.findings_count} findings
                    </span>
                    <span>{new Date(entry.started_at).toLocaleString()}</span>
                    <span className={`transition-transform ${selectedEntry?.scan_id === entry.scan_id ? "rotate-180" : ""}`}>
                      &#9660;
                    </span>
                  </div>
                </div>
              </button>

              {/* Expanded results */}
              {selectedEntry?.scan_id === entry.scan_id && (
                <div className="mt-1 ml-4 border-l-2 border-[var(--color-accent)]/30 pl-4 pb-2">
                  {loading && (
                    <div className="py-4 text-sm text-[var(--color-text-secondary)] animate-pulse">
                      Loading scan results...
                    </div>
                  )}
                  {error && (
                    <div className="py-3 text-sm text-[var(--color-text-secondary)]">{error}</div>
                  )}
                  {loadedResult && (
                    <QuickScanResults
                      scanResult={loadedResult}
                      expandedModules={expandedModules}
                      toggleExpanded={toggleExpanded}
                      sortedFindings={sortedFindings}
                      severityBadge={severityBadge}
                      moduleStatusIcon={moduleStatusIcon}
                      applyFix={applyFix}
                      fixingAction={fixingAction}
                      askClawState={askClawState}
                      toggleAskClaw={toggleAskClaw}
                      askClawAboutFinding={askClawAboutFinding}
                      setAskClawState={setAskClawState}
                    />
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Severity Card
// ---------------------------------------------------------------------------

function SeverityCard({ label, count, color }: { label: string; count: number; color: string }) {
  const colorMap: Record<string, string> = {
    red: "text-red-400 border-red-500/30 bg-red-500/5",
    orange: "text-orange-400 border-orange-500/30 bg-orange-500/5",
    yellow: "text-yellow-400 border-yellow-500/30 bg-yellow-500/5",
    blue: "text-blue-400 border-blue-500/30 bg-blue-500/5",
  };
  return (
    <div className={`rounded-lg border p-3 text-center ${colorMap[color] || ""}`}>
      <div className="text-2xl font-bold">{count}</div>
      <div className="text-xs opacity-80">{label}</div>
    </div>
  );
}
