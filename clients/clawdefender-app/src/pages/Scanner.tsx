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
import { Icon, Badge, Btn, Card } from "../components/design";

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
  ai_analysis?: string;
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
  scan_type?: string;
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

const SEVERITY_CONFIG: Record<string, { color: string; bg: string; label: string; order: number; cssVar: string }> = {
  critical: { color: "text-red-400", bg: "bg-red-500/20", label: "CRITICAL", order: 0, cssVar: "var(--red)" },
  high: { color: "text-orange-400", bg: "bg-orange-500/20", label: "HIGH", order: 1, cssVar: "var(--amber)" },
  medium: { color: "text-yellow-400", bg: "bg-yellow-500/20", label: "MEDIUM", order: 2, cssVar: "var(--amber)" },
  low: { color: "text-blue-400", bg: "bg-blue-500/20", label: "LOW", order: 3, cssVar: "var(--accent)" },
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

    listen<ScanFindingEvent>("rookbot://scan-finding", (event) => {
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
        message: `${p.severity.toUpperCase()}: ${p.title}`,
        severity: p.severity,
      });
    }).then((fn) => unlisteners.push(fn));

    listen<ScanStageCompleteEvent>("rookbot://scan-stage-complete", (event) => {
      const p = event.payload;
      if (currentIdRef.current && p.scan_id !== currentIdRef.current) return;
      addQuickScanActivity({
        type: "stage",
        message: `${p.stage_name} completed (${p.stages_completed}/${p.stages_total})`,
      });
    }).then((fn) => unlisteners.push(fn));

    listen<ScanCompleteEvent>("rookbot://scan-complete", (event) => {
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

  const tabs: { key: typeof activeTab; label: string; icon: string }[] = [
    { key: "ai", label: "AI Scan", icon: "sparkles" },
    { key: "quick", label: "Security Scan", icon: "shield" },
    { key: "history", label: "History", icon: "history" },
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      {/* Header */}
      <div style={{ padding: "18px 24px", borderBottom: "1px solid var(--line)", display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{
          width: 38, height: 38, borderRadius: 10,
          background: "var(--violet-soft)",
          border: "1px solid color-mix(in oklch, var(--violet) 30%, transparent)",
          display: "grid", placeItems: "center",
        }}>
          <Icon name="scan" size={18} color="var(--violet)" />
        </div>
        <div style={{ flex: 1 }}>
          <h1 style={{ margin: 0, fontSize: 17, fontWeight: 600, color: "var(--ink-0)" }}>Security Scanner</h1>
          <div style={{ fontSize: 11.5, color: "var(--ink-2)", marginTop: 2 }}>
            {cloudActive
              ? "Findings enriched with AI analysis"
              : localActive
                ? "Basic AI analysis available"
                : "AI analysis unavailable"}
          </div>
        </div>

        {/* Tab buttons */}
        <div style={{ display: "flex", gap: 2, background: "var(--bg-2)", borderRadius: 8, padding: 2 }}>
          {tabs.map((t) => (
            <button
              key={t.key}
              onClick={() => setActiveTab(t.key)}
              style={{
                display: "inline-flex", alignItems: "center", gap: 5,
                padding: "6px 12px", borderRadius: 6, fontSize: 12, fontWeight: 500,
                background: activeTab === t.key ? "var(--bg-0)" : "transparent",
                color: activeTab === t.key ? "var(--ink-0)" : "var(--ink-2)",
                border: activeTab === t.key ? "1px solid var(--line)" : "1px solid transparent",
                boxShadow: activeTab === t.key ? "0 1px 2px oklch(0 0 0 / 0.04)" : "none",
                cursor: "pointer",
              }}
            >
              <Icon name={t.icon} size={13} />
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab content */}
      <div style={{ flex: 1, overflow: "auto" }} className="cd-scroll">
        {activeTab === "ai" && <AiScanTab />}
        {activeTab === "quick" && <QuickScanTab />}
        {activeTab === "history" && <ScanHistoryTab />}
      </div>
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
    if (scanId) {
      addScanHistory({
        scan_id: scanId,
        scan_type: "ai",
        status: "completed",
        findings_count: 0,
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
    <div style={{ padding: 24 }}>
      {error && (
        <div style={{
          padding: 14, marginBottom: 16, borderRadius: 10,
          background: "var(--red-soft)", border: "1px solid color-mix(in oklch, var(--red) 30%, transparent)",
          fontSize: 12.5, color: "var(--red)",
        }}>
          {error}
        </div>
      )}

      {phase === "select" && (
        <Card title="AI-Powered Security Scan" action={<Badge color="var(--accent)" mono>AI</Badge>}>
          <p style={{ fontSize: 12.5, color: "var(--ink-2)", marginBottom: 16 }}>
            Choose a playbook to run an AI-driven security assessment. The AI agent will analyze
            your MCP configuration, system posture, and security policies using real tools and
            evidence collection.
          </p>
          <PlaybookSelector onStart={handleStartScan} disabled={starting} />
        </Card>
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
  const [cloudEnrich, setCloudEnrich] = useState(false);
  const { cloudActive } = useAiStatus();
  const activeScan = useScanStore((s) => s.quickScanActiveScan);
  const setActiveScan = useScanStore((s) => s.setQuickScanActiveScan);
  const scanResult = useScanStore((s) => s.quickScanResult);
  const setScanResult = useScanStore((s) => s.setQuickScanResult);
  const addScanHistory = useScanStore((s) => s.addScanHistory);
  const setQuickScanCurrentId = useScanStore((s) => s.setQuickScanCurrentId);
  const clearQuickScanLiveFeed = useScanStore((s) => s.clearQuickScanLiveFeed);
  const addQuickScanActivity = useScanStore((s) => s.addQuickScanActivity);

  const activity = useScanStore((s) => s.quickScanActivity);
  const liveFindings = useScanStore((s) => s.quickScanLiveFindings);

  const [elapsed, setElapsed] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [expandedModules, setExpandedModules] = useState<Set<string>>(new Set());
  const [fixingAction, setFixingAction] = useState<string | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const activityFeedRef = useRef<HTMLDivElement>(null);

  const [askClawState, setAskClawState] = useState<Map<string, AskClawEntry>>(new Map());
  const [enrichingKeys, setEnrichingKeys] = useState<Set<string>>(new Set());

  async function enrichFinding(moduleId: string, findingIndex: number) {
    const key = `${moduleId}-${findingIndex}`;
    setEnrichingKeys((prev) => new Set(prev).add(key));
    try {
      const analysis = await invoke<string>("enrich_scan_finding", {
        scanId: scanResult?.scan_id ?? "",
        moduleId,
        findingIndex,
      });
      // Update scanResult in-place so the AI analysis shows up
      if (scanResult) {
        const updated = { ...scanResult, modules: scanResult.modules.map((m) => {
          if (m.module_id !== moduleId) return m;
          return { ...m, findings: m.findings.map((f, i) =>
            i === findingIndex ? { ...f, ai_analysis: analysis } : f
          )};
        })};
        setScanResult(updated);
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setEnrichingKeys((prev) => {
        const next = new Set(prev);
        next.delete(key);
        return next;
      });
    }
  }

  useEffect(() => {
    if (activityFeedRef.current) {
      activityFeedRef.current.scrollTop = activityFeedRef.current.scrollHeight;
    }
  }, [activity]);

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
        cloudEnrich: cloudEnrich,
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
      const raw = await invoke<string>("ask_claw_ai", { input: prompt, contextJson });
      let message = raw;
      try {
        const parsed = JSON.parse(raw);
        message = parsed.message ?? parsed.explanation ?? raw;
      } catch { /* use raw string if not JSON */ }
      setAskClawState((prev) => {
        const next = new Map(prev);
        next.set(findingKey, { loading: false, response: message, followUp: "" });
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

  const isScanning = activeScan?.status === "running";
  const sortedFindings = (findings: ScanFinding[]) =>
    [...findings].sort(
      (a, b) =>
        (SEVERITY_CONFIG[a.severity]?.order ?? 99) -
        (SEVERITY_CONFIG[b.severity]?.order ?? 99)
    );

  const formatElapsed = (s: number) => {
    const m = Math.floor(s / 60);
    const sec = s % 60;
    return `${String(m).padStart(2, "0")}:${String(sec).padStart(2, "0")}`;
  };

  return (
    <div style={{ padding: 24 }}>
      {error && (
        <div style={{
          padding: 14, marginBottom: 16, borderRadius: 10,
          background: "var(--red-soft)", border: "1px solid color-mix(in oklch, var(--red) 30%, transparent)",
          fontSize: 12.5, color: "var(--red)",
        }}>
          {error}
        </div>
      )}

      {/* Active scan: 2-column layout */}
      {activeScan && isScanning ? (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 300px", gap: 0, height: "calc(100vh - 140px)" }}>
          {/* Left column: stages + feed + findings */}
          <div style={{ overflowY: "auto", paddingRight: 20 }} className="cd-scroll">
            {/* Stage cards */}
            <div style={{ display: "grid", gridTemplateColumns: `repeat(${Math.min(activeScan.modules_total, 5)}, 1fr)`, gap: 6, marginBottom: 18 }}>
              {MODULES.filter((m) => selectedModules.has(m.id)).slice(0, activeScan.modules_total).map((m, i) => {
                const isDone = i < activeScan.modules_completed;
                const isRunning = i === activeScan.modules_completed && activeScan.status === "running";
                return (
                  <div key={m.id} style={{
                    padding: "10px 12px",
                    background: "var(--bg-1)",
                    border: `1px solid ${isRunning ? "var(--accent-line)" : "var(--line)"}`,
                    borderRadius: 8,
                    position: "relative", overflow: "hidden",
                  }}>
                    {isRunning && <div className="cd-shimmer" style={{ position: "absolute", inset: 0 }} />}
                    <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
                      <div style={{
                        width: 16, height: 16, borderRadius: 999,
                        background: isDone ? "var(--green-soft)" : isRunning ? "var(--accent-soft)" : "var(--bg-3)",
                        border: `1px solid ${isDone ? "color-mix(in oklch, var(--green) 40%, transparent)" : isRunning ? "var(--accent-line)" : "var(--line)"}`,
                        display: "grid", placeItems: "center", fontSize: 9, fontFamily: "var(--font-mono)",
                        color: isDone ? "var(--green)" : "var(--ink-3)",
                      }}>
                        {isDone ? "\u2713" : i + 1}
                      </div>
                      <span style={{ fontSize: 10, color: "var(--ink-3)", fontFamily: "var(--font-mono)", textTransform: "uppercase", letterSpacing: 0.4 }}>
                        Stage {i + 1}
                      </span>
                    </div>
                    <div style={{ fontSize: 12, fontWeight: 500, color: "var(--ink-1)" }}>{m.label}</div>
                  </div>
                );
              })}
            </div>

            {/* Investigation feed */}
            <Card
              title="Investigation feed"
              action={<Badge color="var(--violet)" mono><span className="cd-pulse">&#9679;</span> live</Badge>}
              padded={false}
            >
              <div ref={activityFeedRef} className="cd-scroll" style={{ maxHeight: 280, overflowY: "auto", fontFamily: "var(--font-mono)", fontSize: 11.5, padding: "10px 14px" }}>
                {activity.map((item) => (
                  <div key={item.id} style={{ display: "flex", gap: 10, padding: "3px 0", color: "var(--ink-2)" }}>
                    <span style={{ color: "var(--ink-4)", width: 60, fontSize: 10, flexShrink: 0 }}>
                      {new Date(item.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                    </span>
                    <span style={{
                      width: 50, flexShrink: 0,
                      color: item.type === "finding" ? "var(--amber)" : item.type === "stage" ? "var(--green)" : "var(--accent)",
                    }}>
                      [{item.type === "finding" ? "FIND" : item.type === "stage" ? "DONE" : "INFO"}]
                    </span>
                    <span style={{ color: item.type === "finding" ? "var(--ink-0)" : "var(--ink-1)" }}>{item.message}</span>
                  </div>
                ))}
                {isScanning && (
                  <div style={{ display: "flex", gap: 10, padding: "3px 0", alignItems: "center" }}>
                    <span style={{ color: "var(--ink-4)", width: 60 }}>&mdash;</span>
                    <span style={{ width: 50, color: "var(--accent)" }}>[TOOL]</span>
                    <span style={{ color: "var(--ink-2)" }}>
                      {activeScan.current_module ? `analyzing ${activeScan.current_module}` : "initializing"}
                    </span>
                    <span className="cd-caret" />
                  </div>
                )}
              </div>
            </Card>

            {/* Live findings */}
            {liveFindings.length > 0 && (
              <div style={{ marginTop: 18 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
                  <h2 style={{ margin: 0, fontSize: 13, fontWeight: 600, color: "var(--ink-1)" }}>Findings</h2>
                  <Badge color="var(--ink-2)" mono>{liveFindings.length}</Badge>
                </div>
                <div style={{ display: "grid", gap: 8 }}>
                  {liveFindings.map((f) => {
                    const cfg = SEVERITY_CONFIG[f.severity] || SEVERITY_CONFIG.low;
                    return (
                      <div key={f.id} className="cd-slide-in" style={{
                        display: "flex", alignItems: "stretch", gap: 12, padding: 14,
                        background: "var(--bg-1)", border: "1px solid var(--line)", borderRadius: 10,
                      }}>
                        <div style={{ width: 3, borderRadius: 2, background: cfg.cssVar }} />
                        <div style={{ flex: 1 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                            <Badge color={cfg.cssVar}>{f.severity}</Badge>
                            <span style={{ fontSize: 12.5, fontWeight: 500, color: "var(--ink-0)" }}>{f.title}</span>
                          </div>
                          <div style={{ fontSize: 11.5, color: "var(--ink-2)" }}>{f.stage}</div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>

          {/* Side rail */}
          <aside style={{ borderLeft: "1px solid var(--line)", padding: 18, background: "var(--bg-1)", display: "grid", alignContent: "start", gap: 14 }}>
            <div>
              <div style={{ fontSize: 10, color: "var(--ink-3)", textTransform: "uppercase", letterSpacing: 0.5 }}>Elapsed</div>
              <div style={{ fontSize: 22, fontFamily: "var(--font-mono)", marginTop: 2 }}>{formatElapsed(elapsed)}</div>
            </div>
            <div>
              <div style={{ fontSize: 10, color: "var(--ink-3)", textTransform: "uppercase", letterSpacing: 0.5 }}>Modules</div>
              <div style={{ fontSize: 13, fontFamily: "var(--font-mono)", marginTop: 2 }}>
                {activeScan.modules_completed} / {activeScan.modules_total}
              </div>
              <div style={{ height: 4, background: "var(--bg-3)", borderRadius: 2, marginTop: 6, overflow: "hidden" }}>
                <div style={{ width: `${activeScan.progress_percent}%`, height: "100%", background: "var(--accent)", transition: "width 0.3s" }} />
              </div>
            </div>
            <div>
              <div style={{ fontSize: 10, color: "var(--ink-3)", textTransform: "uppercase", letterSpacing: 0.5 }}>Findings</div>
              <div style={{ fontSize: 13, fontFamily: "var(--font-mono)", marginTop: 2, color: activeScan.findings_count > 0 ? "var(--amber)" : "var(--green)" }}>
                {activeScan.findings_count}
              </div>
            </div>
            <div>
              <div style={{ fontSize: 10, color: "var(--ink-3)", textTransform: "uppercase", letterSpacing: 0.5 }}>Current</div>
              <div style={{ fontSize: 12, marginTop: 2, color: "var(--ink-1)" }}>
                {activeScan.current_module || "Initializing..."}
              </div>
            </div>
            <div style={{ borderTop: "1px solid var(--line-soft)", paddingTop: 14 }}>
              <Btn kind="ghost" icon="x" onClick={() => {
                if (timerRef.current) clearInterval(timerRef.current);
                timerRef.current = null;
                setActiveScan({ ...activeScan, status: "completed" as const });
              }}>
                Stop scan
              </Btn>
            </div>
          </aside>
        </div>
      ) : (
        /* Non-scanning state */
        <div style={{ display: "grid", gap: 16 }}>
          {/* Module selection */}
          <Card title="Scan Modules" action={
            <div style={{ display: "flex", gap: 8 }}>
              <Btn kind="ghost" size="sm" onClick={() => setSelectedModules(new Set(MODULES.map((m) => m.id)))} disabled={isScanning || selectedModules.size === MODULES.length}>
                Select all
              </Btn>
              <Btn kind="ghost" size="sm" onClick={() => setSelectedModules(new Set())} disabled={isScanning || selectedModules.size === 0}>
                Clear
              </Btn>
            </div>
          }>
            {/* MCP Security */}
            <div style={{ marginBottom: 14 }}>
              <div style={{ fontSize: 10, color: "var(--ink-3)", textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 8 }}>MCP Security</div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 6 }}>
                {MODULES.filter((m) => m.group === "mcp").map((mod) => (
                  <button key={mod.id} onClick={() => toggleModule(mod.id)} disabled={isScanning} style={{
                    display: "flex", alignItems: "center", gap: 8,
                    padding: "8px 12px", borderRadius: 8, fontSize: 12, fontWeight: 500,
                    background: selectedModules.has(mod.id) ? "var(--accent-soft)" : "var(--bg-2)",
                    border: `1px solid ${selectedModules.has(mod.id) ? "var(--accent-line)" : "var(--line)"}`,
                    color: selectedModules.has(mod.id) ? "var(--accent)" : "var(--ink-2)",
                    cursor: "pointer", textAlign: "left",
                  }}>
                    <div style={{
                      width: 16, height: 16, borderRadius: 4, border: `1px solid ${selectedModules.has(mod.id) ? "var(--accent)" : "var(--line)"}`,
                      background: selectedModules.has(mod.id) ? "var(--accent)" : "transparent",
                      display: "grid", placeItems: "center", fontSize: 10, color: "white",
                    }}>
                      {selectedModules.has(mod.id) && "\u2713"}
                    </div>
                    {mod.label}
                  </button>
                ))}
              </div>
            </div>

            {/* System Security */}
            <div>
              <div style={{ fontSize: 10, color: "var(--ink-3)", textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 8 }}>System Security</div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 6 }}>
                {MODULES.filter((m) => m.group === "system").map((mod) => (
                  <button key={mod.id} onClick={() => toggleModule(mod.id)} disabled={isScanning} style={{
                    display: "flex", alignItems: "center", gap: 8,
                    padding: "8px 12px", borderRadius: 8, fontSize: 12, fontWeight: 500,
                    background: selectedModules.has(mod.id) ? "var(--accent-soft)" : "var(--bg-2)",
                    border: `1px solid ${selectedModules.has(mod.id) ? "var(--accent-line)" : "var(--line)"}`,
                    color: selectedModules.has(mod.id) ? "var(--accent)" : "var(--ink-2)",
                    cursor: "pointer", textAlign: "left",
                  }}>
                    <div style={{
                      width: 16, height: 16, borderRadius: 4, border: `1px solid ${selectedModules.has(mod.id) ? "var(--accent)" : "var(--line)"}`,
                      background: selectedModules.has(mod.id) ? "var(--accent)" : "transparent",
                      display: "grid", placeItems: "center", fontSize: 10, color: "white",
                    }}>
                      {selectedModules.has(mod.id) && "\u2713"}
                    </div>
                    {mod.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Cloud enrichment toggle */}
            {cloudActive && (
              <div style={{
                marginTop: 16, padding: "10px 14px", borderRadius: 8,
                background: cloudEnrich ? "color-mix(in oklch, var(--violet) 8%, transparent)" : "var(--bg-2)",
                border: `1px solid ${cloudEnrich ? "color-mix(in oklch, var(--violet) 30%, transparent)" : "var(--line)"}`,
                display: "flex", alignItems: "center", gap: 10, cursor: "pointer",
              }} onClick={() => setCloudEnrich(!cloudEnrich)}>
                <div style={{
                  width: 18, height: 18, borderRadius: 4, flexShrink: 0,
                  border: `1px solid ${cloudEnrich ? "var(--violet)" : "var(--line)"}`,
                  background: cloudEnrich ? "var(--violet)" : "transparent",
                  display: "grid", placeItems: "center", fontSize: 11, color: "white",
                }}>
                  {cloudEnrich && "\u2713"}
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 12, fontWeight: 500, color: cloudEnrich ? "var(--violet)" : "var(--ink-1)" }}>
                    <Icon name="sparkles" size={12} color={cloudEnrich ? "var(--violet)" : "var(--ink-2)"} />{" "}
                    Enrich with Cloud AI
                  </div>
                  <div style={{ fontSize: 10.5, color: "var(--ink-3)", marginTop: 2 }}>
                    Cloud AI will analyze critical &amp; high severity findings for false-positive assessment
                  </div>
                </div>
              </div>
            )}

            <div style={{ marginTop: 16 }}>
              <Btn
                kind="primary"
                icon="play"
                onClick={startScan}
                disabled={isScanning || selectedModules.size === 0}
                style={{ width: "100%", justifyContent: "center" }}
              >
                {isScanning ? "Scanning..." : `Run Security Scan (${selectedModules.size} modules)`}
              </Btn>
            </div>
          </Card>

          {/* Completed scan results */}
          {scanResult && (
            <QuickScanResults
              scanResult={scanResult}
              expandedModules={expandedModules}
              toggleExpanded={toggleExpanded}
              sortedFindings={sortedFindings}
              applyFix={applyFix}
              fixingAction={fixingAction}
              askClawState={askClawState}
              toggleAskClaw={toggleAskClaw}
              askClawAboutFinding={askClawAboutFinding}
              setAskClawState={setAskClawState}
              onEnrichFinding={enrichFinding}
              enrichingKeys={enrichingKeys}
            />
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Quick Scan Results
// ---------------------------------------------------------------------------

function QuickScanResults({
  scanResult,
  expandedModules,
  toggleExpanded,
  sortedFindings,
  applyFix,
  fixingAction,
  askClawState,
  toggleAskClaw,
  askClawAboutFinding,
  setAskClawState,
  onEnrichFinding,
  enrichingKeys,
}: {
  scanResult: ScanResult;
  expandedModules: Set<string>;
  toggleExpanded: (id: string) => void;
  sortedFindings: (findings: ScanFinding[]) => ScanFinding[];
  applyFix: (finding: ScanFinding) => void;
  fixingAction: string | null;
  askClawState: Map<string, AskClawEntry>;
  toggleAskClaw: (key: string) => void;
  askClawAboutFinding: (key: string, finding: ScanFinding, followUp?: string) => void;
  setAskClawState: React.Dispatch<React.SetStateAction<Map<string, AskClawEntry>>>;
  onEnrichFinding?: (moduleId: string, findingIndex: number) => void;
  enrichingKeys?: Set<string>;
}) {
  return (
    <div style={{ display: "grid", gap: 14 }}>
      {/* Summary header */}
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <h2 style={{ margin: 0, fontSize: 13, fontWeight: 600, color: "var(--ink-1)" }}>Results</h2>
        <Badge color="var(--ink-2)" mono>{scanResult.total_findings} findings</Badge>
        {scanResult.total_findings > 0 && (
          <Btn size="sm" kind="accent" style={{ marginLeft: "auto" }} icon="check">
            Apply all safe fixes
          </Btn>
        )}
      </div>

      {/* Severity summary */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8 }}>
        <SeverityCard label="Critical" count={scanResult.critical_count} color="var(--red)" />
        <SeverityCard label="High" count={scanResult.high_count} color="var(--amber)" />
        <SeverityCard label="Medium" count={scanResult.medium_count} color="var(--amber)" />
        <SeverityCard label="Low" count={scanResult.low_count} color="var(--accent)" />
      </div>

      {/* Module results */}
      {scanResult.modules.map((mod) => (
        <div key={mod.module_id} style={{
          background: "var(--bg-1)", border: "1px solid var(--line)", borderRadius: 10, overflow: "hidden",
        }}>
          <button onClick={() => toggleExpanded(mod.module_id)} style={{
            width: "100%", display: "flex", alignItems: "center", justifyContent: "space-between",
            padding: "12px 16px", cursor: "pointer", background: "transparent", border: "none",
            color: "var(--ink-0)",
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span style={{
                color: mod.status === "completed" && mod.findings.length === 0 ? "var(--green)" : mod.findings.length > 0 ? "var(--amber)" : "var(--ink-3)",
                fontSize: 16,
              }}>
                {mod.status === "completed" && mod.findings.length === 0 ? "\u2713" : mod.findings.length > 0 ? "\u26A0" : "\u2022"}
              </span>
              <span style={{ fontSize: 13, fontWeight: 500 }}>{mod.module_name}</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span style={{ fontSize: 11, color: "var(--ink-3)" }}>{mod.summary}</span>
              {mod.findings.length > 0 && <Badge color="var(--amber)" mono>{mod.findings.length}</Badge>}
              <span style={{
                color: "var(--ink-3)", transition: "transform 0.15s",
                transform: expandedModules.has(mod.module_id) ? "rotate(180deg)" : "none",
                display: "inline-block",
              }}>
                &#9660;
              </span>
            </div>
          </button>

          {expandedModules.has(mod.module_id) && (
            <div style={{ borderTop: "1px solid var(--line)" }}>
              {mod.findings.length === 0 ? (
                <div style={{ padding: "14px 16px", fontSize: 12.5, color: "var(--green)" }}>No issues found</div>
              ) : (
                sortedFindings(mod.findings).map((finding, idx) => {
                  const findingKey = `${mod.module_id}-${idx}`;
                  const clawEntry = askClawState.get(findingKey);
                  const cfg = SEVERITY_CONFIG[finding.severity] || SEVERITY_CONFIG.low;
                  return (
                    <div key={idx} style={{ padding: "14px 16px", borderTop: idx > 0 ? "1px solid var(--line-soft)" : "none" }}>
                      <div style={{ display: "flex", alignItems: "stretch", gap: 12 }}>
                        <div style={{ width: 3, borderRadius: 2, background: cfg.cssVar, flexShrink: 0 }} />
                        <div style={{ flex: 1 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                            <Badge color={cfg.cssVar}>{finding.severity}</Badge>
                            <span style={{ fontSize: 10.5, padding: "2px 6px", background: "var(--bg-2)", borderRadius: 3, color: "var(--ink-2)" }}>{finding.category}</span>
                            <span style={{ fontSize: 12.5, fontWeight: 500, color: "var(--ink-0)" }}>{finding.description}</span>
                          </div>
                          <div style={{ fontSize: 11, color: "var(--ink-2)", marginBottom: 4 }}>
                            <span style={{ fontWeight: 500 }}>Resource:</span>{" "}
                            <span style={{ fontFamily: "var(--font-mono)" }}>{finding.affected_resource}</span>
                          </div>
                          <div style={{ fontSize: 11, color: "var(--ink-2)" }}>
                            <span style={{ fontWeight: 500 }}>Fix:</span> {finding.fix_suggestion}
                          </div>
                          {finding.fix_action && (
                            <div style={{ marginTop: 8 }}>
                              <Btn
                                size="sm"
                                kind="accent"
                                icon="check"
                                onClick={() => applyFix(finding)}
                                disabled={fixingAction === `${finding.fix_action.action_type}:${finding.affected_resource}`}
                              >
                                {fixingAction === `${finding.fix_action.action_type}:${finding.affected_resource}`
                                  ? "Applying..."
                                  : finding.fix_action.action_type === "wrap_server" ? "Wrap Server" : "Apply Fix"}
                              </Btn>
                            </div>
                          )}

                          {/* AI Analysis display */}
                          {finding.ai_analysis && (
                            <div style={{
                              marginTop: 10, padding: "10px 12px", borderRadius: 8,
                              background: "color-mix(in oklch, var(--violet) 6%, transparent)",
                              border: "1px solid color-mix(in oklch, var(--violet) 20%, transparent)",
                            }}>
                              <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
                                <Icon name="sparkles" size={11} color="var(--violet)" />
                                <span style={{ fontSize: 10.5, fontWeight: 600, color: "var(--violet)" }}>AI Analysis</span>
                              </div>
                              <div style={{ fontSize: 11.5, color: "var(--ink-1)", whiteSpace: "pre-wrap", lineHeight: 1.5 }}>
                                {finding.ai_analysis}
                              </div>
                            </div>
                          )}

                          {/* On-demand AI enrichment button for critical/high findings */}
                          {!finding.ai_analysis && (finding.severity === "critical" || finding.severity === "high") && onEnrichFinding && (
                            <div style={{ marginTop: 8 }}>
                              <Btn
                                size="sm"
                                kind="soft"
                                icon="sparkles"
                                onClick={() => onEnrichFinding(mod.module_id, idx)}
                                disabled={enrichingKeys?.has(`${mod.module_id}-${idx}`)}
                              >
                                {enrichingKeys?.has(`${mod.module_id}-${idx}`) ? "Analyzing..." : "Get AI Analysis"}
                              </Btn>
                            </div>
                          )}
                        </div>
                        <Btn size="sm" kind={clawEntry ? "accent" : "soft"} onClick={() => toggleAskClaw(findingKey)}>
                          Ask Rook
                        </Btn>
                      </div>

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
                })
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Ask Rook inline panel (reusable)
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
    <div style={{
      marginTop: 10, marginLeft: 15, padding: 12, borderRadius: 10,
      background: "var(--accent-soft)", border: "1px solid var(--accent-line)",
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
        <Icon name="sparkles" size={13} color="var(--accent)" />
        <span style={{ fontSize: 11.5, fontWeight: 600, color: "var(--accent)" }}>Ask Rook AI</span>
        {entry.loading && <span style={{ fontSize: 11, color: "var(--ink-3)" }} className="cd-pulse">Analyzing...</span>}
      </div>

      {!entry.response && !entry.loading && (
        <Btn size="sm" kind="primary" onClick={() => onAnalyze(findingKey, finding)}>Analyze this finding</Btn>
      )}

      {entry.response && (
        <div style={{
          fontSize: 12, color: "var(--ink-0)", whiteSpace: "pre-wrap", lineHeight: 1.6,
          background: "var(--bg-1)", borderRadius: 8, padding: 10, marginBottom: 8,
        }}>
          {entry.response}
        </div>
      )}

      {entry.response && (
        <div style={{ display: "flex", gap: 6 }}>
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
            style={{
              flex: 1, padding: "6px 10px", borderRadius: 6, fontSize: 12,
              background: "var(--bg-0)", border: "1px solid var(--line)",
              color: "var(--ink-0)", outline: "none",
            }}
          />
          <Btn
            size="sm"
            kind="primary"
            icon="send"
            onClick={() => {
              if (entry.followUp.trim()) onAnalyze(findingKey, finding, entry.followUp.trim());
            }}
            disabled={entry.loading || !entry.followUp.trim()}
          >
            Send
          </Btn>
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
      const raw = await invoke<string>("ask_claw_ai", { input: prompt, contextJson });
      let message = raw;
      try {
        const parsed = JSON.parse(raw);
        message = parsed.message ?? parsed.explanation ?? raw;
      } catch { /* use raw string if not JSON */ }
      setAskClawState((prev) => {
        const next = new Map(prev);
        next.set(findingKey, { loading: false, response: message, followUp: "" });
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

  const sortedFindings = (findings: ScanFinding[]) =>
    [...findings].sort(
      (a, b) =>
        (SEVERITY_CONFIG[a.severity]?.order ?? 99) -
        (SEVERITY_CONFIG[b.severity]?.order ?? 99)
    );

  return (
    <div style={{ padding: 24 }}>
      <h2 style={{ margin: "0 0 14px", fontSize: 15, fontWeight: 600, color: "var(--ink-0)" }}>Scan History</h2>

      {scanHistory.length === 0 ? (
        <Card>
          <div style={{ textAlign: "center", padding: "24px 0" }}>
            <Icon name="history" size={28} color="var(--ink-3)" />
            <p style={{ fontSize: 13, color: "var(--ink-2)", marginTop: 10 }}>
              No scans recorded yet. Run a Security Scan or AI Scan to see history here.
            </p>
          </div>
        </Card>
      ) : (
        <div style={{ display: "grid", gap: 8 }}>
          {scanHistory.map((entry) => (
            <div key={entry.scan_id}>
              <button onClick={() => selectEntry(entry)} style={{
                width: "100%", textAlign: "left", cursor: "pointer",
                padding: "12px 16px", borderRadius: 10,
                background: "var(--bg-1)",
                border: `1px solid ${selectedEntry?.scan_id === entry.scan_id ? "var(--accent-line)" : "var(--line)"}`,
              }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <Badge color={entry.status === "completed" ? "var(--green)" : entry.status === "failed" ? "var(--red)" : "var(--accent)"}>
                      {entry.status}
                    </Badge>
                    <Badge color={entry.scan_type === "ai" ? "var(--accent)" : "var(--ink-2)"} mono>
                      {entry.scan_type === "ai" ? "AI" : "Security"}
                    </Badge>
                    <span style={{ fontSize: 12, fontFamily: "var(--font-mono)", color: "var(--ink-1)" }}>
                      {entry.scan_id.slice(0, 16)}
                    </span>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: 12, fontSize: 12 }}>
                    <span style={{ color: entry.findings_count > 0 ? "var(--amber)" : "var(--ink-2)", fontWeight: entry.findings_count > 0 ? 500 : 400 }}>
                      {entry.findings_count} findings
                    </span>
                    <span style={{ color: "var(--ink-3)", fontSize: 11 }}>{new Date(entry.started_at).toLocaleString()}</span>
                    <span style={{
                      color: "var(--ink-3)", transition: "transform 0.15s", display: "inline-block",
                      transform: selectedEntry?.scan_id === entry.scan_id ? "rotate(180deg)" : "none",
                    }}>
                      &#9660;
                    </span>
                  </div>
                </div>
              </button>

              {selectedEntry?.scan_id === entry.scan_id && (
                <div style={{ marginTop: 4, marginLeft: 16, paddingLeft: 16, borderLeft: "2px solid var(--accent-line)" }}>
                  {loading && (
                    <div style={{ padding: "16px 0", fontSize: 12.5, color: "var(--ink-2)" }} className="cd-pulse">
                      Loading scan results...
                    </div>
                  )}
                  {error && <div style={{ padding: "12px 0", fontSize: 12.5, color: "var(--ink-2)" }}>{error}</div>}
                  {loadedResult && (
                    <QuickScanResults
                      scanResult={loadedResult}
                      expandedModules={expandedModules}
                      toggleExpanded={toggleExpanded}
                      sortedFindings={sortedFindings}
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
  return (
    <div style={{
      borderRadius: 10, padding: 14, textAlign: "center",
      background: `color-mix(in oklch, ${color} 8%, transparent)`,
      border: `1px solid color-mix(in oklch, ${color} 20%, transparent)`,
    }}>
      <div style={{ fontSize: 22, fontWeight: 700, color, fontFamily: "var(--font-mono)" }}>{count}</div>
      <div style={{ fontSize: 10.5, color: "var(--ink-2)", marginTop: 2 }}>{label}</div>
    </div>
  );
}
