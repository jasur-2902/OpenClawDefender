import { useState, useEffect, useCallback, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { ScanProgress } from "../types";

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

interface ScanHistoryEntry {
  scan_id: string;
  status: ScanProgress["status"];
  findings_count: number;
  started_at: string;
}

const MODULES = [
  { id: "mcp-config-audit", label: "MCP Config Audit", icon: "shield" },
  { id: "policy-strength", label: "Policy Strength", icon: "lock" },
  { id: "server-reputation", label: "Server Reputation", icon: "search" },
  { id: "system-posture", label: "System Posture", icon: "monitor" },
  { id: "behavioral-anomaly", label: "Behavioral Anomaly", icon: "activity" },
] as const;

const SEVERITY_CONFIG: Record<string, { color: string; bg: string; label: string; order: number }> = {
  critical: { color: "text-red-400", bg: "bg-red-500/20", label: "CRITICAL", order: 0 },
  high: { color: "text-orange-400", bg: "bg-orange-500/20", label: "HIGH", order: 1 },
  medium: { color: "text-yellow-400", bg: "bg-yellow-500/20", label: "MEDIUM", order: 2 },
  low: { color: "text-blue-400", bg: "bg-blue-500/20", label: "LOW", order: 3 },
};

export function Scanner() {
  const [selectedModules, setSelectedModules] = useState<Set<string>>(
    new Set(MODULES.map((m) => m.id))
  );
  const [activeScan, setActiveScan] = useState<ScanProgress | null>(null);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [scanHistory, setScanHistory] = useState<ScanHistoryEntry[]>([]);
  const [elapsed, setElapsed] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [expandedModules, setExpandedModules] = useState<Set<string>>(new Set());
  const [fixingAction, setFixingAction] = useState<string | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

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
        setScanHistory((prev) => [
          {
            scan_id: progress.scan_id,
            status: progress.status,
            findings_count: progress.findings_count,
            started_at: new Date().toISOString(),
          },
          ...prev,
        ]);
        // Fetch full results
        try {
          const result = await invoke<ScanResult>("get_scan_results", {
            scanId,
          });
          setScanResult(result);
          // Auto-expand modules with findings
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
  }, []);

  useEffect(() => {
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, []);

  async function startScan() {
    setError(null);
    setElapsed(0);
    setScanResult(null);
    setExpandedModules(new Set());
    try {
      const scanId = await invoke<string>("start_scan", {
        serverCommand: "system-scan",
        modules: Array.from(selectedModules),
        timeout: 300,
      });
      setActiveScan({
        scan_id: scanId,
        status: "running",
        progress_percent: 0,
        modules_completed: 0,
        modules_total: selectedModules.size,
        findings_count: 0,
        current_module: null,
      });

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
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }

  function toggleExpanded(moduleId: string) {
    setExpandedModules((prev) => {
      const next = new Set(prev);
      if (next.has(moduleId)) {
        next.delete(moduleId);
      } else {
        next.add(moduleId);
      }
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
      // Show success briefly
      alert(result);
    } catch (e) {
      setError(String(e));
    } finally {
      setFixingAction(null);
    }
  }

  function statusBadge(status: ScanProgress["status"]) {
    const styles: Record<string, string> = {
      running: "bg-[var(--color-accent)]/20 text-[var(--color-accent)]",
      completed: "bg-[var(--color-success)]/20 text-[var(--color-success)]",
      failed: "bg-[var(--color-danger)]/20 text-[var(--color-danger)]",
    };
    return (
      <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${styles[status]}`}>
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
    if (status === "completed" && findingsCount === 0) {
      return <span className="text-[var(--color-success)] text-lg">&#10003;</span>;
    }
    if (status === "completed" && findingsCount > 0) {
      return <span className="text-[var(--color-warning)] text-lg">&#9888;</span>;
    }
    if (status === "skipped") {
      return <span className="text-[var(--color-text-secondary)] text-lg">&#8722;</span>;
    }
    return <span className="text-[var(--color-text-secondary)] text-lg">&#8226;</span>;
  }

  const isScanning = activeScan?.status === "running";

  // Sort findings by severity
  const sortedFindings = (findings: ScanFinding[]) =>
    [...findings].sort(
      (a, b) =>
        (SEVERITY_CONFIG[a.severity]?.order ?? 99) -
        (SEVERITY_CONFIG[b.severity]?.order ?? 99)
    );

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Security Scanner</h1>
        {scanResult && (
          <div className="flex items-center gap-3 text-sm">
            {scanResult.critical_count > 0 && (
              <span className="text-red-400 font-medium">
                {scanResult.critical_count} Critical
              </span>
            )}
            {scanResult.high_count > 0 && (
              <span className="text-orange-400 font-medium">
                {scanResult.high_count} High
              </span>
            )}
            {scanResult.medium_count > 0 && (
              <span className="text-yellow-400 font-medium">
                {scanResult.medium_count} Medium
              </span>
            )}
            {scanResult.low_count > 0 && (
              <span className="text-blue-400 font-medium">
                {scanResult.low_count} Low
              </span>
            )}
          </div>
        )}
      </div>

      {error && (
        <div className="rounded-lg border border-[var(--color-danger)] bg-[var(--color-danger)]/10 p-4 text-sm text-[var(--color-danger)]">
          {error}
        </div>
      )}

      {/* Scan Configuration */}
      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">Scan Modules</h2>
          <button
            onClick={() => {
              if (selectedModules.size === MODULES.length) {
                setSelectedModules(new Set());
              } else {
                setSelectedModules(new Set(MODULES.map((m) => m.id)));
              }
            }}
            disabled={isScanning}
            className="text-xs text-[var(--color-accent)] hover:underline disabled:opacity-50"
          >
            {selectedModules.size === MODULES.length ? "Deselect All" : "Select All"}
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
          {MODULES.map((mod) => (
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

        <button
          onClick={startScan}
          disabled={isScanning || selectedModules.size === 0}
          className="w-full px-4 py-2.5 rounded-lg bg-[var(--color-accent)] text-white text-sm font-medium hover:bg-[var(--color-accent-hover)] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {isScanning ? "Scanning..." : "Run Security Scan"}
        </button>
      </div>

      {/* Active Scan Progress */}
      {activeScan && (
        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold">
              {activeScan.status === "running" ? "Scanning..." : "Scan Complete"}
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
                  : activeScan.status === "running"
                    ? "Initializing..."
                    : "Done"}
              </span>
              <span>{Math.round(activeScan.progress_percent)}%</span>
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
              <span className="text-[var(--color-text-secondary)]">Modules: </span>
              <span className="font-medium">
                {activeScan.modules_completed}/{activeScan.modules_total}
              </span>
            </div>
            <div>
              <span className="text-[var(--color-text-secondary)]">Findings: </span>
              <span
                className={`font-medium ${
                  activeScan.findings_count > 0
                    ? "text-[var(--color-warning)]"
                    : "text-[var(--color-success)]"
                }`}
              >
                {activeScan.findings_count}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Scan Results */}
      {scanResult && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold">Results</h2>
            <span className="text-xs text-[var(--color-text-secondary)]">
              {scanResult.completed_at
                ? new Date(scanResult.completed_at).toLocaleString()
                : ""}
            </span>
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
                    <span className="text-xs text-[var(--color-text-secondary)]">
                      {mod.summary}
                    </span>
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
                    <span
                      className={`text-[var(--color-text-secondary)] transition-transform ${
                        expandedModules.has(mod.module_id) ? "rotate-180" : ""
                      }`}
                    >
                      &#9660;
                    </span>
                  </div>
                </button>

                {expandedModules.has(mod.module_id) && (
                  <div className="border-t border-[var(--color-border)]">
                    {mod.findings.length === 0 ? (
                      <div className="px-4 py-3 text-sm text-[var(--color-success)]">
                        No issues found
                      </div>
                    ) : (
                      <div className="divide-y divide-[var(--color-border)]">
                        {sortedFindings(mod.findings).map((finding, idx) => (
                          <div key={idx} className="px-4 py-3 space-y-2">
                            <div className="flex items-start justify-between gap-3">
                              <div className="flex items-center gap-2 min-w-0 flex-wrap">
                                {severityBadge(finding.severity)}
                                <span className="px-1.5 py-0.5 rounded text-xs bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)]">
                                  {finding.category}
                                </span>
                                <span className="text-sm font-medium truncate">
                                  {finding.description}
                                </span>
                              </div>
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
                                  disabled={
                                    fixingAction ===
                                    `${finding.fix_action.action_type}:${finding.affected_resource}`
                                  }
                                  className="mt-1 px-3 py-1 rounded text-xs font-medium bg-[var(--color-accent)]/20 text-[var(--color-accent)] hover:bg-[var(--color-accent)]/30 disabled:opacity-50 transition-colors"
                                >
                                  {fixingAction ===
                                  `${finding.fix_action.action_type}:${finding.affected_resource}`
                                    ? "Applying..."
                                    : finding.fix_action.action_type === "wrap_server"
                                      ? "Wrap Server"
                                      : "Apply Fix"}
                                </button>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Scan History */}
      <div className="space-y-3">
        <h2 className="text-lg font-semibold">Scan History</h2>
        {scanHistory.length === 0 ? (
          <p className="text-sm text-[var(--color-text-secondary)]">
            No previous scans. Run a security scan above to see results here.
          </p>
        ) : (
          <div className="rounded-lg border border-[var(--color-border)] overflow-hidden">
            {scanHistory.map((entry, i) => (
              <div
                key={entry.scan_id}
                className={`flex items-center justify-between px-4 py-3 ${
                  i % 2 === 0 ? "bg-[var(--color-bg-secondary)]" : "bg-[var(--color-bg-tertiary)]"
                }`}
              >
                <div className="flex items-center gap-3">
                  {statusBadge(entry.status)}
                  <span className="text-sm font-mono">{entry.scan_id.slice(0, 12)}</span>
                </div>
                <div className="flex items-center gap-4 text-sm text-[var(--color-text-secondary)]">
                  <span>{entry.findings_count} findings</span>
                  <span>{new Date(entry.started_at).toLocaleString()}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function SeverityCard({
  label,
  count,
  color,
}: {
  label: string;
  count: number;
  color: string;
}) {
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
