import { useState, useEffect, useCallback, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { ScanProgress } from "../types";

interface ScanHistoryEntry {
  scan_id: string;
  status: ScanProgress["status"];
  findings_count: number;
  started_at: string;
}

const MODULES = [
  { id: "tool-poisoning", label: "Tool Poisoning" },
  { id: "sampling-abuse", label: "Sampling Abuse" },
  { id: "resource-injection", label: "Resource Injection" },
  { id: "exfiltration", label: "Exfiltration" },
] as const;

export function Scanner() {
  const [serverCommand, setServerCommand] = useState("");
  const [selectedModules, setSelectedModules] = useState<Set<string>>(
    new Set(MODULES.map((m) => m.id))
  );
  const [timeout, setScanTimeout] = useState(60);
  const [activeScan, setActiveScan] = useState<ScanProgress | null>(null);
  const [scanHistory, setScanHistory] = useState<ScanHistoryEntry[]>([]);
  const [elapsed, setElapsed] = useState(0);
  const [error, setError] = useState<string | null>(null);
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
    if (!serverCommand.trim()) return;
    setError(null);
    setElapsed(0);
    try {
      const scanId = await invoke<string>("start_scan", {
        serverCommand: serverCommand.trim(),
        modules: Array.from(selectedModules),
        timeout,
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
      }, 1000);
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

  const isScanning = activeScan?.status === "running";

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold">Scanner</h1>

      {error && (
        <div className="rounded-lg border border-[var(--color-danger)] bg-[var(--color-danger)]/10 p-4 text-sm text-[var(--color-danger)]">
          {error}
        </div>
      )}

      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4 space-y-4">
        <h2 className="text-lg font-semibold">New Scan</h2>
        <div>
          <label className="block text-sm text-[var(--color-text-secondary)] mb-1">
            Server Command
          </label>
          <input
            type="text"
            value={serverCommand}
            onChange={(e) => setServerCommand(e.target.value)}
            placeholder="e.g. npx @modelcontextprotocol/server-filesystem /tmp"
            disabled={isScanning}
            className="w-full px-3 py-2 rounded-md bg-[var(--color-bg-primary)] border border-[var(--color-border)] text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-secondary)]/50 focus:outline-none focus:border-[var(--color-accent)]"
          />
        </div>

        <div>
          <label className="block text-sm text-[var(--color-text-secondary)] mb-2">
            Modules
          </label>
          <div className="flex flex-wrap gap-2">
            {MODULES.map((mod) => (
              <button
                key={mod.id}
                onClick={() => toggleModule(mod.id)}
                disabled={isScanning}
                className={`px-3 py-1.5 rounded-md text-sm border transition-colors ${
                  selectedModules.has(mod.id)
                    ? "border-[var(--color-accent)] bg-[var(--color-accent)]/20 text-[var(--color-accent)]"
                    : "border-[var(--color-border)] text-[var(--color-text-secondary)] hover:border-[var(--color-text-secondary)]"
                }`}
              >
                {mod.label}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-end gap-4">
          <div>
            <label className="block text-sm text-[var(--color-text-secondary)] mb-1">
              Timeout (seconds)
            </label>
            <input
              type="number"
              value={timeout}
              onChange={(e) => setScanTimeout(parseInt(e.target.value) || 60)}
              min={10}
              max={600}
              disabled={isScanning}
              className="w-28 px-3 py-2 rounded-md bg-[var(--color-bg-primary)] border border-[var(--color-border)] text-sm text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
            />
          </div>
          <button
            onClick={startScan}
            disabled={isScanning || selectedModules.size === 0 || !serverCommand.trim()}
            className="px-4 py-2 rounded-md bg-[var(--color-accent)] text-white text-sm font-medium hover:bg-[var(--color-accent-hover)] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            Start Scan
          </button>
        </div>
      </div>

      {activeScan && (
        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold">Active Scan</h2>
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
              <span>{activeScan.progress_percent}%</span>
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

      <div className="space-y-3">
        <h2 className="text-lg font-semibold">Scan History</h2>
        {scanHistory.length === 0 ? (
          <p className="text-sm text-[var(--color-text-secondary)]">
            No previous scans. Start a scan above to see results here.
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
                  <span className="text-sm font-mono">{entry.scan_id.slice(0, 8)}</span>
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
