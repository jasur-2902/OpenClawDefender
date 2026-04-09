import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { AiScanResult, ScanRemediation } from "../../types";
import { AiFindingCard } from "./AiFindingCard";

interface Props {
  scanId: string;
  onNewScan: () => void;
}

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function AiScanResults({ scanId, onNewScan }: Props) {
  const [result, setResult] = useState<AiScanResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [applyingAll, setApplyingAll] = useState(false);
  const [applyAllDone, setApplyAllDone] = useState(false);

  useEffect(() => {
    async function load() {
      try {
        const r = await invoke<AiScanResult>("get_ai_scan_result", { scanId });
        // Normalize status: Rust enum Failed{error} serializes as {"Failed":{"error":"..."}}
        let failError: string | undefined;
        if (r.status && typeof r.status !== "string") {
          const statusObj = r.status as unknown as Record<string, unknown>;
          const variant = Object.keys(statusObj)[0] ?? "failed";
          if (variant === "Failed" && statusObj[variant] && typeof statusObj[variant] === "object") {
            failError = (statusObj[variant] as Record<string, string>).error;
          }
          r.status = variant.toLowerCase();
        } else if (typeof r.status === "string") {
          r.status = r.status.toLowerCase();
        }
        if (failError && !r.summary) {
          r.summary = failError;
        }
        // Ensure numeric/array fields have safe defaults
        r.estimated_cost = r.estimated_cost ?? 0;
        r.tool_calls_used = r.tool_calls_used ?? 0;
        r.duration_secs = r.duration_secs ?? 0;
        r.stages_completed = r.stages_completed ?? [];
        r.findings = r.findings ?? [];
        r.summary = r.summary ?? "";
        setResult(r);
      } catch (e) {
        setError(String(e));
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [scanId]);

  async function applyAllSafeFixes() {
    if (!result) return;
    setApplyingAll(true);
    try {
      const remediations = await invoke<ScanRemediation[]>("get_scan_remediations", { scanId });
      const safe = remediations.filter(
        (r) => r.auto_executable && r.risk_level === "low" && r.status !== "executed"
      );
      for (const rem of safe) {
        try {
          await invoke("execute_scan_remediation", {
            scanId,
            remediationId: rem.id,
          });
        } catch {
          // Continue with other remediations
        }
      }
      setApplyAllDone(true);
    } catch (e) {
      setError(String(e));
    } finally {
      setApplyingAll(false);
    }
  }

  if (loading) {
    return (
      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-6">
        <div className="flex items-center gap-2 text-sm text-[var(--color-text-secondary)]">
          <span className="inline-block w-2 h-2 rounded-full bg-[var(--color-accent)] animate-pulse" />
          Loading results...
        </div>
      </div>
    );
  }

  if (error || !result) {
    return (
      <div className="space-y-3">
        <div className="rounded-lg border border-[var(--color-danger)] bg-[var(--color-danger)]/10 p-4 text-sm text-[var(--color-danger)]">
          {error || "Failed to load scan results."}
        </div>
        <button
          onClick={onNewScan}
          className="px-4 py-2 rounded-lg bg-[var(--color-accent)] text-white text-sm font-medium hover:bg-[var(--color-accent-hover)] transition-colors"
        >
          Start New Scan
        </button>
      </div>
    );
  }

  const sortedFindings = [...result.findings].sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99)
  );

  function formatDuration(secs: number): string {
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    return m > 0 ? `${m}m ${s}s` : `${s}s`;
  }

  return (
    <div className="space-y-4">
      {/* Summary header */}
      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4 space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold text-[var(--color-text-primary)]">
            Scan Results
          </h3>
          <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
            result.status === "completed"
              ? "bg-[var(--color-safe)]/20 text-[var(--color-safe)]"
              : result.status === "cancelled"
                ? "bg-[var(--color-warning)]/20 text-[var(--color-warning)]"
                : "bg-[var(--color-danger)]/20 text-[var(--color-danger)]"
          }`}>
            {result.status.charAt(0).toUpperCase() + result.status.slice(1)}
          </span>
        </div>

        {result.summary && (
          <p className="text-sm text-[var(--color-text-secondary)]">{result.summary}</p>
        )}

        <div className="flex flex-wrap gap-4 text-xs text-[var(--color-text-secondary)]">
          <div>
            <span className="text-[var(--color-text-muted)]">Playbook: </span>
            <span className="font-medium text-[var(--color-text-primary)]">{result.playbook_name}</span>
          </div>
          <div>
            <span className="text-[var(--color-text-muted)]">Duration: </span>
            <span className="font-medium text-[var(--color-text-primary)]">{formatDuration(result.duration_secs)}</span>
          </div>
          <div>
            <span className="text-[var(--color-text-muted)]">Stages: </span>
            <span className="font-medium text-[var(--color-text-primary)]">{result.stages_completed.length}</span>
          </div>
          <div>
            <span className="text-[var(--color-text-muted)]">Tool Calls: </span>
            <span className="font-medium text-[var(--color-text-primary)]">{result.tool_calls_used}</span>
          </div>
          <div>
            <span className="text-[var(--color-text-muted)]">Est. Cost: </span>
            <span className="font-medium text-[var(--color-text-primary)]">
              ${result.estimated_cost.toFixed(3)}
            </span>
          </div>
        </div>

        {/* Severity counts */}
        <div className="grid grid-cols-5 gap-2">
          <SeverityCount label="Critical" count={result.critical_count} color="red" />
          <SeverityCount label="High" count={result.high_count} color="orange" />
          <SeverityCount label="Medium" count={result.medium_count} color="yellow" />
          <SeverityCount label="Low" count={result.low_count} color="blue" />
          <SeverityCount label="Info" count={result.info_count} color="gray" />
        </div>

        {/* Actions */}
        <div className="flex items-center gap-3 pt-1">
          <button
            onClick={applyAllSafeFixes}
            disabled={applyingAll || applyAllDone || result.total_findings === 0}
            className="px-4 py-2 rounded-lg bg-[var(--color-accent)] text-white text-sm font-medium hover:bg-[var(--color-accent-hover)] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {applyingAll ? "Applying..." : applyAllDone ? "Applied Safe Fixes" : "Apply All Safe Fixes"}
          </button>
          <button
            onClick={onNewScan}
            className="px-4 py-2 rounded-lg border border-[var(--color-border)] text-sm font-medium text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:border-[var(--color-accent)] transition-colors"
          >
            New Scan
          </button>
          <button
            disabled
            className="px-4 py-2 rounded-lg border border-[var(--color-border)] text-sm font-medium text-[var(--color-text-muted)] cursor-not-allowed"
            title="Report generation coming soon"
          >
            Export Report
          </button>
        </div>
      </div>

      {/* Findings list */}
      {sortedFindings.length > 0 ? (
        <div className="space-y-2">
          <h4 className="text-sm font-medium text-[var(--color-text-secondary)]">
            Findings ({result.total_findings})
          </h4>
          {sortedFindings.map((f) => (
            <AiFindingCard key={f.id} finding={f} scanId={scanId} />
          ))}
        </div>
      ) : (
        <div className="rounded-lg border border-[var(--color-safe)] bg-[var(--color-safe)]/10 p-4 text-center">
          <span className="text-sm text-[var(--color-safe)]">
            No security issues found. Your system looks clean.
          </span>
        </div>
      )}
    </div>
  );
}

function SeverityCount({ label, count, color }: { label: string; count: number; color: string }) {
  const colorMap: Record<string, string> = {
    red: "text-red-400 border-red-500/30 bg-red-500/5",
    orange: "text-orange-400 border-orange-500/30 bg-orange-500/5",
    yellow: "text-yellow-400 border-yellow-500/30 bg-yellow-500/5",
    blue: "text-blue-400 border-blue-500/30 bg-blue-500/5",
    gray: "text-gray-400 border-gray-500/30 bg-gray-500/5",
  };
  return (
    <div className={`rounded-lg border p-2 text-center ${colorMap[color] || ""}`}>
      <div className="text-xl font-bold">{count}</div>
      <div className="text-xs opacity-80">{label}</div>
    </div>
  );
}
