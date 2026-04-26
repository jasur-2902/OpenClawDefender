import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { AiScanFinding, ScanEvidenceItem, ScanRemediation } from "../../types";

interface AskClawState {
  loading: boolean;
  response: string | null;
  followUp: string;
}

const SEVERITY_STYLES: Record<string, { color: string; bg: string; label: string }> = {
  critical: { color: "text-red-400", bg: "bg-red-500/20", label: "CRITICAL" },
  high: { color: "text-orange-400", bg: "bg-orange-500/20", label: "HIGH" },
  medium: { color: "text-yellow-400", bg: "bg-yellow-500/20", label: "MEDIUM" },
  low: { color: "text-blue-400", bg: "bg-blue-500/20", label: "LOW" },
  info: { color: "text-gray-400", bg: "bg-gray-500/20", label: "INFO" },
};

interface Props {
  finding: AiScanFinding;
  scanId: string;
  animate?: boolean;
}

export function AiFindingCard({ finding, scanId, animate }: Props) {
  const [evidenceExpanded, setEvidenceExpanded] = useState(false);
  const [evidence, setEvidence] = useState<ScanEvidenceItem[] | null>(null);
  const [loadingEvidence, setLoadingEvidence] = useState(false);
  const [remediations, setRemediations] = useState<ScanRemediation[] | null>(null);
  const [remExpanded, setRemExpanded] = useState(false);
  const [loadingRem, setLoadingRem] = useState(false);
  const [executingRem, setExecutingRem] = useState<string | null>(null);
  const [askClaw, setAskClaw] = useState<AskClawState | null>(null);

  const sev = SEVERITY_STYLES[finding.severity] || SEVERITY_STYLES.info;

  async function loadEvidence() {
    if (evidence) {
      setEvidenceExpanded(!evidenceExpanded);
      return;
    }
    setLoadingEvidence(true);
    try {
      const chain = await invoke<ScanEvidenceItem[]>("get_scan_evidence_chain", {
        scanId,
        findingId: finding.id,
      });
      setEvidence(chain);
      setEvidenceExpanded(true);
    } catch {
      setEvidence([]);
      setEvidenceExpanded(true);
    } finally {
      setLoadingEvidence(false);
    }
  }

  async function loadRemediations() {
    if (remediations) {
      setRemExpanded(!remExpanded);
      return;
    }
    setLoadingRem(true);
    try {
      const all = await invoke<ScanRemediation[]>("get_scan_remediations", { scanId });
      const relevant = all.filter((r) => r.finding_id === finding.id);
      setRemediations(relevant);
      setRemExpanded(true);
    } catch {
      setRemediations([]);
      setRemExpanded(true);
    } finally {
      setLoadingRem(false);
    }
  }

  async function executeRemediation(remId: string) {
    setExecutingRem(remId);
    try {
      await invoke("execute_scan_remediation", { scanId, remediationId: remId });
      setRemediations((prev) =>
        prev?.map((r) =>
          r.id === remId ? { ...r, status: "executed", executed_at: new Date().toISOString() } : r
        ) ?? null
      );
    } catch {
      // silently fail
    } finally {
      setExecutingRem(null);
    }
  }

  function toggleAskClaw() {
    if (askClaw) {
      setAskClaw(null);
    } else {
      setAskClaw({ loading: false, response: null, followUp: "" });
    }
  }

  async function runAskClaw(followUpQuestion?: string) {
    setAskClaw((prev) => prev ? { ...prev, loading: true, followUp: "" } : { loading: true, response: null, followUp: "" });

    const prompt = followUpQuestion
      ? followUpQuestion
      : `Analyze this AI scan finding:\nSeverity: ${finding.severity}\nTitle: ${finding.title}\nDescription: ${finding.description}\n${finding.remediation_hint ? `Suggestion: ${finding.remediation_hint}` : ""}\n\nIs this a real risk? What should I do?`;

    const contextJson = JSON.stringify({
      active_page: "scanner",
      finding_severity: finding.severity,
      finding_title: finding.title,
      finding_description: finding.description,
      finding_stage: finding.stage,
    });

    try {
      const raw = await invoke<string>("ask_claw_ai", { input: prompt, contextJson });
      let message = raw;
      try {
        const parsed = JSON.parse(raw);
        message = parsed.message ?? parsed.explanation ?? raw;
      } catch { /* use raw string if not JSON */ }
      setAskClaw({ loading: false, response: message, followUp: "" });
    } catch (e) {
      setAskClaw({ loading: false, response: `Error: ${String(e)}`, followUp: "" });
    }
  }

  async function revertRemediation(remId: string) {
    setExecutingRem(remId);
    try {
      await invoke("revert_scan_remediation", { scanId, remediationId: remId });
      setRemediations((prev) =>
        prev?.map((r) =>
          r.id === remId ? { ...r, status: "pending", executed_at: null, reverted_at: new Date().toISOString() } : r
        ) ?? null
      );
    } catch {
      // silently fail
    } finally {
      setExecutingRem(null);
    }
  }

  return (
    <div
      className={`rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] overflow-hidden ${
        animate ? "animate-slide-in" : ""
      }`}
    >
      <div className="px-4 py-3 space-y-2">
        {/* Header */}
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-2 flex-wrap min-w-0">
            <span className={`px-2 py-0.5 rounded text-xs font-bold ${sev.color} ${sev.bg}`}>
              {sev.label}
            </span>
            <span className="text-sm font-medium text-[var(--color-text-primary)]">
              {finding.title}
            </span>
          </div>
          <span className="text-xs text-[var(--color-text-secondary)] shrink-0">
            {finding.stage}
          </span>
        </div>

        {/* Description */}
        <p className="text-xs text-[var(--color-text-secondary)]">{finding.description}</p>

        {/* Remediation hint */}
        {finding.remediation_hint && (
          <div className="text-xs text-[var(--color-text-secondary)]">
            <span className="font-medium">Suggestion:</span> {finding.remediation_hint}
          </div>
        )}

        {/* Actions */}
        <div className="flex items-center gap-2 pt-1">
          <button
            onClick={loadEvidence}
            disabled={loadingEvidence}
            className="px-2.5 py-1 rounded text-xs font-medium bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors disabled:opacity-50"
          >
            {loadingEvidence ? "Loading..." : evidenceExpanded ? "Hide Evidence" : "View Evidence"}
          </button>
          <button
            onClick={loadRemediations}
            disabled={loadingRem}
            className="px-2.5 py-1 rounded text-xs font-medium bg-[var(--color-accent)]/20 text-[var(--color-accent)] hover:bg-[var(--color-accent)]/30 transition-colors disabled:opacity-50"
          >
            {loadingRem ? "Loading..." : remExpanded ? "Hide Fixes" : "Fix"}
          </button>
          <button
            onClick={toggleAskClaw}
            className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
              askClaw
                ? "bg-purple-500/20 text-purple-400"
                : "bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] hover:text-purple-400 hover:bg-purple-500/10"
            }`}
          >
            Ask Rook
          </button>
          <span className="text-xs text-[var(--color-text-muted)] ml-auto">
            {new Date(finding.discovered_at).toLocaleTimeString()}
          </span>
        </div>
      </div>

      {/* Evidence panel */}
      {evidenceExpanded && evidence && (
        <div className="border-t border-[var(--color-border)] px-4 py-3 bg-[var(--color-bg-tertiary)] space-y-2">
          <div className="text-xs font-medium text-[var(--color-text-secondary)]">
            Evidence Chain ({evidence.length} items)
          </div>
          {evidence.length === 0 ? (
            <div className="text-xs text-[var(--color-text-muted)]">No evidence collected yet.</div>
          ) : (
            evidence.map((ev) => (
              <div key={ev.id} className="rounded border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-2 text-xs space-y-1">
                <div className="flex items-center gap-2">
                  <span className="px-1.5 py-0.5 rounded bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] font-mono">
                    {ev.evidence_type}
                  </span>
                  <span className="text-[var(--color-text-secondary)]">{ev.source}</span>
                  <span className="ml-auto text-[var(--color-text-muted)]">
                    {new Date(ev.collected_at).toLocaleTimeString()}
                  </span>
                </div>
                <pre className="text-[var(--color-text-primary)] whitespace-pre-wrap break-words font-mono text-xs max-h-32 overflow-y-auto">
                  {ev.content}
                </pre>
              </div>
            ))
          )}
        </div>
      )}

      {/* Ask Rook panel */}
      {askClaw && (
        <div className="border-t border-purple-500/30 px-4 py-3 bg-purple-500/5 space-y-2">
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-purple-400">Ask Rook AI</span>
            {askClaw.loading && (
              <span className="text-xs text-purple-400/60 animate-pulse">Analyzing...</span>
            )}
          </div>

          {!askClaw.response && !askClaw.loading && (
            <button
              onClick={() => runAskClaw()}
              className="px-3 py-1.5 rounded text-xs font-medium bg-purple-500/20 text-purple-400 hover:bg-purple-500/30 transition-colors"
            >
              Analyze this finding
            </button>
          )}

          {askClaw.response && (
            <div className="text-xs text-[var(--color-text-primary)] whitespace-pre-wrap leading-relaxed bg-[var(--color-bg-secondary)] rounded p-2">
              {askClaw.response}
            </div>
          )}

          {askClaw.response && (
            <div className="flex gap-2">
              <input
                type="text"
                placeholder="Ask a follow-up question..."
                value={askClaw.followUp}
                onChange={(e) => setAskClaw((prev) => prev ? { ...prev, followUp: e.target.value } : prev)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && askClaw.followUp.trim()) {
                    runAskClaw(askClaw.followUp.trim());
                  }
                }}
                disabled={askClaw.loading}
                className="flex-1 px-2 py-1 rounded text-xs bg-[var(--color-bg-primary)] border border-[var(--color-border)] text-[var(--color-text-primary)] placeholder-[var(--color-text-secondary)] disabled:opacity-50"
              />
              <button
                onClick={() => {
                  if (askClaw.followUp.trim()) runAskClaw(askClaw.followUp.trim());
                }}
                disabled={askClaw.loading || !askClaw.followUp.trim()}
                className="px-3 py-1 rounded text-xs font-medium bg-purple-500/20 text-purple-400 hover:bg-purple-500/30 disabled:opacity-50 transition-colors"
              >
                Send
              </button>
            </div>
          )}
        </div>
      )}

      {/* Remediation panel */}
      {remExpanded && remediations && (
        <div className="border-t border-[var(--color-border)] px-4 py-3 bg-[var(--color-bg-tertiary)] space-y-2">
          <div className="text-xs font-medium text-[var(--color-text-secondary)]">
            Remediations ({remediations.length})
          </div>
          {remediations.length === 0 ? (
            <div className="text-xs text-[var(--color-text-muted)]">No automated remediations available.</div>
          ) : (
            remediations.map((rem) => (
              <div key={rem.id} className="rounded border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-2 text-xs space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-medium text-[var(--color-text-primary)]">{rem.title}</span>
                  <span className={`px-1.5 py-0.5 rounded text-xs ${
                    rem.risk_level === "low" ? "bg-[var(--color-safe)]/20 text-[var(--color-safe)]" :
                    rem.risk_level === "medium" ? "bg-[var(--color-warning)]/20 text-[var(--color-warning)]" :
                    "bg-[var(--color-danger)]/20 text-[var(--color-danger)]"
                  }`}>
                    {rem.risk_level}
                  </span>
                </div>
                <p className="text-[var(--color-text-secondary)]">{rem.description}</p>
                <div className="flex items-center gap-2 pt-1">
                  {rem.status === "executed" ? (
                    <button
                      onClick={() => revertRemediation(rem.id)}
                      disabled={executingRem === rem.id}
                      className="px-2.5 py-1 rounded text-xs font-medium bg-[var(--color-warning)]/20 text-[var(--color-warning)] hover:bg-[var(--color-warning)]/30 disabled:opacity-50"
                    >
                      {executingRem === rem.id ? "Reverting..." : "Revert"}
                    </button>
                  ) : (
                    <button
                      onClick={() => executeRemediation(rem.id)}
                      disabled={executingRem === rem.id || !rem.auto_executable}
                      className="px-2.5 py-1 rounded text-xs font-medium bg-[var(--color-accent)]/20 text-[var(--color-accent)] hover:bg-[var(--color-accent)]/30 disabled:opacity-50"
                    >
                      {executingRem === rem.id ? "Applying..." : rem.auto_executable ? "Apply Fix" : "Manual Fix Required"}
                    </button>
                  )}
                  {rem.status === "executed" && (
                    <span className="text-xs text-[var(--color-safe)]">Applied</span>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}
