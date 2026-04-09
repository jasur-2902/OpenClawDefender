import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { InvestigationDetail } from "./InvestigationDetail";
import type { InvestigationProgress, InvestigationResult } from "../../types";

interface Props {
  investigationId: string;
  onComplete?: () => void;
  onCancel?: () => void;
}

function formatElapsed(secs: number): string {
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  return m > 0 ? `${m}m ${s}s` : `${s}s`;
}

export function LiveInvestigationView({ investigationId, onComplete, onCancel }: Props) {
  const [progress, setProgress] = useState<InvestigationProgress | null>(null);
  const [result, setResult] = useState<InvestigationResult | null>(null);
  const [elapsed, setElapsed] = useState(0);
  const [cancelling, setCancelling] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const startTimeRef = useRef(Date.now());

  // Poll progress every 2 seconds
  useEffect(() => {
    const interval = setInterval(async () => {
      try {
        const p = await invoke<InvestigationProgress>("get_investigation_progress", {
          investigationId,
        });
        setProgress(p);

        if (p.status === "Complete" || p.status === "Failed" || p.status === "Cancelled") {
          clearInterval(interval);
          // Fetch full result
          try {
            const r = await invoke<InvestigationResult>("get_investigation_result", {
              investigationId,
            });
            setResult(r);
          } catch {
            // Try loading from store
            try {
              const r = await invoke<InvestigationResult>("get_investigation", {
                investigationId,
              });
              setResult(r);
            } catch {
              // Result may not be available yet
            }
          }
          onComplete?.();
        }
      } catch {
        // Investigation may have completed or engine restarted
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [investigationId, onComplete]);

  // Elapsed time timer
  useEffect(() => {
    startTimeRef.current = Date.now();
    const interval = setInterval(() => {
      setElapsed(Math.floor((Date.now() - startTimeRef.current) / 1000));
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  async function handleCancel() {
    setCancelling(true);
    try {
      await invoke("cancel_investigation", { investigationId });
      onCancel?.();
    } catch (e) {
      setError(String(e));
      setCancelling(false);
    }
  }

  const isComplete = progress?.status === "Complete" || progress?.status === "Failed" || progress?.status === "Cancelled";

  // Show full result once complete
  if (isComplete && result) {
    return <InvestigationDetail investigationId={investigationId} result={result} />;
  }

  const questionsAnswered = progress?.questions_answered ?? 0;
  const questionsTotal = progress?.questions_total ?? 5;
  const progressPercent = questionsTotal > 0 ? (questionsAnswered / questionsTotal) * 100 : 0;
  const toolCalls = progress?.tool_calls_count ?? 0;
  const maxToolCalls = progress?.max_tool_calls ?? 0;
  const depth = progress?.depth ?? "Standard";

  return (
    <div className="space-y-4">
      {error && (
        <div className="rounded-lg border border-[var(--color-danger)] bg-[var(--color-danger)]/10 p-3 text-sm text-[var(--color-danger)]">
          {error}
        </div>
      )}

      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4 space-y-3">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            {!isComplete && (
              <span className="inline-block w-2 h-2 rounded-full bg-[var(--color-accent)] animate-pulse" />
            )}
            <span className="text-sm font-medium text-[var(--color-text-primary)]">
              {isComplete
                ? `Investigation ${progress?.status ?? "Complete"}`
                : progress?.current_activity || "Initializing investigation..."}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs px-2 py-0.5 rounded-full bg-[var(--color-accent)]/15 text-[var(--color-accent)] font-medium">
              {depth}
            </span>
            {!isComplete && (
              <button
                onClick={handleCancel}
                disabled={cancelling}
                className="px-3 py-1 rounded-md text-xs font-medium border border-[var(--color-danger)] text-[var(--color-danger)] hover:bg-[var(--color-danger)]/10 disabled:opacity-50 transition-colors"
              >
                {cancelling ? "Cancelling..." : "Cancel"}
              </button>
            )}
          </div>
        </div>

        {/* Progress bar */}
        <div>
          <div className="flex justify-between text-xs text-[var(--color-text-secondary)] mb-1">
            <span>Questions: {questionsAnswered}/{questionsTotal}</span>
            <span>{Math.round(progressPercent)}%</span>
          </div>
          <div className="w-full h-2 rounded-full bg-[var(--color-bg-primary)]">
            <div
              className="h-2 rounded-full bg-[var(--color-accent)] transition-all duration-500"
              style={{ width: `${progressPercent}%` }}
            />
          </div>
        </div>

        {/* Question step indicators */}
        <div className="flex items-center gap-1">
          {Array.from({ length: questionsTotal }, (_, i) => (
            <div
              key={i}
              className={`h-1.5 flex-1 rounded-full min-w-[20px] transition-colors ${
                i < questionsAnswered
                  ? "bg-[var(--color-accent)]"
                  : i === questionsAnswered && !isComplete
                    ? "bg-[var(--color-accent)]/40 animate-pulse"
                    : "bg-[var(--color-bg-tertiary)]"
              }`}
            />
          ))}
        </div>

        {/* Stats row */}
        <div className="flex gap-6 text-xs text-[var(--color-text-secondary)]">
          <div>
            <span className="text-[var(--color-text-muted)]">Elapsed: </span>
            <span className="font-medium text-[var(--color-text-primary)]">
              {formatElapsed(progress?.elapsed_secs ?? elapsed)}
            </span>
          </div>
          <div>
            <span className="text-[var(--color-text-muted)]">Tool Calls: </span>
            <span className="font-medium text-[var(--color-text-primary)]">
              {toolCalls}{maxToolCalls > 0 ? `/${maxToolCalls}` : ""}
            </span>
          </div>
          <div>
            <span className="text-[var(--color-text-muted)]">Findings: </span>
            <span
              className={`font-medium ${
                (progress?.findings_count ?? 0) > 0
                  ? "text-[var(--color-warning)]"
                  : "text-[var(--color-safe)]"
              }`}
            >
              {progress?.findings_count ?? 0}
            </span>
          </div>
        </div>

        {/* Target summary */}
        {progress?.target_summary && (
          <div className="text-xs text-[var(--color-text-muted)] pt-2 border-t border-[var(--color-border)]">
            Investigating: {progress.target_summary}
          </div>
        )}
      </div>
    </div>
  );
}
