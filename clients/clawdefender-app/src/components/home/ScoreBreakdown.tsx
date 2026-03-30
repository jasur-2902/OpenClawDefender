import { useEffect, useCallback, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import {
  PROTECTION_SCORE_EXPLAINER,
} from "../../constants/messages";
import type { BackendScoreFactor, FixAction } from "../../types";

interface ScoreBreakdownProps {
  open: boolean;
  onClose: () => void;
  factors: BackendScoreFactor[];
  totalScore: number;
}

function statusColor(status: string): string {
  if (status === "full") return "var(--color-safe)";
  if (status === "partial") return "var(--color-warning)";
  return "var(--color-danger)";
}

function StatusIcon({ status }: { status: string }) {
  if (status === "full") {
    return (
      <span
        className="inline-flex items-center justify-center w-5 h-5 rounded-full bg-[var(--color-safe-subtle)] text-[var(--color-safe)] text-xs"
        aria-label="Active"
      >
        &#10003;
      </span>
    );
  }
  if (status === "partial") {
    return (
      <span
        className="inline-flex items-center justify-center w-5 h-5 rounded-full bg-[var(--color-warning-subtle)] text-[var(--color-warning)] text-xs font-bold"
        aria-label="Partial"
      >
        !
      </span>
    );
  }
  return (
    <span
      className="inline-flex items-center justify-center w-5 h-5 rounded-full bg-[var(--color-danger-subtle)] text-[var(--color-danger)] text-xs"
      aria-label="Inactive"
    >
      &#10005;
    </span>
  );
}

function PointsBar({
  current,
  max,
  status,
}: {
  current: number;
  max: number;
  status: string;
}) {
  const pct = max > 0 ? (current / max) * 100 : 0;
  const color = statusColor(status);

  return (
    <div
      className="h-1.5 rounded-full bg-[var(--color-bg-tertiary)] overflow-hidden mt-1"
      role="progressbar"
      aria-valuenow={current}
      aria-valuemin={0}
      aria-valuemax={max}
      aria-label={`${current} of ${max} points`}
    >
      <div
        className="h-full rounded-full"
        style={{
          width: `${pct}%`,
          backgroundColor: color,
          transition: "width 0.5s ease-out, background-color 0.3s ease",
        }}
      />
    </div>
  );
}

export function ScoreBreakdown({
  open,
  onClose,
  factors,
  totalScore,
}: ScoreBreakdownProps) {
  const navigate = useNavigate();
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);

  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    },
    [onClose]
  );

  useEffect(() => {
    if (open) {
      document.addEventListener("keydown", handleKeyDown);
      requestAnimationFrame(() => closeButtonRef.current?.focus());
      return () => document.removeEventListener("keydown", handleKeyDown);
    }
  }, [open, handleKeyDown]);

  if (!open) return null;

  const handleFixAction = async (factor: BackendScoreFactor, actionIndex: number) => {
    const action = factor.fix_actions[actionIndex];
    if (!action) return;

    if (action.action_type === "navigate") {
      navigate(action.target);
      onClose();
      return;
    }

    try {
      const resultStr = await invoke<string>("execute_fix_action", {
        factorId: factor.id,
        actionIndex,
      });

      // Try to parse action result
      try {
        const result: FixAction = JSON.parse(resultStr);
        if (result.action_type === "navigate") {
          navigate(result.target);
          onClose();
        } else {
          setActionFeedback(`Action executed: ${result.label}`);
          setTimeout(() => setActionFeedback(null), 3000);
        }
      } catch {
        setActionFeedback("Action completed");
        setTimeout(() => setActionFeedback(null), 3000);
      }
    } catch (err) {
      setActionFeedback(`Failed: ${err}`);
      setTimeout(() => setActionFeedback(null), 3000);
    }
  };

  return (
    <>
      {/* Overlay */}
      <div
        className="fixed inset-0 bg-black/50 z-[var(--z-overlay)]"
        onClick={onClose}
        aria-hidden="true"
      />
      {/* Drawer */}
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Protection score breakdown"
        className="fixed bottom-0 left-0 right-0 z-[var(--z-modal)] bg-[var(--color-bg-secondary)] border-t border-[var(--color-border)] rounded-t-2xl max-h-[70vh] overflow-y-auto animate-slide-up"
        style={{
          animation: "slideUp 200ms var(--ease-out) forwards",
        }}
      >
        <div className="p-6">
          {/* Handle */}
          <div className="flex justify-center mb-4">
            <div className="w-10 h-1 rounded-full bg-[var(--color-bg-tertiary)]" />
          </div>

          <div className="flex items-center justify-between mb-2">
            <h2 className="text-lg font-semibold text-[var(--color-text-primary)]">
              Protection Score Breakdown
            </h2>
            <span className="text-2xl font-bold tabular-nums text-[var(--color-text-primary)]">
              {totalScore}/100
            </span>
          </div>

          <p className="text-sm text-[var(--color-text-secondary)] mb-6">
            {PROTECTION_SCORE_EXPLAINER}
          </p>

          {actionFeedback && (
            <div className="mb-4 p-2 rounded-lg bg-[var(--color-accent-subtle)] text-sm text-[var(--color-accent-text)]">
              {actionFeedback}
            </div>
          )}

          <div className="space-y-3">
            {factors.map((factor) => (
              <div
                key={factor.id}
                className="p-3 rounded-lg bg-[var(--color-bg-primary)] border border-[var(--color-border)]"
              >
                <div className="flex items-start gap-3">
                  <StatusIcon status={factor.status} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium text-[var(--color-text-primary)]">
                        {factor.name}
                      </span>
                      <span className="text-xs tabular-nums text-[var(--color-text-secondary)] ml-2">
                        {factor.current_points}/{factor.max_points}
                      </span>
                    </div>
                    <PointsBar
                      current={factor.current_points}
                      max={factor.max_points}
                      status={factor.status}
                    />
                    <p className="text-xs text-[var(--color-text-secondary)] mt-1.5">
                      {factor.details}
                    </p>
                    {factor.fix_actions.length > 0 && factor.status !== "full" && (
                      <div className="flex gap-2 mt-2">
                        {factor.fix_actions.map((action, idx) => (
                          <button
                            key={idx}
                            onClick={() => handleFixAction(factor, idx)}
                            className="text-xs font-medium text-[var(--color-accent)] hover:text-[var(--color-accent-hover)] px-2 py-1 rounded bg-[var(--color-accent-subtle)] hover:bg-[var(--color-accent-subtle)] transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--color-accent)]"
                          >
                            {action.label}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>

          <button
            ref={closeButtonRef}
            onClick={onClose}
            className="mt-6 w-full py-2.5 rounded-lg text-sm font-medium text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] bg-[var(--color-bg-tertiary)] hover:bg-[var(--color-border)] transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--color-accent)]"
          >
            Close
          </button>
        </div>
      </div>

      <style>{`
        @keyframes slideUp {
          from { transform: translateY(100%); }
          to { transform: translateY(0); }
        }
      `}</style>
    </>
  );
}
