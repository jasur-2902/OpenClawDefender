import { useEffect, useCallback, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { PROTECTION_SCORE_EXPLAINER } from "../../constants/messages";

export interface ScoreBreakdownFactor {
  key: string;
  label: string;
  description: string;
  points: number;
  maxPoints: number;
  status: "good" | "warn" | "bad";
  fixRoute?: string;
  fixAction?: () => void;
  fixLabel?: string;
}

interface ScoreBreakdownDrawerProps {
  open: boolean;
  onClose: () => void;
  factors: ScoreBreakdownFactor[];
  totalScore: number;
}

function StatusIcon({ status }: { status: "good" | "warn" | "bad" }) {
  if (status === "good") {
    return (
      <span
        className="inline-flex items-center justify-center w-5 h-5 rounded-full bg-[var(--color-safe-subtle)] text-[var(--color-safe)] text-xs"
        aria-label="Active"
      >
        &#10003;
      </span>
    );
  }
  if (status === "warn") {
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

export function ScoreBreakdownDrawer({
  open,
  onClose,
  factors,
  totalScore,
}: ScoreBreakdownDrawerProps) {
  const navigate = useNavigate();
  const closeButtonRef = useRef<HTMLButtonElement>(null);

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

  const handleFixClick = (factor: ScoreBreakdownFactor) => {
    if (factor.fixAction) {
      factor.fixAction();
    } else if (factor.fixRoute) {
      navigate(factor.fixRoute);
      onClose();
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
        className="fixed bottom-0 left-0 right-0 z-[var(--z-modal)] bg-[var(--color-bg-secondary)] border-t border-[var(--color-border)] rounded-t-2xl max-h-[70vh] overflow-y-auto"
        style={{
          animation: "scoreDrawerSlideUp 200ms var(--ease-out) forwards",
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

          <div className="space-y-3">
            {factors.map((factor) => (
              <div
                key={factor.key}
                className="flex items-center gap-3 p-3 rounded-lg bg-[var(--color-bg-primary)] border border-[var(--color-border)]"
              >
                <StatusIcon status={factor.status} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium text-[var(--color-text-primary)]">
                      {factor.label}
                    </span>
                    <span className="text-xs tabular-nums text-[var(--color-text-secondary)] ml-2">
                      {factor.points}/{factor.maxPoints}
                    </span>
                  </div>
                  <p className="text-xs text-[var(--color-text-secondary)] mt-0.5 truncate">
                    {factor.description}
                  </p>
                </div>
                {factor.status !== "good" &&
                  (factor.fixRoute || factor.fixAction) && (
                    <button
                      onClick={() => handleFixClick(factor)}
                      className="text-xs font-medium text-[var(--color-accent)] hover:text-[var(--color-accent-hover)] whitespace-nowrap ml-2"
                    >
                      {factor.fixLabel ?? "Fix"}
                    </button>
                  )}
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
        @keyframes scoreDrawerSlideUp {
          from { transform: translateY(100%); }
          to { transform: translateY(0); }
        }
      `}</style>
    </>
  );
}
