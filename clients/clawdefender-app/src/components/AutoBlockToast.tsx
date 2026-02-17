import { useState, useEffect } from "react";

interface AutoBlockInfo {
  id: string;
  server_name: string;
  action: string;
  anomaly_score: number;
}

interface AutoBlockToastProps {
  block: AutoBlockInfo;
  onDismiss: (id: string) => void;
  onReview: (id: string) => void;
  onTrust: (id: string) => void;
}

export function AutoBlockToast({
  block,
  onDismiss,
  onReview,
  onTrust,
}: AutoBlockToastProps) {
  const [visible, setVisible] = useState(false);
  const [exiting, setExiting] = useState(false);

  useEffect(() => {
    // Trigger slide-in
    requestAnimationFrame(() => setVisible(true));

    const timer = setTimeout(() => {
      dismiss();
    }, 10000);

    return () => clearTimeout(timer);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function dismiss() {
    setExiting(true);
    setTimeout(() => onDismiss(block.id), 300);
  }

  return (
    <div
      className="w-80 bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-lg shadow-xl overflow-hidden"
      style={{
        transform: visible && !exiting ? "translateX(0)" : "translateX(120%)",
        opacity: visible && !exiting ? 1 : 0,
        transition: "transform 300ms ease, opacity 300ms ease",
      }}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2 bg-[var(--color-bg-tertiary)]">
        <div className="flex items-center gap-2">
          <span className="inline-block w-2 h-2 rounded-full bg-[var(--color-warning)]" />
          <span className="text-xs font-semibold text-[var(--color-warning)]">
            Auto-Blocked
          </span>
        </div>
        <button
          onClick={dismiss}
          className="text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] text-sm leading-none"
        >
          x
        </button>
      </div>

      {/* Body */}
      <div className="px-3 py-2 space-y-1">
        <p className="text-sm text-[var(--color-text-primary)]">
          <span className="font-medium">{block.server_name}</span>
        </p>
        <p className="text-xs text-[var(--color-text-secondary)] break-all">
          {block.action}
        </p>
        <p className="text-xs text-[var(--color-text-secondary)]">
          Anomaly score:{" "}
          <span className="font-mono text-[var(--color-warning)]">
            {block.anomaly_score.toFixed(2)}
          </span>
        </p>
      </div>

      {/* Actions */}
      <div className="flex gap-2 px-3 py-2 border-t border-[var(--color-border)]">
        <button
          onClick={() => onReview(block.id)}
          className="flex-1 py-1.5 text-xs font-medium rounded bg-[var(--color-bg-tertiary)] text-[var(--color-text-primary)] hover:bg-[var(--color-border)] transition-colors"
        >
          Review
        </button>
        <button
          onClick={() => onTrust(block.id)}
          className="flex-1 py-1.5 text-xs font-medium rounded bg-[var(--color-accent)] text-white hover:bg-[var(--color-accent-hover)] transition-colors"
        >
          Trust This Action
        </button>
      </div>
    </div>
  );
}

export type { AutoBlockInfo };
