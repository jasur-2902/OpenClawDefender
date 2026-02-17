interface SuspiciousEvent {
  timestamp: string;
  action: string;
}

interface AlertData {
  id: string;
  level: string;
  message: string;
  details: string;
  events: SuspiciousEvent[];
  kill_chain?: string;
}

interface AlertWindowProps {
  alert: AlertData;
  onKillProcess: (id: string) => void;
  onViewTimeline: (id: string) => void;
  onDismiss: (id: string) => void;
}

export function AlertWindow({
  alert,
  onKillProcess,
  onViewTimeline,
  onDismiss,
}: AlertWindowProps) {
  const isCritical = alert.level === "critical";

  return (
    <div
      role="alert"
      aria-live="assertive"
      aria-label={`Security alert: ${alert.level} - ${alert.message}`}
      className="w-full max-w-lg mx-auto border rounded-lg shadow-2xl overflow-hidden"
      style={{
        backgroundColor: isCritical
          ? "var(--color-bg-secondary)"
          : "var(--color-bg-secondary)",
        borderColor: isCritical ? "var(--color-danger)" : "var(--color-border)",
      }}
    >
      {/* Header */}
      <div
        className="px-4 py-3 flex items-center gap-2"
        style={{
          backgroundColor: isCritical
            ? "var(--color-danger)"
            : "var(--color-warning)",
        }}
      >
        <span className="text-white text-sm font-bold tracking-wide">
          SECURITY ALERT
        </span>
        <span className="ml-auto text-white text-xs uppercase font-semibold opacity-80">
          {alert.level}
        </span>
      </div>

      {/* Message */}
      <div className="px-4 py-3 space-y-3">
        <p className="text-sm font-medium text-[var(--color-text-primary)]">
          {alert.message}
        </p>

        {alert.details && (
          <p className="text-xs text-[var(--color-text-secondary)]">
            {alert.details}
          </p>
        )}

        {/* Kill chain info */}
        {alert.kill_chain && (
          <div className="px-3 py-2 rounded bg-[var(--color-danger)]/10 border border-[var(--color-danger)]/30">
            <p className="text-xs font-semibold text-[var(--color-danger)] mb-1">
              Kill Chain Pattern Detected
            </p>
            <p className="text-xs text-[var(--color-text-secondary)]">
              {alert.kill_chain}
            </p>
          </div>
        )}

        {/* Suspicious events */}
        {alert.events.length > 0 && (
          <div>
            <p className="text-xs font-semibold text-[var(--color-text-secondary)] mb-1.5">
              Suspicious Events
            </p>
            <div className="space-y-1 max-h-40 overflow-y-auto">
              {alert.events.map((evt, i) => (
                <div
                  key={i}
                  className="flex gap-2 text-xs px-2 py-1.5 rounded bg-[var(--color-bg-tertiary)]"
                >
                  <span className="text-[var(--color-text-secondary)] font-mono shrink-0">
                    {formatTime(evt.timestamp)}
                  </span>
                  <span className="text-[var(--color-text-primary)] break-all">
                    {evt.action}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="flex gap-2 px-4 py-3 border-t border-[var(--color-border)]">
        <button
          onClick={() => onKillProcess(alert.id)}
          className="px-4 py-2 text-xs font-bold rounded bg-[var(--color-danger)] text-white hover:brightness-110 transition-all"
        >
          Kill Process
        </button>
        <button
          onClick={() => onViewTimeline(alert.id)}
          className="px-4 py-2 text-xs font-medium rounded bg-[var(--color-bg-tertiary)] text-[var(--color-text-primary)] hover:bg-[var(--color-border)] transition-colors"
        >
          View in Timeline
        </button>
        <button
          onClick={() => onDismiss(alert.id)}
          className="ml-auto px-4 py-2 text-xs font-medium rounded bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] hover:bg-[var(--color-border)] transition-colors"
        >
          Dismiss
        </button>
      </div>
    </div>
  );
}

function formatTime(timestamp: string): string {
  try {
    const d = new Date(timestamp);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch {
    return timestamp;
  }
}

export type { AlertData, SuspiciousEvent };
