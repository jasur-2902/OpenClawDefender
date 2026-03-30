import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { ShieldIcon, getTrustColor, getTrustLabel } from "./ShieldIcon";
import { CapabilityIcons } from "./CapabilityIcons";
import type { ToolCardData } from "../../types";

interface ToolCardProps {
  tool: ToolCardData;
}

export function ToolCard({ tool }: ToolCardProps) {
  const navigate = useNavigate();

  const statusLine = useMemo(() => {
    if (!tool.is_wrapped) return "Not wrapped — not monitored";

    if (tool.behavioral_status === "learning") {
      const pct = Math.round(tool.learning_progress * 100);
      return `Learning — ${pct}% complete`;
    }

    const parts: string[] = [];
    parts.push("Active");
    parts.push(`${tool.event_count_today} action${tool.event_count_today !== 1 ? "s" : ""} today`);

    if (tool.blocked_count_today > 0) {
      parts.push(`${tool.blocked_count_today} blocked`);
    } else if (tool.health_warnings.length > 0) {
      const critical = tool.health_warnings.filter((w) => w.severity === "critical").length;
      if (critical > 0) {
        parts.push(`${critical} issue${critical !== 1 ? "s" : ""} found`);
      } else {
        parts.push("No issues");
      }
    } else {
      parts.push("No issues");
    }

    return parts.join(" · ");
  }, [tool]);

  const statusColor = useMemo(() => {
    if (!tool.is_wrapped) return "var(--color-text-muted)";
    if (tool.behavioral_status === "learning") return "var(--color-info)";
    if (tool.blocked_count_today > 0) return "var(--color-warning)";
    if (tool.health_warnings.some((w) => w.severity === "critical"))
      return "var(--color-danger)";
    return "var(--color-text-secondary)";
  }, [tool]);

  const hasCriticalWarning = tool.health_warnings.some(
    (w) => w.severity === "critical"
  );

  const ariaLabel = `${tool.server_name}, ${tool.client_app}, ${
    tool.is_wrapped
      ? `${getTrustLabel(tool.trust_level)} trust level`
      : "Not protected"
  }${hasCriticalWarning ? ", has critical warning" : ""}`;

  return (
    <button
      onClick={() => navigate(`/tools/${encodeURIComponent(tool.server_name)}`)}
      aria-label={ariaLabel}
      className={`w-full text-left rounded-lg border bg-[var(--color-bg-secondary)] p-4 cursor-pointer transition-colors duration-150 hover:bg-[var(--color-bg-tertiary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-1 ${
        !tool.is_wrapped
          ? "opacity-60 border-[var(--color-border)]"
          : hasCriticalWarning
            ? "border-[var(--color-danger-border)]"
            : "border-[var(--color-border)] hover:border-[var(--color-accent-subtle)]"
      }`}
    >
      {/* Header */}
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2 min-w-0 flex-1">
          <span className="text-base font-medium text-[var(--color-text-primary)] truncate" title={tool.server_name}>
            {tool.server_name}
          </span>
        </div>
        {tool.is_wrapped && (
          <span
            role="status"
            aria-label={`Trust level: ${getTrustLabel(tool.trust_level)}${tool.trust_customized ? " (customized)" : ""}`}
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium shrink-0"
            style={{
              color: getTrustColor(tool.trust_level),
              backgroundColor: `color-mix(in srgb, ${getTrustColor(tool.trust_level)} 15%, transparent)`,
            }}
          >
            <ShieldIcon level={tool.trust_level} size={12} />
            {getTrustLabel(tool.trust_level)}
            {tool.trust_customized && (
              <span className="text-[10px] opacity-70">(custom)</span>
            )}
          </span>
        )}
      </div>

      {/* Client app */}
      <p className="text-xs text-[var(--color-text-muted)] mb-3 truncate">
        {tool.client_app}
      </p>

      {/* Capabilities */}
      <div className="mb-3">
        <CapabilityIcons capabilities={tool.capabilities} />
      </div>

      {/* Status line */}
      <p className="text-xs mb-2" style={{ color: statusColor }}>
        {statusLine}
      </p>

      {/* Health warning strip */}
      {hasCriticalWarning && (
        <div role="alert" className="mt-2 px-2 py-1 rounded bg-[var(--color-danger-light)] text-[var(--color-danger)] text-xs">
          {tool.health_warnings.find((w) => w.severity === "critical")?.title}
        </div>
      )}

      {/* Last unusual activity */}
      {tool.last_unusual_activity && (
        <p className="text-[10px] text-[var(--color-text-muted)] mt-2 truncate">
          Last unusual: {formatRelativeTime(tool.last_unusual_activity)}
        </p>
      )}

      {/* Not wrapped CTA */}
      {!tool.is_wrapped && (
        <div className="mt-3 flex items-center gap-1">
          <span className="text-xs font-medium text-[var(--color-accent)]">
            Protect this tool
          </span>
          <svg
            width="12"
            height="12"
            viewBox="0 0 24 24"
            fill="none"
            stroke="var(--color-accent)"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <polyline points="9 18 15 12 9 6" />
          </svg>
        </div>
      )}
    </button>
  );
}

function formatRelativeTime(timestamp: string): string {
  const diff = Date.now() - new Date(timestamp).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}
