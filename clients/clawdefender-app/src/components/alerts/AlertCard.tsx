import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { getThreatColor, type ThreatLevel } from "../../utils/threatLevel";
import { useAlertStore } from "../../stores/alertStore";
import { useToastStore } from "../notifications/ToastContainer";
import type { IntelligentAlert, AlertAction } from "../../types";

const severityOrder: Record<string, number> = {
  dangerous: 0,
  suspicious: 1,
  unusual: 2,
  info: 3,
};

const severityLabels: Record<string, string> = {
  dangerous: "Dangerous",
  suspicious: "Suspicious",
  unusual: "Unusual",
  info: "Info",
};

function relativeTime(ts: string): string {
  try {
    const now = Date.now();
    const then = new Date(ts).getTime();
    const diffMs = now - then;
    const diffMin = Math.floor(diffMs / 60_000);
    if (diffMin < 1) return "just now";
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHr = Math.floor(diffMin / 60);
    if (diffHr < 24) return `${diffHr}h ago`;
    const diffDay = Math.floor(diffHr / 24);
    return `${diffDay}d ago`;
  } catch {
    return ts;
  }
}

function getSeverityBg(severity: string): string {
  switch (severity) {
    case "dangerous":
      return "var(--color-danger-subtle)";
    case "suspicious":
      return "var(--color-warning-subtle)";
    case "unusual":
      return "var(--color-info-subtle)";
    default:
      return "var(--color-info-subtle)";
  }
}

interface AlertCardProps {
  alert: IntelligentAlert;
  compact?: boolean;
}

export function AlertCard({ alert, compact }: AlertCardProps) {
  const navigate = useNavigate();
  const dismissAlert = useAlertStore((s) => s.dismissAlert);
  const resolveAlert = useAlertStore((s) => s.resolveAlert);
  const addToast = useToastStore((s) => s.addToast);

  const color = getThreatColor((alert.severity || "info") as ThreatLevel);
  const bg = getSeverityBg(alert.severity);
  const label = severityLabels[alert.severity] || "Info";

  async function handleAction(action: AlertAction) {
    switch (action.action_type) {
      case "restrict":
        await resolveAlert(alert.id, "restricted");
        addToast({
          title: "Done. I'll keep an eye on it.",
          severity: "success",
        });
        if (alert.server_name) {
          navigate(`/tools/${encodeURIComponent(alert.server_name)}`);
        }
        break;
      case "allow":
        try {
          if (action.params) {
            await invoke("add_rule", { rule: action.params });
          }
          await resolveAlert(alert.id, "allowed");
          addToast({
            title: "Got it. I added a rule so this won't be blocked again.",
            severity: "success",
          });
        } catch {
          addToast({ title: "Could not add that rule.", severity: "danger" });
        }
        break;
      case "dismiss":
        await dismissAlert(alert.id);
        addToast({ title: "Dismissed.", severity: "info" });
        break;
      case "view_details":
        navigate(`/alerts/${alert.id}`);
        break;
      case "ask_claw":
        navigate("/ask", { state: { prefill: `Tell me about: ${alert.title}` } });
        break;
      default:
        navigate(`/alerts/${alert.id}`);
    }
  }

  async function handleDismiss() {
    await dismissAlert(alert.id);
    addToast({ title: "Dismissed.", severity: "info" });
  }

  if (compact) {
    return (
      <div
        className="rounded-lg border-l-[3px] bg-[var(--color-bg-secondary)] border border-[var(--color-border)] p-3 opacity-70"
        style={{ borderLeftColor: color }}
      >
        <div className="flex items-center gap-2">
          <span
            role="status"
            aria-label={`${label} severity`}
            className="inline-flex items-center text-[10px] uppercase font-semibold tracking-wide px-2 py-0.5 rounded-full"
            style={{ color, backgroundColor: bg }}
          >
            {label}
          </span>
          <span className="text-sm text-[var(--color-text-primary)] truncate flex-1">
            {alert.title}
          </span>
          <span className="text-xs text-[var(--color-text-muted)] shrink-0">
            {relativeTime(alert.created_at)}
          </span>
          {alert.resolved_by && (
            <span className="text-[10px] uppercase font-semibold px-2 py-0.5 rounded-full bg-[var(--color-bg-tertiary)] text-[var(--color-text-muted)]">
              {alert.resolved_by === "dismissed" ? "Dismissed" : "Resolved"}
            </span>
          )}
        </div>
      </div>
    );
  }

  return (
    <div
      className="rounded-lg border-l-[3px] bg-[var(--color-bg-secondary)] border border-[var(--color-border)] p-4 transition-colors hover:bg-[var(--color-bg-tertiary)]"
      style={{ borderLeftColor: color }}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1.5">
            <span
              role="status"
              aria-label={`${label} alert: ${alert.title}`}
              className="inline-flex items-center text-[10px] uppercase font-semibold tracking-wide px-2 py-0.5 rounded-full"
              style={{ color, backgroundColor: bg }}
            >
              {label}
            </span>
            {alert.kill_chain && (
              <span className="inline-flex items-center text-[10px] uppercase font-semibold tracking-wide px-2 py-0.5 rounded-full bg-[var(--color-danger-subtle)] text-[var(--color-danger)]">
                Kill Chain
              </span>
            )}
            <span className="text-xs text-[var(--color-text-muted)]">
              {relativeTime(alert.created_at)}
              {alert.dedup_count > 1 && alert.updated_at !== alert.created_at && (
                <>, last {relativeTime(alert.updated_at)}</>
              )}
            </span>
          </div>
          <p className="text-sm font-medium text-[var(--color-text-primary)] mb-1">
            {alert.title}
          </p>

          {/* AI analysis badge */}
          {alert.ai_risk_level && (
            <div className="flex items-center gap-2 mb-1.5">
              <span
                className="inline-flex items-center text-[10px] uppercase font-semibold tracking-wide px-2 py-0.5 rounded-full bg-[var(--color-accent-subtle)] text-[var(--color-accent)]"
              >
                AI: {alert.ai_risk_level}
              </span>
              {alert.ai_confidence != null && (
                <span className="text-[10px] text-[var(--color-text-muted)]">
                  {(alert.ai_confidence * 100).toFixed(0)}% confidence
                </span>
              )}
            </div>
          )}

          {/* AI summary (when available, takes precedence as the primary description) */}
          {alert.ai_summary ? (
            <>
              <AlertDescription text={alert.ai_summary} />
              {alert.description !== alert.ai_summary && (
                <AlertDescription text={alert.description} />
              )}
            </>
          ) : (
            <AlertDescription text={alert.description} />
          )}

          {/* Recommendation callout -- prefer AI recommendation if available */}
          {(alert.ai_recommendation || alert.recommendation) && (
            <div
              className="text-xs text-[var(--color-text-secondary)] mb-2 px-3 py-2 rounded-md border-l-2 bg-[var(--color-bg-tertiary)]"
              style={{ borderLeftColor: color }}
            >
              {alert.ai_recommendation || alert.recommendation}
            </div>
          )}

          {/* Dedup indicator */}
          {alert.dedup_count > 1 && (
            <p className="text-xs text-[var(--color-text-muted)] mb-2">
              This has happened {alert.dedup_count} times
            </p>
          )}

          {/* Server attribution */}
          {alert.server_name && (
            <div className="text-xs text-[var(--color-text-muted)] mb-2">
              Server:{" "}
              <Link
                to={`/tools/${encodeURIComponent(alert.server_name)}`}
                className="text-[var(--color-accent)] hover:underline"
              >
                {alert.server_name}
              </Link>
            </div>
          )}
        </div>
      </div>

      {/* Action buttons */}
      <div className="flex items-center gap-2 mt-1 flex-wrap">
        {alert.actions.map((action) => (
          <button
            key={action.id}
            onClick={() => handleAction(action)}
            className={`text-xs px-2.5 py-1 rounded border transition-colors ${
              action.action_type === "restrict"
                ? "border-[var(--color-danger)] text-[var(--color-danger)] hover:bg-[var(--color-danger-subtle)]"
                : action.action_type === "allow"
                  ? "border-[var(--color-safe)] text-[var(--color-safe)] hover:bg-[var(--color-safe-subtle)]"
                  : "border-[var(--color-border)] text-[var(--color-text-secondary)] hover:bg-[var(--color-bg-tertiary)]"
            }`}
          >
            {action.label}
          </button>
        ))}
        <Link
          to={`/alerts/${alert.id}`}
          className="text-xs px-2.5 py-1 rounded border border-[var(--color-border)] text-[var(--color-text-secondary)] hover:bg-[var(--color-bg-tertiary)] transition-colors"
        >
          View Details
        </Link>
        <Link
          to="/ask"
          state={{ prefill: `Tell me about the alert: ${alert.title}` }}
          className="text-xs px-2.5 py-1 rounded border border-[var(--color-border)] text-[var(--color-accent)] hover:bg-[var(--color-bg-tertiary)] transition-colors"
        >
          Ask Rook
        </Link>
        <button
          onClick={handleDismiss}
          className="text-xs px-2.5 py-1 rounded border border-[var(--color-border)] text-[var(--color-text-muted)] hover:bg-[var(--color-bg-tertiary)] transition-colors ml-auto"
        >
          Dismiss
        </button>
      </div>
    </div>
  );
}

const DESCRIPTION_TRUNCATE_LEN = 150;

function AlertDescription({ text }: { text: string }) {
  const [expanded, setExpanded] = useState(false);
  const chars = Array.from(text);
  const isLong = chars.length > DESCRIPTION_TRUNCATE_LEN;

  if (!isLong) {
    return (
      <p className="text-xs text-[var(--color-text-secondary)] mb-2">
        {text}
      </p>
    );
  }

  return (
    <p className="text-xs text-[var(--color-text-secondary)] mb-2">
      {expanded ? text : chars.slice(0, DESCRIPTION_TRUNCATE_LEN).join("") + "\u2026"}
      <button
        onClick={(e) => {
          e.stopPropagation();
          setExpanded(!expanded);
        }}
        className="ml-1 text-[var(--color-accent)] hover:text-[var(--color-accent-hover)] transition-colors"
      >
        {expanded ? "Read less" : "Read more"}
      </button>
    </p>
  );
}

/** Sort alerts: dangerous first, kill chain at top within dangerous, then by time */
export function sortAlerts(alerts: IntelligentAlert[]): IntelligentAlert[] {
  return [...alerts].sort((a, b) => {
    const sa = severityOrder[a.severity] ?? 9;
    const sb = severityOrder[b.severity] ?? 9;
    if (sa !== sb) return sa - sb;
    // Kill chain alerts at top within same severity
    const aKc = a.kill_chain ? 0 : 1;
    const bKc = b.kill_chain ? 0 : 1;
    if (aKc !== bKc) return aKc - bKc;
    return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
  });
}
