import { useEffect, useState, useCallback } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { PageHeader } from "../components/PageHeader";
import { ThreatStory } from "../components/alerts/ThreatStory";
import { LiveInvestigationView } from "../components/investigation/LiveInvestigationView";
import { useAlertStore } from "../stores/alertStore";
import { useToastStore } from "../components/notifications/ToastContainer";
import { getThreatColor, type ThreatLevel } from "../utils/threatLevel";
import type { IntelligentAlert, AlertAction, InvestigationProgress } from "../types";
import { truncateEnd } from "../utils/textUtils";
import { useAiStatus } from "../hooks/useAiStatus";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

function formatFullTime(ts: string): string {
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

const severityLabels: Record<string, string> = {
  dangerous: "Dangerous",
  suspicious: "Suspicious",
  unusual: "Unusual",
  info: "Info",
};

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

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function AlertDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const resolveAlert = useAlertStore((s) => s.resolveAlert);
  const dismissAlert = useAlertStore((s) => s.dismissAlert);
  const addToast = useToastStore((s) => s.addToast);

  const [alert, setAlert] = useState<IntelligentAlert | null>(null);
  const [loading, setLoading] = useState(true);
  const [investigationId, setInvestigationId] = useState<string | null>(null);
  const [startingInvestigation, setStartingInvestigation] = useState(false);
  const { canInvestigate } = useAiStatus();

  useEffect(() => {
    if (!id) return;
    setLoading(true);
    invoke<IntelligentAlert | null>("get_alert_detail", { alertId: id })
      .then((data) => {
        setAlert(data ?? null);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [id]);

  const handleAction = useCallback(
    async (action: AlertAction) => {
      if (!alert) return;
      switch (action.action_type) {
        case "restrict":
          await resolveAlert(alert.id, "restricted");
          addToast({ title: "Done. I'll keep an eye on it.", severity: "success" });
          if (alert.server_name) {
            navigate(`/tools/${encodeURIComponent(alert.server_name)}`);
          } else {
            navigate("/alerts");
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
            navigate("/alerts");
          } catch {
            addToast({ title: "Could not add that rule.", severity: "danger" });
          }
          break;
        case "dismiss":
          await dismissAlert(alert.id);
          addToast({ title: "Dismissed.", severity: "info" });
          navigate("/alerts");
          break;
        case "ask_claw":
          navigate("/ask", {
            state: { prefill: `Tell me about: ${alert.title}` },
          });
          break;
        default:
          break;
      }
    },
    [alert, resolveAlert, dismissAlert, addToast, navigate]
  );

  const handleRestrict = useCallback(async () => {
    if (!alert) return;
    await resolveAlert(alert.id, "restricted");
    addToast({ title: "Done. I'll keep an eye on it.", severity: "success" });
    if (alert.server_name) {
      navigate(`/tools/${encodeURIComponent(alert.server_name)}`);
    } else {
      navigate("/alerts");
    }
  }, [alert, resolveAlert, addToast, navigate]);

  const handleKeepBlocking = useCallback(async () => {
    if (!alert) return;
    await resolveAlert(alert.id, "kept_blocking");
    addToast({ title: "Got it. I'll keep blocking this.", severity: "success" });
    navigate("/alerts");
  }, [alert, resolveAlert, addToast, navigate]);

  const handleDismiss = useCallback(async () => {
    if (!alert) return;
    await dismissAlert(alert.id);
    addToast({ title: "Dismissed.", severity: "info" });
    navigate("/alerts");
  }, [alert, dismissAlert, addToast, navigate]);

  if (loading) {
    return (
      <div className="p-6">
        <PageHeader
          title="Alert Detail"
          breadcrumbs={[{ label: "Alerts", to: "/alerts" }, { label: "Loading..." }]}
        />
        <div className="flex justify-center py-16">
          <span className="text-sm text-[var(--color-text-muted)]">Loading...</span>
        </div>
      </div>
    );
  }

  if (!alert) {
    return (
      <div className="p-6">
        <PageHeader
          title="Alert Not Found"
          breadcrumbs={[{ label: "Alerts", to: "/alerts" }, { label: "Not Found" }]}
        />
        <div className="flex flex-col items-center justify-center py-16 text-center">
          <p className="text-sm text-[var(--color-text-secondary)] mb-4">
            This alert may have been dismissed or does not exist.
          </p>
          <Link to="/alerts" className="text-sm text-[var(--color-accent)] hover:underline">
            Back to Alerts
          </Link>
        </div>
      </div>
    );
  }

  const color = getThreatColor((alert.severity || "info") as ThreatLevel);
  const bg = getSeverityBg(alert.severity);
  const label = severityLabels[alert.severity] || "Info";
  const isResolved = alert.status === "resolved" || alert.status === "dismissed";
  const isKillChain = !!alert.kill_chain;

  return (
    <div className="p-6 max-w-3xl space-y-6">
      <PageHeader
        title="Alert Detail"
        breadcrumbs={[
          { label: "Alerts", to: "/alerts" },
          {
            label: truncateEnd(alert.title, 40),
          },
        ]}
      />

      {/* Alert header card */}
      <div
        className="rounded-lg border-l-[3px] bg-[var(--color-bg-secondary)] border border-[var(--color-border)] p-5"
        style={{ borderLeftColor: color }}
      >
        <div className="flex items-center gap-2 mb-3">
          <span
            role="status"
            aria-label={`${label} severity alert`}
            className="inline-flex items-center text-[10px] uppercase font-semibold tracking-wide px-2 py-0.5 rounded-full"
            style={{ color, backgroundColor: bg }}
          >
            {label}
          </span>
          {isKillChain && (
            <span className="inline-flex items-center text-[10px] uppercase font-semibold tracking-wide px-2 py-0.5 rounded-full bg-[var(--color-danger-subtle)] text-[var(--color-danger)]">
              Kill Chain
            </span>
          )}
          <span className="text-xs text-[var(--color-text-muted)]">
            {relativeTime(alert.created_at)}
          </span>
          {isResolved && (
            <span className="text-[10px] uppercase font-semibold px-2 py-0.5 rounded-full bg-[var(--color-bg-tertiary)] text-[var(--color-text-muted)]">
              {alert.status === "dismissed" ? "Dismissed" : "Resolved"}
            </span>
          )}
        </div>

        <h2 className="text-lg font-semibold text-[var(--color-text-primary)] mb-2">
          {alert.title}
        </h2>

        <p className="text-sm text-[var(--color-text-secondary)] mb-4">
          {alert.description}
        </p>

        {/* AI Analysis Section */}
        {(alert.ai_summary || alert.ai_risk_level) && (
          <div className="mb-4 px-4 py-3 rounded-lg bg-[var(--color-info-subtle)] border border-[var(--color-info-border)]">
            <div className="flex items-center gap-2 mb-2">
              <span className="inline-block w-2 h-2 rounded-full bg-[var(--color-accent)]" aria-hidden="true" />
              <span className="text-xs font-semibold text-[var(--color-text-primary)] uppercase tracking-wide">
                AI Analysis
              </span>
              {alert.ai_risk_level && (
                <span className="text-[10px] uppercase font-semibold px-2 py-0.5 rounded-full bg-[var(--color-accent-subtle)] text-[var(--color-accent)]">
                  {alert.ai_risk_level} risk
                </span>
              )}
              {alert.ai_confidence != null && (
                <span className="text-[10px] text-[var(--color-text-muted)]">
                  {(alert.ai_confidence * 100).toFixed(0)}% confidence
                </span>
              )}
            </div>
            {alert.ai_summary && (
              <p className="text-sm text-[var(--color-text-primary)] mb-2">
                {alert.ai_summary}
              </p>
            )}
            {alert.ai_recommendation && (
              <p className="text-sm text-[var(--color-text-secondary)]">
                Recommended: {alert.ai_recommendation}
              </p>
            )}
          </div>
        )}

        {/* Recommendation (fallback to non-AI recommendation) */}
        {alert.recommendation && !alert.ai_recommendation && (
          <div
            className="text-sm text-[var(--color-text-secondary)] mb-4 px-3 py-2 rounded-md border-l-2 bg-[var(--color-bg-tertiary)]"
            style={{ borderLeftColor: color }}
          >
            {alert.recommendation}
          </div>
        )}
        {alert.ai_recommendation && (
          <div
            className="text-sm text-[var(--color-text-secondary)] mb-4 px-3 py-2 rounded-md border-l-2 bg-[var(--color-bg-tertiary)]"
            style={{ borderLeftColor: color }}
          >
            {alert.ai_recommendation}
          </div>
        )}

        {/* Dedup */}
        {alert.dedup_count > 1 && (
          <p className="text-xs text-[var(--color-text-muted)] mb-4">
            This has happened {alert.dedup_count} times
          </p>
        )}

        {/* Metadata grid */}
        <div className="grid grid-cols-3 gap-4 text-sm mb-4">
          <div>
            <p className="text-xs text-[var(--color-text-muted)] mb-0.5">Server</p>
            <p className="text-[var(--color-text-primary)] font-medium">
              {alert.server_name ? (
                <Link
                  to={`/tools/${encodeURIComponent(alert.server_name)}`}
                  className="text-[var(--color-accent)] hover:underline"
                >
                  {alert.server_name}
                </Link>
              ) : (
                "Unknown"
              )}
            </p>
          </div>
          <div>
            <p className="text-xs text-[var(--color-text-muted)] mb-0.5">First Seen</p>
            <p className="text-[var(--color-text-primary)]">
              {formatFullTime(alert.created_at)}
            </p>
          </div>
          <div>
            <p className="text-xs text-[var(--color-text-muted)] mb-0.5">Type</p>
            <p className="text-[var(--color-text-primary)] capitalize">
              {alert.alert_type.replace(/_/g, " ")}
            </p>
          </div>
        </div>

        {/* Source events */}
        {alert.source_events.length > 0 && (
          <div className="mb-4">
            <p className="text-xs text-[var(--color-text-muted)] mb-1">
              Related Events ({alert.source_events.length})
            </p>
            <div className="flex flex-wrap gap-1">
              {alert.source_events.slice(0, 6).map((eid) => (
                <span
                  key={eid}
                  className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--color-bg-tertiary)] text-[var(--color-text-muted)]"
                >
                  {eid.slice(0, 8)}
                </span>
              ))}
              {alert.source_events.length > 6 && (
                <span className="text-[10px] text-[var(--color-text-muted)]">
                  +{alert.source_events.length - 6} more
                </span>
              )}
            </div>
          </div>
        )}

        {/* Action buttons */}
        {!isResolved && (
          <div className="flex items-center gap-2 pt-3 border-t border-[var(--color-border)] flex-wrap">
            {alert.actions.map((action) => (
              <button
                key={action.id}
                onClick={() => handleAction(action)}
                className={`text-xs px-3 py-1.5 rounded-lg border transition-colors ${
                  action.action_type === "restrict"
                    ? "border-[var(--color-danger)] text-[var(--color-danger)] hover:bg-[var(--color-danger-subtle)]"
                    : action.action_type === "allow"
                      ? "bg-[var(--color-safe)] text-white hover:opacity-90 border-transparent"
                      : "border-[var(--color-border)] text-[var(--color-text-secondary)] hover:bg-[var(--color-bg-tertiary)]"
                }`}
              >
                {action.label}
              </button>
            ))}
            {alert.server_name && !alert.actions.some((a) => a.action_type === "restrict") && (
              <button
                onClick={handleRestrict}
                className="text-xs px-3 py-1.5 rounded-lg border border-[var(--color-danger)] text-[var(--color-danger)] hover:bg-[var(--color-danger-subtle)] transition-colors"
              >
                Restrict this tool
              </button>
            )}
            {alert.alert_type === "block" && (
              <button
                onClick={handleKeepBlocking}
                className="text-xs px-3 py-1.5 rounded-lg border border-[var(--color-border)] text-[var(--color-text-secondary)] hover:bg-[var(--color-bg-tertiary)] transition-colors"
              >
                Keep blocking
              </button>
            )}
            <button
              onClick={async () => {
                if (!alert) return;
                setStartingInvestigation(true);
                try {
                  const result = await invoke<InvestigationProgress>("start_investigation", {
                    targetType: "alert",
                    targetId: alert.id,
                    targetData: { title: alert.title, description: alert.description, severity: alert.severity },
                    depth: "standard",
                  });
                  setInvestigationId(result.investigation_id);
                } catch {
                  // ok
                }
                setStartingInvestigation(false);
              }}
              disabled={startingInvestigation || !!investigationId || !canInvestigate}
              className="text-xs px-3 py-1.5 rounded-lg bg-[var(--color-accent)] text-white hover:opacity-90 disabled:opacity-50 transition-opacity"
              title={!canInvestigate ? "Requires Cloud API -- set up in Settings" : undefined}
            >
              {startingInvestigation ? "Starting..." : "Investigate"}
            </button>
            <Link
              to="/ask"
              state={{ prefill: `Tell me about alert: ${alert.title}` }}
              className="text-xs px-3 py-1.5 rounded-lg border border-[var(--color-border)] text-[var(--color-accent)] hover:bg-[var(--color-bg-tertiary)] transition-colors"
            >
              Ask Claw about this
            </Link>
            <button
              onClick={handleDismiss}
              className="text-xs px-3 py-1.5 rounded-lg border border-[var(--color-danger)] text-[var(--color-danger)] hover:bg-[var(--color-danger-subtle)] transition-colors ml-auto"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Resolved info */}
        {isResolved && alert.resolved_at && (
          <div className="pt-3 border-t border-[var(--color-border)]">
            <p className="text-xs text-[var(--color-text-muted)]">
              {alert.status === "dismissed" ? "Dismissed" : "Resolved"}{" "}
              {relativeTime(alert.resolved_at)}
              {alert.resolved_by && ` -- ${alert.resolved_by}`}
            </p>
          </div>
        )}
      </div>

      {/* Investigation results */}
      {investigationId && (
        <section aria-label="AI Investigation">
          <h3 className="text-xs font-semibold text-[var(--color-text-muted)] uppercase tracking-wide mb-3">
            AI Investigation
          </h3>
          <div className="bg-[var(--color-bg-secondary)] rounded-xl border border-[var(--color-border)] p-4">
            <LiveInvestigationView
              investigationId={investigationId}
              onComplete={() => {}}
              onCancel={() => setInvestigationId(null)}
            />
          </div>
        </section>
      )}

      {/* Kill chain: ThreatStory */}
      {isKillChain && alert.kill_chain && (
        <section aria-label="Threat story">
          <h3 className="text-xs font-semibold text-[var(--color-text-muted)] uppercase tracking-wide mb-3">
            Attack Chain
          </h3>
          <div className="bg-[var(--color-bg-secondary)] rounded-xl border border-[var(--color-border)] p-5">
            <ThreatStory
              narrative={alert.kill_chain}
              recommendation={alert.recommendation}
              serverName={alert.server_name}
              onAction={alert.server_name ? handleRestrict : undefined}
              actionLabel="Restrict this server"
            />
          </div>
        </section>
      )}
    </div>
  );
}
