import { useEffect, useMemo, useCallback, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { PageHeader } from "../components/PageHeader";
import { useAlertStore } from "../stores/alertStore";
import { AlertCard, sortAlerts } from "../components/alerts/AlertCard";
import { useTauriEvent } from "../hooks/useTauriEvent";
import { useToastStore } from "../components/notifications/ToastContainer";
import { EMPTY_STATES } from "../constants/messages";
import type { IntelligentAlert, Recommendation } from "../types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function relativeDay(ts: string): string {
  try {
    const d = new Date(ts);
    const today = new Date();
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);

    if (d.toDateString() === today.toDateString()) return "Today";
    if (d.toDateString() === yesterday.toDateString()) return "Yesterday";
    return d.toLocaleDateString([], { weekday: "long", month: "short", day: "numeric" });
  } catch {
    return ts;
  }
}

function groupByDay(alerts: IntelligentAlert[]): [string, IntelligentAlert[]][] {
  const groups = new Map<string, IntelligentAlert[]>();
  for (const alert of alerts) {
    const key = relativeDay(alert.resolved_at || alert.updated_at || alert.created_at);
    const list = groups.get(key) || [];
    list.push(alert);
    groups.set(key, list);
  }
  return Array.from(groups.entries());
}

// ---------------------------------------------------------------------------
// Recommendation Card
// ---------------------------------------------------------------------------

function RecommendationCard({
  rec,
  onExecute,
  onDismiss,
}: {
  rec: Recommendation;
  onExecute: (id: string) => void;
  onDismiss: (id: string) => void;
}) {
  return (
    <div className="flex items-center justify-between gap-3 p-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)]">
      <p className="text-sm text-[var(--color-text-secondary)] flex-1">
        {rec.description}
      </p>
      <div className="flex items-center gap-2 shrink-0">
        <button
          onClick={() => onExecute(rec.id)}
          className="text-xs px-3 py-1.5 rounded-lg bg-[var(--color-accent)] text-white hover:opacity-90 transition-opacity"
        >
          {rec.action_label || "Do it"}
        </button>
        <button
          onClick={() => onDismiss(rec.id)}
          className="text-xs px-2.5 py-1.5 rounded-lg border border-[var(--color-border)] text-[var(--color-text-muted)] hover:bg-[var(--color-bg-tertiary)] transition-colors"
        >
          Dismiss
        </button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Empty State
// ---------------------------------------------------------------------------

function EmptyAlerts({
  stats,
}: {
  stats: { resolved_this_week: number; blocked_this_week: number } | null;
}) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <div className="w-12 h-12 rounded-full bg-[var(--color-safe-subtle)] flex items-center justify-center mb-4">
        <svg
          width="24"
          height="24"
          viewBox="0 0 24 24"
          fill="none"
          stroke="var(--color-safe)"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
        >
          <polyline points="20 6 9 17 4 12" />
        </svg>
      </div>
      <p className="text-sm font-medium text-[var(--color-text-primary)] mb-1">
        All clear right now
      </p>
      <p className="text-sm text-[var(--color-text-secondary)] max-w-sm">
        {EMPTY_STATES.alerts.body}
      </p>
      {stats && (stats.resolved_this_week > 0 || stats.blocked_this_week > 0) && (
        <p className="text-xs text-[var(--color-text-muted)] mt-3">
          This week: {stats.resolved_this_week} alerts resolved, {stats.blocked_this_week} threats blocked
        </p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------

export function Alerts() {
  const alerts = useAlertStore((s) => s.alerts);
  const stats = useAlertStore((s) => s.stats);
  const loading = useAlertStore((s) => s.loading);
  const fetchAlerts = useAlertStore((s) => s.fetchAlerts);
  const fetchStats = useAlertStore((s) => s.fetchStats);
  const dismissAll = useAlertStore((s) => s.dismissAll);
  const fetchHistory = useAlertStore((s) => s.fetchHistory);
  const addToast = useToastStore((s) => s.addToast);

  const [history, setHistory] = useState<IntelligentAlert[]>([]);
  const [recommendations, setRecommendations] = useState<Recommendation[]>([]);

  // Fetch alerts, stats, history, and recommendations on mount
  useEffect(() => {
    fetchAlerts();
    fetchStats();
    fetchHistory(7).then(setHistory);

    invoke<Recommendation[]>("get_recommendations_cmd")
      .then((recs) => setRecommendations(recs.filter((r) => !r.dismissed)))
      .catch(() => {});
  }, [fetchAlerts, fetchStats, fetchHistory]);

  // Listen for real-time alert events (both legacy and intelligent-alert)
  const handleNewAlert = useCallback(() => {
    fetchAlerts();
    fetchStats();
  }, [fetchAlerts, fetchStats]);
  useTauriEvent("clawdefender://alert", handleNewAlert);
  useTauriEvent("clawdefender://intelligent-alert", handleNewAlert);

  // Sort active alerts
  const sortedAlerts = useMemo(() => sortAlerts(alerts), [alerts]);

  // Group history by day
  const historyGroups = useMemo(() => groupByDay(history), [history]);

  // Derived flags
  const hasActiveAlerts = sortedAlerts.length > 0;
  const hasUnusualOrLower = sortedAlerts.some(
    (a) => a.severity === "unusual" || a.severity === "info"
  );
  const hasHistory = history.length > 0;
  const hasRecommendations = recommendations.length > 0;
  const isEmpty = !hasActiveAlerts && !hasHistory && !hasRecommendations;

  async function handleDismissAllLow() {
    const count = await dismissAll("unusual");
    addToast({
      title: `Dismissed ${count} alert${count !== 1 ? "s" : ""}.`,
      severity: "info",
    });
  }

  async function handleExecuteRec(id: string) {
    try {
      const result = await invoke<string>("execute_recommendation_cmd", { id });
      addToast({ title: result || "Done.", severity: "success" });
      setRecommendations((prev) => prev.filter((r) => r.id !== id));
    } catch {
      addToast({ title: "Could not apply that recommendation.", severity: "danger" });
    }
  }

  async function handleDismissRec(id: string) {
    try {
      await invoke("dismiss_recommendation_cmd", { id });
    } catch {
      // non-critical
    }
    setRecommendations((prev) => prev.filter((r) => r.id !== id));
  }

  return (
    <div className="p-6 space-y-6 max-w-4xl">
      <PageHeader
        title="Alerts"
        subtitle="Threats and items needing your attention"
        actions={
          hasActiveAlerts && hasUnusualOrLower ? (
            <button
              onClick={handleDismissAllLow}
              className="text-xs px-3 py-1.5 rounded-lg border border-[var(--color-border)] text-[var(--color-text-secondary)] hover:bg-[var(--color-bg-tertiary)] transition-colors"
            >
              Dismiss all Unusual and below
            </button>
          ) : undefined
        }
      />

      {/* Loading spinner */}
      {loading && sortedAlerts.length === 0 && (
        <div className="flex justify-center py-8">
          <span className="text-sm text-[var(--color-text-muted)]">Loading alerts...</span>
        </div>
      )}

      {/* Section 1: Active alerts */}
      {hasActiveAlerts && (
        <section aria-label="Active alerts" aria-live="polite">
          <h2 className="text-xs font-semibold text-[var(--color-text-muted)] uppercase tracking-wide mb-3">
            Needs Attention ({sortedAlerts.length})
          </h2>
          <div className="space-y-3" role="list" aria-label="Alert list">
            {sortedAlerts.map((alert) => (
              <div key={alert.id} role="listitem">
                <AlertCard alert={alert} />
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Empty state */}
      {isEmpty && !loading && <EmptyAlerts stats={stats} />}

      {/* Section 2: Recommendations */}
      {hasRecommendations && (
        <section aria-label="Recommendations">
          <h2
            className={`text-xs font-semibold text-[var(--color-text-muted)] uppercase tracking-wide mb-3 ${
              !hasActiveAlerts ? "opacity-80" : ""
            }`}
          >
            Recommendations
          </h2>
          <div className="space-y-2">
            {recommendations.map((rec) => (
              <RecommendationCard
                key={rec.id}
                rec={rec}
                onExecute={handleExecuteRec}
                onDismiss={handleDismissRec}
              />
            ))}
          </div>
        </section>
      )}

      {/* Section 3: Recently Handled */}
      {hasHistory && (
        <section aria-label="Recently handled alerts">
          <h2 className="text-xs font-semibold text-[var(--color-text-muted)] uppercase tracking-wide mb-1">
            Recently Handled
          </h2>
          {stats && (
            <p className="text-xs text-[var(--color-text-muted)] mb-3">
              This week: {stats.resolved_this_week} alerts resolved, {stats.blocked_this_week} threats blocked
            </p>
          )}
          <div className="space-y-4">
            {historyGroups.map(([day, dayAlerts]) => (
              <div key={day}>
                <p className="text-xs font-medium text-[var(--color-text-muted)] mb-2">
                  {day}
                </p>
                <div className="space-y-2">
                  {dayAlerts.map((alert) => (
                    <AlertCard key={alert.id} alert={alert} compact />
                  ))}
                </div>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
