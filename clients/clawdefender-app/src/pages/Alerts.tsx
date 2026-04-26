import { useEffect, useMemo, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { useAlertStore } from "../stores/alertStore";
import { Icon, Dot, SectionTitle } from "../components/design";
import { useTauriEvent } from "../hooks/useTauriEvent";
import type { IntelligentAlert } from "../types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const severityLabels: Record<string, string> = {
  dangerous: "Critical",
  critical: "Critical",
  suspicious: "High",
  high: "High",
  unusual: "Medium",
  medium: "Medium",
  info: "Low",
  low: "Low",
};

function relativeTime(ts: string): string {
  try {
    const diff = Date.now() - new Date(ts).getTime();
    const min = Math.floor(diff / 60_000);
    if (min < 1) return "just now";
    if (min < 60) return `${min}m ago`;
    const hr = Math.floor(min / 60);
    if (hr < 24) return `${hr}h ago`;
    return `${Math.floor(hr / 24)}d ago`;
  } catch {
    return ts;
  }
}

type SeverityGroup = {
  severity: string;
  label: string;
  color: string;
  alerts: IntelligentAlert[];
};

function groupBySeverity(alerts: IntelligentAlert[]): SeverityGroup[] {
  const map = new Map<string, IntelligentAlert[]>();
  for (const a of alerts) {
    const key = severityLabels[a.severity] || "Low";
    const list = map.get(key) || [];
    list.push(a);
    map.set(key, list);
  }

  const order = ["Critical", "High", "Medium", "Low"];
  const colorMap: Record<string, string> = {
    Critical: "var(--red)",
    High: "var(--amber)",
    Medium: "var(--violet)",
    Low: "var(--ink-2)",
  };

  return order
    .filter((label) => map.has(label))
    .map((label) => ({
      severity: label.toLowerCase(),
      label,
      color: colorMap[label] || "var(--ink-2)",
      alerts: map.get(label)!,
    }));
}

// ---------------------------------------------------------------------------
// Alerts Screen
// ---------------------------------------------------------------------------

export function Alerts() {
  const navigate = useNavigate();
  const alerts = useAlertStore((s) => s.alerts);
  const loading = useAlertStore((s) => s.loading);
  const fetchAlerts = useAlertStore((s) => s.fetchAlerts);
  const fetchStats = useAlertStore((s) => s.fetchStats);

  useEffect(() => {
    fetchAlerts();
    fetchStats();
  }, [fetchAlerts, fetchStats]);

  const handleNewAlert = useCallback(() => {
    fetchAlerts();
    fetchStats();
  }, [fetchAlerts, fetchStats]);
  useTauriEvent("rookbot://alert", handleNewAlert);
  useTauriEvent("rookbot://intelligent-alert", handleNewAlert);

  const groups = useMemo(() => groupBySeverity(alerts), [alerts]);

  return (
    <div className="cd-scroll" style={{ overflowY: "auto", height: "100%" }}>
      <div
        style={{ maxWidth: 720, margin: "0 auto", padding: "40px 28px 48px" }}
      >
        <SectionTitle sub="Things RookBot thinks you should look at.">
          Alerts
        </SectionTitle>

        {loading && alerts.length === 0 && (
          <div
            style={{
              textAlign: "center",
              padding: 40,
              color: "var(--ink-3)",
              fontSize: 13,
            }}
          >
            Loading alerts...
          </div>
        )}

        {!loading && alerts.length === 0 && (
          <div
            style={{
              textAlign: "center",
              padding: 60,
              color: "var(--ink-2)",
            }}
          >
            <div style={{ fontSize: 15, fontWeight: 500, marginBottom: 6 }}>
              All clear right now
            </div>
            <div style={{ fontSize: 13, color: "var(--ink-3)" }}>
              When RookBot detects something that needs your attention, it will
              appear here.
            </div>
          </div>
        )}

        {groups.map((group) => (
          <div key={group.severity} style={{ marginBottom: 24 }}>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                padding: "0 4px 8px",
                fontSize: 11,
                fontWeight: 600,
                color: "var(--ink-2)",
                textTransform: "uppercase",
                letterSpacing: 0.5,
              }}
            >
              <Dot color={group.color} size={6} />
              {group.label} {"\u00B7"} {group.alerts.length}
            </div>
            <div
              style={{
                background: "var(--bg-1)",
                border: "1px solid var(--line)",
                borderRadius: 12,
                overflow: "hidden",
                boxShadow: "0 1px 2px oklch(0 0 0 / 0.04)",
              }}
            >
              {group.alerts.map((a, i) => (
                <button
                  key={a.id}
                  onClick={() => navigate(`/alerts/${a.id}`)}
                  style={{
                    width: "100%",
                    display: "flex",
                    alignItems: "flex-start",
                    gap: 14,
                    padding: "14px 16px",
                    textAlign: "left",
                    borderBottom:
                      i < group.alerts.length - 1
                        ? "1px solid var(--line-soft)"
                        : "none",
                    background: "transparent",
                    border: "none",
                    borderBottomStyle: "solid",
                    borderBottomWidth:
                      i < group.alerts.length - 1 ? 1 : 0,
                    borderBottomColor: "var(--line-soft)",
                    cursor: "pointer",
                  }}
                  onMouseEnter={(e) =>
                    (e.currentTarget.style.background = "var(--accent-soft)")
                  }
                  onMouseLeave={(e) =>
                    (e.currentTarget.style.background = "transparent")
                  }
                >
                  <div
                    style={{
                      width: 8,
                      height: 8,
                      borderRadius: 999,
                      background: group.color,
                      marginTop: 6,
                      flexShrink: 0,
                    }}
                  />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div
                      style={{
                        display: "flex",
                        alignItems: "baseline",
                        gap: 8,
                        marginBottom: 3,
                      }}
                    >
                      <span
                        style={{
                          fontSize: 14,
                          fontWeight: 600,
                          color: "var(--ink-0)",
                          flex: 1,
                          minWidth: 0,
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {a.title}
                      </span>
                      <span
                        style={{
                          fontSize: 12,
                          color: "var(--ink-3)",
                          flexShrink: 0,
                        }}
                      >
                        {relativeTime(a.created_at)}
                      </span>
                    </div>
                    <div
                      style={{
                        fontSize: 13,
                        color: "var(--ink-2)",
                        lineHeight: 1.45,
                        marginBottom: 6,
                      }}
                    >
                      {a.description}
                    </div>
                    <div
                      style={{
                        display: "flex",
                        gap: 14,
                        fontSize: 12,
                        color: "var(--ink-3)",
                      }}
                    >
                      <span>{a.server_name || "System"}</span>
                      <span>{"\u00B7"}</span>
                      <span>{a.status}</span>
                      {a.source_events.length > 1 && (
                        <>
                          <span>{"\u00B7"}</span>
                          <span>{a.source_events.length} events</span>
                        </>
                      )}
                    </div>
                  </div>
                  <Icon
                    name="chevron"
                    size={13}
                    color="var(--ink-3)"
                  />
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
