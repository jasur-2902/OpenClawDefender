import { useEffect, useState, useCallback } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { useAlertStore } from "../stores/alertStore";
import { useToastStore } from "../components/notifications/ToastContainer";
import {
  Icon,
  Card,
  Badge,
  Btn,
} from "../components/design";
import type {
  IntelligentAlert,
  AlertAction,
  InvestigationProgress,
} from "../types";
import { useAiStatus } from "../hooks/useAiStatus";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function severityColor(sev: string): string {
  switch (sev) {
    case "dangerous":
    case "critical":
      return "var(--red)";
    case "suspicious":
    case "high":
      return "var(--amber)";
    case "unusual":
    case "medium":
      return "var(--violet)";
    case "info":
    case "low":
    default:
      return "var(--ink-2)";
  }
}

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

function formatFullTime(ts: string): string {
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

// ---------------------------------------------------------------------------
// AlertDetail Screen
// ---------------------------------------------------------------------------

export function AlertDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const resolveAlert = useAlertStore((s) => s.resolveAlert);
  const dismissAlert = useAlertStore((s) => s.dismissAlert);
  const addToast = useToastStore((s) => s.addToast);
  const { canInvestigate } = useAiStatus();

  const [alert, setAlert] = useState<IntelligentAlert | null>(null);
  const [loading, setLoading] = useState(true);
  const [investigationId, setInvestigationId] = useState<string | null>(null);
  const [startingInvestigation, setStartingInvestigation] = useState(false);

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
          addToast({ title: "Done. Restricted.", severity: "success" });
          navigate("/alerts");
          break;
        case "allow":
          try {
            if (action.params) await invoke("add_rule", { rule: action.params });
            await resolveAlert(alert.id, "allowed");
            addToast({ title: "Allowed. Rule added.", severity: "success" });
          } catch {
            addToast({ title: "Could not add that rule.", severity: "danger" });
          }
          navigate("/alerts");
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

  const handleDismiss = useCallback(async () => {
    if (!alert) return;
    await dismissAlert(alert.id);
    addToast({ title: "Dismissed.", severity: "info" });
    navigate("/alerts");
  }, [alert, dismissAlert, addToast, navigate]);

  // Loading
  if (loading) {
    return (
      <div
        className="cd-scroll"
        style={{
          padding: 24,
          maxWidth: 1080,
          margin: "0 auto",
          overflowY: "auto",
          height: "100%",
        }}
      >
        <button
          onClick={() => navigate("/alerts")}
          style={{
            fontSize: 11.5,
            color: "var(--ink-2)",
            marginBottom: 14,
            background: "none",
            border: "none",
            cursor: "pointer",
          }}
        >
          {"\u2190"} Back
        </button>
        <div style={{ textAlign: "center", padding: 40, color: "var(--ink-3)" }}>
          Loading...
        </div>
      </div>
    );
  }

  // Not found
  if (!alert) {
    return (
      <div
        className="cd-scroll"
        style={{
          padding: 24,
          maxWidth: 1080,
          margin: "0 auto",
          overflowY: "auto",
          height: "100%",
        }}
      >
        <button
          onClick={() => navigate("/alerts")}
          style={{
            fontSize: 11.5,
            color: "var(--ink-2)",
            marginBottom: 14,
            background: "none",
            border: "none",
            cursor: "pointer",
          }}
        >
          {"\u2190"} Back
        </button>
        <div
          style={{
            textAlign: "center",
            padding: 60,
            color: "var(--ink-2)",
            fontSize: 14,
          }}
        >
          Alert not found. It may have been dismissed.
        </div>
      </div>
    );
  }

  const sc = severityColor(alert.severity);
  const isResolved =
    alert.status === "resolved" || alert.status === "dismissed";

  return (
    <div
      className="cd-scroll"
      style={{
        padding: 24,
        maxWidth: 1080,
        margin: "0 auto",
        overflowY: "auto",
        height: "100%",
      }}
    >
      {/* Back */}
      <button
        onClick={() => navigate("/alerts")}
        style={{
          fontSize: 11.5,
          color: "var(--ink-2)",
          marginBottom: 14,
          background: "none",
          border: "none",
          cursor: "pointer",
        }}
      >
        {"\u2190"} Back
      </button>

      {/* Hero header */}
      <div
        style={{
          display: "flex",
          alignItems: "flex-start",
          gap: 14,
          marginBottom: 18,
        }}
      >
        <div
          style={{
            width: 6,
            alignSelf: "stretch",
            borderRadius: 3,
            background: sc,
            marginTop: 2,
          }}
        />
        <div style={{ flex: 1 }}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              marginBottom: 6,
            }}
          >
            <Badge color={sc}>{alert.severity}</Badge>
            <Badge color="var(--ink-2)" mono>
              {alert.id.slice(0, 12)}
            </Badge>
            <span style={{ fontSize: 11, color: "var(--ink-3)" }}>
              {formatFullTime(alert.created_at)}
            </span>
            {isResolved && (
              <Badge color="var(--ink-3)">
                {alert.status === "dismissed" ? "Dismissed" : "Resolved"}
              </Badge>
            )}
          </div>
          <h1
            style={{
              margin: 0,
              fontSize: 22,
              fontWeight: 600,
              letterSpacing: -0.3,
            }}
          >
            {alert.title}
          </h1>
          <div
            style={{
              marginTop: 6,
              fontSize: 13.5,
              color: "var(--ink-2)",
              lineHeight: 1.5,
            }}
          >
            {alert.description}
          </div>
        </div>
        {!isResolved && (
          <div style={{ display: "flex", gap: 6 }}>
            <Btn
              kind="primary"
              icon="search"
              disabled={
                !canInvestigate ||
                startingInvestigation ||
                !!investigationId
              }
              onClick={async () => {
                setStartingInvestigation(true);
                try {
                  const result = await invoke<InvestigationProgress>(
                    "start_investigation",
                    {
                      targetType: "alert",
                      targetId: alert.id,
                      targetData: {
                        title: alert.title,
                        description: alert.description,
                        severity: alert.severity,
                      },
                      depth: "standard",
                    }
                  );
                  setInvestigationId(result.investigation_id);
                } catch {
                  // ok
                }
                setStartingInvestigation(false);
              }}
            >
              {startingInvestigation ? "Starting..." : "Investigate"}
            </Btn>
            <Btn kind="danger" icon="lock" onClick={handleDismiss}>
              Block server
            </Btn>
            <Btn kind="ghost" onClick={handleDismiss}>
              Dismiss
            </Btn>
          </div>
        )}
      </div>

      {/* AI Verdict card */}
      {(alert.ai_summary || alert.ai_recommendation) && (
        <Card
          title="AI Verdict"
          style={{
            marginBottom: 14,
            borderColor: "color-mix(in oklch, var(--violet) 35%, var(--line))",
          }}
          action={
            alert.ai_confidence != null ? (
              <Badge color="var(--red)" mono>
                conf {alert.ai_confidence.toFixed(2)}
              </Badge>
            ) : undefined
          }
        >
          {alert.ai_summary && (
            <div
              style={{
                fontSize: 13,
                color: "var(--ink-1)",
                lineHeight: 1.6,
                marginBottom: alert.ai_recommendation ? 8 : 0,
              }}
            >
              {alert.ai_summary}
            </div>
          )}
          {alert.ai_recommendation && (
            <div style={{ fontSize: 12.5, color: "var(--ink-2)", lineHeight: 1.5 }}>
              Recommended: {alert.ai_recommendation}
            </div>
          )}
        </Card>
      )}

      {/* Kill chain (ThreatStory) */}
      {alert.kill_chain && (
        <Card
          title={`ThreatStory \u2014 ${alert.kill_chain.pattern_name}`}
          style={{ marginBottom: 14 }}
        >
          <div style={{ fontSize: 12.5, color: "var(--ink-2)", marginBottom: 14, lineHeight: 1.5 }}>
            {alert.kill_chain.summary}
          </div>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: `repeat(${alert.kill_chain.steps.length}, 1fr)`,
              gap: 8,
              position: "relative",
            }}
          >
            {alert.kill_chain.steps.map((s, i) => (
              <div key={i}>
                <div style={{ position: "relative", marginBottom: 12 }}>
                  {i < alert.kill_chain!.steps.length - 1 && (
                    <div
                      style={{
                        height: 2,
                        background: sc,
                        position: "absolute",
                        top: 11,
                        left: 24,
                        right: -8,
                      }}
                    />
                  )}
                  <div
                    style={{
                      width: 24,
                      height: 24,
                      borderRadius: 999,
                      background: sc,
                      color: "var(--bg-0)",
                      display: "grid",
                      placeItems: "center",
                      fontSize: 11,
                      fontWeight: 700,
                      fontFamily: "var(--font-mono)",
                      position: "relative",
                      zIndex: 1,
                    }}
                  >
                    {i + 1}
                  </div>
                </div>
                <div
                  style={{
                    fontSize: 10.5,
                    color: sc,
                    fontFamily: "var(--font-mono)",
                    textTransform: "uppercase",
                    letterSpacing: 0.5,
                  }}
                >
                  {relativeTime(s.timestamp)}
                </div>
                <div
                  style={{
                    fontSize: 11.5,
                    fontWeight: 600,
                    marginTop: 2,
                  }}
                >
                  Step {s.step_number}
                </div>
                <button
                  onClick={() => navigate(`/activity/${s.event_id}`)}
                  style={{
                    marginTop: 6,
                    fontFamily: "var(--font-mono)",
                    fontSize: 10.5,
                    color: "var(--ink-2)",
                    textAlign: "left",
                    background: "none",
                    border: "none",
                    cursor: "pointer",
                    padding: 0,
                  }}
                >
                  {s.description}
                </button>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* 2-column: Recommended actions + Evidence */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1.3fr 1fr",
          gap: 14,
        }}
      >
        {/* Recommended actions */}
        <Card title="Recommended actions" padded={false}>
          {alert.actions.length > 0 ? (
            alert.actions.map((action, i) => (
              <div
                key={action.id}
                style={{
                  padding: "14px 16px",
                  borderBottom:
                    i < alert.actions.length - 1
                      ? "1px solid var(--line-soft)"
                      : "none",
                  display: "flex",
                  gap: 10,
                }}
              >
                <Icon
                  name={
                    action.action_type === "restrict"
                      ? "lock"
                      : action.action_type === "allow"
                        ? "shield"
                        : "key"
                  }
                  size={16}
                  color={
                    action.action_type === "restrict"
                      ? "var(--red)"
                      : "var(--accent)"
                  }
                />
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 12.5, fontWeight: 500 }}>
                    {action.label}
                  </div>
                </div>
                <Btn
                  size="sm"
                  kind={
                    action.action_type === "restrict" ? "danger" : "accent"
                  }
                  onClick={() => handleAction(action)}
                >
                  Apply
                </Btn>
              </div>
            ))
          ) : (
            <div style={{ padding: 16 }}>
              <div
                style={{
                  padding: "14px 16px",
                  display: "flex",
                  gap: 10,
                }}
              >
                <Icon name="lock" size={16} color="var(--red)" />
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 12.5, fontWeight: 500 }}>
                    {alert.recommendation || "Review and take action"}
                  </div>
                </div>
              </div>
            </div>
          )}
        </Card>

        {/* Evidence */}
        <Card title="Evidence">
          {alert.source_events.length > 0 ? (
            alert.source_events.slice(0, 8).map((eid) => (
              <button
                key={eid}
                onClick={() => navigate(`/activity/${eid}`)}
                style={{
                  width: "100%",
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  padding: "8px 10px",
                  background: "var(--bg-2)",
                  borderRadius: 6,
                  marginBottom: 6,
                  textAlign: "left",
                  border: "none",
                  cursor: "pointer",
                }}
              >
                <Icon name="activity" size={13} color="var(--ink-2)" />
                <span
                  style={{
                    fontFamily: "var(--font-mono)",
                    fontSize: 11,
                    color: "var(--ink-1)",
                    flex: 1,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {eid.length > 20 ? eid.slice(0, 20) + "\u2026" : eid}
                </span>
                <Icon name="chevron" size={11} color="var(--ink-3)" />
              </button>
            ))
          ) : (
            <div style={{ fontSize: 12, color: "var(--ink-3)" }}>
              No evidence events linked.
            </div>
          )}
          {alert.source_events.length > 8 && (
            <div
              style={{
                fontSize: 11,
                color: "var(--ink-3)",
                textAlign: "center",
                padding: 4,
              }}
            >
              +{alert.source_events.length - 8} more events
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
