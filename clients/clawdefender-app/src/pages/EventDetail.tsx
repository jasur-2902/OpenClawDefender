import { useMemo, useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { useEventStore } from "../stores/eventStore";
import {
  Icon,
  Card,
  Badge,
  VerdictPill,
  KV,
  Btn,
} from "../components/design";
import type {
  HumanizedEvent,
  CorrelationResult,
  InvestigationProgress,
} from "../types";
import { useAiStatus } from "../hooks/useAiStatus";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function kindIcon(e: HumanizedEvent): string {
  const et = e.raw_event.event_type;
  if (et === "eslogger" || e.source_type === "os") return "process";
  if (et === "network" || et === "dns") return et;
  return "tools";
}

function fmtTime(ts: string): string {
  try {
    return new Date(ts).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return ts;
  }
}

function classColor(level: string): string {
  switch (level.toLowerCase()) {
    case "critical":
    case "high":
      return "var(--red)";
    case "suspicious":
    case "medium":
    case "notable":
      return "var(--amber)";
    case "low":
      return "var(--green)";
    default:
      return "var(--ink-2)";
  }
}

function tryFormatJson(str: string): string {
  try {
    return JSON.stringify(JSON.parse(str), null, 2);
  } catch {
    return str;
  }
}

function extractSlmAnalysis(details: string): {
  explanation: string | null;
  confidence: number | null;
  riskLevel: string | null;
} {
  try {
    const parsed = JSON.parse(details);
    const slm = parsed.slm_analysis ?? parsed.analysis;
    if (!slm || typeof slm !== "object")
      return { explanation: null, confidence: null, riskLevel: null };
    return {
      explanation: slm.explanation ?? null,
      confidence: slm.confidence ?? null,
      riskLevel: slm.risk_level ?? null,
    };
  } catch {
    return { explanation: null, confidence: null, riskLevel: null };
  }
}

// ---------------------------------------------------------------------------
// EventDetail Screen
// ---------------------------------------------------------------------------

export function EventDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const events = useEventStore((s) => s.events);
  const [showRaw, setShowRaw] = useState(false);
  const [investigationId, setInvestigationId] = useState<string | null>(null);
  const [startingInvestigation, setStartingInvestigation] = useState(false);
  const { canInvestigate } = useAiStatus();

  const event = useMemo(
    () => events.find((e) => e.event_id === id) ?? null,
    [events, id]
  );

  // Correlation data
  const [correlationResult, setCorrelationResult] =
    useState<CorrelationResult | null>(null);

  useEffect(() => {
    if (!id || !event) return;
    let cancelled = false;
    invoke<CorrelationResult>("get_correlation_for_event", { eventId: id })
      .then((result) => {
        if (!cancelled) setCorrelationResult(result);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [id, event]);

  // Nearby events from same server
  const nearby = useMemo(() => {
    if (!event) return [];
    const t = new Date(event.timestamp).getTime();
    return events
      .filter(
        (e) =>
          e.event_id !== event.event_id &&
          e.server_display_name === event.server_display_name &&
          Math.abs(new Date(e.timestamp).getTime() - t) <= 5 * 60_000
      )
      .slice(0, 5);
  }, [event, events]);

  // SLM analysis
  const slm = event ? extractSlmAnalysis(event.raw_event.details) : null;

  // Mock anomaly dimensions (from design ref -- these would come from SLM in real app)
  const dimensions = [
    { name: "novelty", v: 0.82 },
    { name: "rarity", v: 0.71 },
    { name: "scope", v: 0.45 },
    { name: "intent", v: 0.88 },
    { name: "freq", v: 0.34 },
    { name: "egress", v: 0.65 },
    { name: "priv", v: 0.22 },
    { name: "chain", v: 0.78 },
    { name: "intel", v: 0.95 },
  ];

  if (!event) {
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
          onClick={() => navigate("/activity")}
          style={{
            fontSize: 11.5,
            color: "var(--ink-2)",
            marginBottom: 14,
            display: "inline-flex",
            alignItems: "center",
            gap: 6,
            background: "none",
            border: "none",
            cursor: "pointer",
          }}
        >
          <Icon name="chevron" size={11} color="var(--ink-2)" />
          Back
        </button>
        <div
          style={{
            textAlign: "center",
            padding: 60,
            color: "var(--ink-2)",
            fontSize: 14,
          }}
        >
          Event not found. It may have been evicted from the buffer.
        </div>
      </div>
    );
  }

  const isSuspicious =
    event.risk_level === "high" ||
    event.risk_level === "critical" ||
    event.risk_level === "suspicious";

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
        onClick={() => navigate("/activity")}
        style={{
          fontSize: 11.5,
          color: "var(--ink-2)",
          marginBottom: 14,
          display: "inline-flex",
          alignItems: "center",
          gap: 6,
          background: "none",
          border: "none",
          cursor: "pointer",
        }}
      >
        <span
          style={{
            display: "inline-block",
            transform: "rotate(180deg)",
          }}
        >
          <Icon name="chevron" size={11} color="var(--ink-2)" />
        </span>
        Back
      </button>

      {/* Hero */}
      <div
        style={{
          display: "flex",
          alignItems: "flex-start",
          gap: 16,
          marginBottom: 18,
        }}
      >
        <div
          style={{
            width: 44,
            height: 44,
            borderRadius: 10,
            background: "var(--bg-2)",
            border: "1px solid var(--line)",
            display: "grid",
            placeItems: "center",
          }}
        >
          <Icon name={kindIcon(event)} size={20} color="var(--ink-1)" />
        </div>
        <div style={{ flex: 1 }}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              marginBottom: 6,
            }}
          >
            <VerdictPill
              verdict={event.action_taken === "Blocked" ? "BLOCK" : "ALLOW"}
            />
            <Badge color={classColor(event.risk_level)}>
              {event.risk_level}
            </Badge>
            <span
              style={{
                fontSize: 10.5,
                fontFamily: "var(--font-mono)",
                color: "var(--ink-3)",
              }}
            >
              {event.event_id.slice(0, 12)} {"\u00B7"} {fmtTime(event.timestamp)}
            </span>
          </div>
          <h1
            style={{
              margin: 0,
              fontSize: 18,
              fontWeight: 600,
              fontFamily: "var(--font-mono)",
            }}
          >
            {event.one_liner}
          </h1>
          <div
            style={{
              marginTop: 6,
              fontSize: 13,
              color: "var(--ink-2)",
              lineHeight: 1.55,
            }}
          >
            {event.expanded_explanation ||
              "Event passed local SLM triage with no anomalies."}
          </div>
        </div>
        <div style={{ display: "flex", gap: 6 }}>
          <Btn
            icon="search"
            kind="accent"
            disabled={!canInvestigate || startingInvestigation || !!investigationId}
            onClick={async () => {
              setStartingInvestigation(true);
              try {
                const result = await invoke<InvestigationProgress>(
                  "start_investigation",
                  {
                    targetType: "event",
                    targetId: event.event_id,
                    targetData: JSON.parse(JSON.stringify(event.raw_event)),
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
            {startingInvestigation ? "Starting..." : "Investigate with AI"}
          </Btn>
          <Btn
            icon="lock"
            kind="danger"
            onClick={() =>
              navigate("/ask", {
                state: {
                  prefill: `Block the server: ${event.server_display_name}`,
                },
              })
            }
          >
            Block server
          </Btn>
        </div>
      </div>

      {/* 2 column grid */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1.4fr 1fr",
          gap: 14,
        }}
      >
        {/* Left column */}
        <div style={{ display: "grid", gap: 14 }}>
          {/* SLM Triage */}
          <Card
            title="SLM Triage"
            action={
              slm?.confidence != null ? (
                <Badge color="var(--accent)" mono>
                  conf {slm.confidence.toFixed(2)}
                </Badge>
              ) : undefined
            }
          >
            <div
              style={{
                fontSize: 12.5,
                color: "var(--ink-1)",
                lineHeight: 1.55,
              }}
            >
              Classified as{" "}
              <strong style={{ color: classColor(event.risk_level) }}>
                {event.risk_level}
              </strong>
              .{" "}
              {slm?.explanation ||
                event.risk_explanation ||
                "Matches established baseline for this server. No follow-up required."}
            </div>
          </Card>

          {/* Cloud investigation (only for suspicious) */}
          {isSuspicious && (
            <Card
              title="Cloud Investigation"
              action={
                <Badge color="var(--violet)" mono>
                  conf 0.94
                </Badge>
              }
            >
              <div
                style={{
                  fontSize: 12.5,
                  color: "var(--ink-1)",
                  lineHeight: 1.6,
                }}
              >
                {event.behavioral_context ||
                  "This event is suspicious and warrants further investigation. Cloud analysis pending."}
              </div>
              <div style={{ marginTop: 12, display: "flex", gap: 8 }}>
                {event.kill_chain_id && (
                  <Btn
                    kind="accent"
                    icon="alert"
                    onClick={() =>
                      navigate(`/alerts/${event.kill_chain_id}`)
                    }
                  >
                    View parent alert
                  </Btn>
                )}
                <Btn kind="ghost">Mark false positive</Btn>
              </div>
            </Card>
          )}

          {/* Top anomaly factors */}
          <Card
            title="Top anomaly factors"
            action={
              <button
                onClick={() => setShowRaw(!showRaw)}
                style={{
                  fontSize: 11.5,
                  color: "var(--accent)",
                  background: "none",
                  border: "none",
                  cursor: "pointer",
                }}
              >
                {showRaw ? "Hide raw event" : "Show raw event"}
              </button>
            }
          >
            <div style={{ display: "grid", gap: 6 }}>
              {[...dimensions]
                .sort((a, b) => b.v - a.v)
                .slice(0, 4)
                .map((d) => (
                  <div
                    key={d.name}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 10,
                      fontSize: 11.5,
                    }}
                  >
                    <span
                      style={{
                        width: 70,
                        fontFamily: "var(--font-mono)",
                        color: "var(--ink-2)",
                      }}
                    >
                      {d.name}
                    </span>
                    <div
                      style={{
                        flex: 1,
                        height: 5,
                        background: "var(--bg-3)",
                        borderRadius: 3,
                        overflow: "hidden",
                      }}
                    >
                      <div
                        style={{
                          width: `${d.v * 100}%`,
                          height: "100%",
                          background:
                            d.v > 0.7
                              ? "var(--red)"
                              : d.v > 0.4
                                ? "var(--amber)"
                                : "var(--green)",
                        }}
                      />
                    </div>
                    <span
                      style={{
                        width: 32,
                        textAlign: "right",
                        fontFamily: "var(--font-mono)",
                        color: "var(--ink-1)",
                      }}
                    >
                      {d.v.toFixed(2)}
                    </span>
                  </div>
                ))}
            </div>
            {showRaw && (
              <pre
                className="cd-slide-in"
                style={{
                  marginTop: 14,
                  padding: 12,
                  background: "var(--bg-2)",
                  borderRadius: 8,
                  fontFamily: "var(--font-mono)",
                  fontSize: 11,
                  lineHeight: 1.6,
                  color: "var(--ink-1)",
                  whiteSpace: "pre-wrap",
                  overflow: "auto",
                  maxHeight: 300,
                }}
              >
                {tryFormatJson(JSON.stringify(event.raw_event))}
              </pre>
            )}
          </Card>
        </div>

        {/* Right column */}
        <div style={{ display: "grid", gap: 14 }}>
          {/* Source server */}
          <Card title="Source server">
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 10,
                marginBottom: 10,
              }}
            >
              <div
                style={{
                  width: 32,
                  height: 32,
                  borderRadius: 8,
                  background: "var(--bg-2)",
                  display: "grid",
                  placeItems: "center",
                  border: "1px solid var(--line)",
                }}
              >
                <Icon name="tools" size={14} color="var(--ink-1)" />
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 13, fontWeight: 500 }}>
                  {event.server_display_name}
                </div>
                <div
                  style={{
                    fontSize: 10.5,
                    color: "var(--ink-3)",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  {event.client_name || event.raw_event.server_name}
                </div>
              </div>
            </div>
            <KV k="Event type" v={event.raw_event.event_type} />
            <KV k="Action" v={event.raw_event.action} />
            <KV k="Decision" v={event.decision} />
            {event.raw_event.resource && (
              <KV k="Resource" v={event.raw_event.resource} mono />
            )}
          </Card>

          {/* Behavioral context */}
          <Card title="Behavioral context">
            <div
              style={{
                fontSize: 12,
                color: "var(--ink-1)",
                lineHeight: 1.55,
              }}
            >
              {event.behavioral_context ||
                "No behavioral anomalies detected for this server."}
            </div>
            {event.risk_explanation && (
              <div
                style={{
                  marginTop: 8,
                  fontSize: 11.5,
                  color: "var(--amber)",
                }}
              >
                {event.risk_explanation}
              </div>
            )}
          </Card>

          {/* Correlated events */}
          <Card title="Correlated">
            {correlationResult &&
            correlationResult.correlated_events.length > 0 ? (
              <div style={{ display: "grid", gap: 6 }}>
                {correlationResult.correlated_events.slice(0, 5).map((c) => (
                  <button
                    key={c.event_id}
                    onClick={() => navigate(`/activity/${c.event_id}`)}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 8,
                      padding: 8,
                      background: "var(--bg-2)",
                      borderRadius: 6,
                      border: "none",
                      cursor: "pointer",
                      textAlign: "left",
                      width: "100%",
                    }}
                  >
                    <Icon name="activity" size={13} color="var(--ink-2)" />
                    <span
                      style={{
                        fontFamily: "var(--font-mono)",
                        fontSize: 10.5,
                        color: "var(--ink-3)",
                        width: 40,
                      }}
                    >
                      {fmtTime(c.timestamp)}
                    </span>
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
                      {c.description}
                    </span>
                  </button>
                ))}
              </div>
            ) : nearby.length > 0 ? (
              <div style={{ display: "grid", gap: 6 }}>
                {nearby.map((n) => (
                  <button
                    key={n.event_id}
                    onClick={() => navigate(`/activity/${n.event_id}`)}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 8,
                      padding: 8,
                      background: "var(--bg-2)",
                      borderRadius: 6,
                      border: "none",
                      cursor: "pointer",
                      textAlign: "left",
                      width: "100%",
                    }}
                  >
                    <Icon name={kindIcon(n)} size={13} color="var(--ink-2)" />
                    <span
                      style={{
                        fontFamily: "var(--font-mono)",
                        fontSize: 10.5,
                        color: "var(--ink-3)",
                        width: 40,
                      }}
                    >
                      {fmtTime(n.timestamp)}
                    </span>
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
                      {n.one_liner}
                    </span>
                  </button>
                ))}
              </div>
            ) : (
              <div style={{ fontSize: 12, color: "var(--ink-3)" }}>
                No correlated events found.
              </div>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}
