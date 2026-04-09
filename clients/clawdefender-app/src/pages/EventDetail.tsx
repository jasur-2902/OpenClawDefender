import { useMemo, useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { useEventStore } from "../stores/eventStore";
import { PageHeader } from "../components/PageHeader";
import { CorrelationTimeline } from "../components/activity/CorrelationTimeline";
import { CoverageInsight } from "../components/activity/CoverageInsight";
import { LiveInvestigationView } from "../components/investigation/LiveInvestigationView";
import { InvestigationDetail } from "../components/investigation/InvestigationDetail";
import { getThreatColor } from "../utils/threatLevel";
import type { ThreatLevel } from "../utils/threatLevel";
import type { HumanizedEvent, CorrelationResult, CoverageAssessment, InvestigationProgress } from "../types";
import { truncateEnd } from "../utils/textUtils";
import { ExpandableContent } from "../components/shared/TruncatedText";
import { useAiStatus } from "../hooks/useAiStatus";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function tryFormatJson(str: string): string {
  try {
    return JSON.stringify(JSON.parse(str), null, 2);
  } catch {
    return str;
  }
}

function extractSlmAnalysis(details: string): string | null {
  try {
    const parsed = JSON.parse(details);
    const slm = parsed.slm_analysis ?? parsed.analysis;
    if (!slm) return null;
    if (typeof slm === "string") return slm;
    if (typeof slm === "object") {
      const parts: string[] = [];
      if (slm.risk_level) parts.push(`Risk: ${slm.risk_level}`);
      if (slm.explanation) parts.push(slm.explanation);
      if (slm.confidence != null)
        parts.push(`Confidence: ${(slm.confidence * 100).toFixed(0)}%`);
      return parts.join("\n") || null;
    }
  } catch {
    // Not JSON
  }
  return null;
}

function extractPolicyRule(details: string): string | null {
  try {
    const parsed = JSON.parse(details);
    return parsed.matched_rule ?? parsed.policy_rule ?? null;
  } catch {
    return null;
  }
}

function ActionBadge({ action }: { action: HumanizedEvent["action_taken"] }) {
  const config: Record<
    HumanizedEvent["action_taken"],
    { label: string; bg: string; color: string }
  > = {
    Allowed: {
      label: "Allowed",
      bg: "var(--color-safe-subtle)",
      color: "var(--color-safe)",
    },
    Blocked: {
      label: "Blocked",
      bg: "var(--color-danger-subtle)",
      color: "var(--color-danger)",
    },
    Prompted: {
      label: "Prompted",
      bg: "var(--color-warning-subtle)",
      color: "var(--color-warning)",
    },
    AutoBlocked: {
      label: "Auto-blocked",
      bg: "var(--color-danger-subtle)",
      color: "var(--color-danger)",
    },
  };
  const c = config[action] ?? {
    label: action ?? "Unknown",
    bg: "var(--color-bg-tertiary)",
    color: "var(--color-text-secondary)",
  };
  return (
    <span
      role="status"
      className="text-sm px-3 py-1 rounded-full font-medium"
      style={{ backgroundColor: c.bg, color: c.color }}
    >
      {c.label}
    </span>
  );
}

function RiskBadge({ level }: { level: HumanizedEvent["risk_level"] }) {
  const color = getThreatColor(level as ThreatLevel);
  return (
    <span
      role="status"
      aria-label={`Risk level: ${level}`}
      className="text-sm px-2 py-0.5 rounded font-medium"
      style={{ color, borderColor: color, border: "1px solid" }}
    >
      {level}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Mini Timeline -- events from same server within +/-5 minutes
// ---------------------------------------------------------------------------

function MiniTimeline({
  event,
  allEvents,
}: {
  event: HumanizedEvent;
  allEvents: HumanizedEvent[];
}) {
  const navigate = useNavigate();
  const eventTime = new Date(event.timestamp).getTime();
  const nearby = allEvents.filter(
    (e) =>
      e.event_id !== event.event_id &&
      e.server_display_name === event.server_display_name &&
      Math.abs(new Date(e.timestamp).getTime() - eventTime) <= 5 * 60_000
  );

  if (nearby.length === 0) return null;

  return (
    <div className="mt-6">
      <h3 className="text-sm font-semibold text-[var(--color-text-primary)] mb-3">
        Nearby activity from {event.server_display_name}
      </h3>
      <div className="space-y-1">
        {nearby.slice(0, 10).map((e) => (
          <button
            key={e.event_id}
            onClick={() => navigate(`/activity/${e.event_id}`)}
            className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-[var(--color-bg-tertiary)] transition-colors text-sm w-full text-left"
          >
            <span
              className="inline-block w-2 h-2 rounded-full shrink-0"
              style={{
                backgroundColor: getThreatColor(e.risk_level as ThreatLevel),
              }}
              aria-hidden="true"
            />
            <span className="text-xs text-[var(--color-text-secondary)] font-mono w-16 shrink-0">
              {new Date(e.timestamp).toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
              })}
            </span>
            <span className="text-[var(--color-text-primary)] flex-1 truncate">
              {e.one_liner}
            </span>
            <ActionBadge action={e.action_taken} />
          </button>
        ))}
        {nearby.length > 10 && (
          <p className="text-xs text-[var(--color-text-muted)] px-3 py-1">
            +{nearby.length - 10} more events
          </p>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// EventDetail Page
// ---------------------------------------------------------------------------

export function EventDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const events = useEventStore((s) => s.events);
  const [showTechnical, setShowTechnical] = useState(false);
  const [showEducational, setShowEducational] = useState(false);
  const [investigationId, setInvestigationId] = useState<string | null>(null);
  const [investigationDepth, setInvestigationDepth] = useState<string>("quick");
  const [startingInvestigation, setStartingInvestigation] = useState(false);
  const { canInvestigate } = useAiStatus();

  const event = useMemo(
    () => events.find((e) => e.event_id === id) ?? null,
    [events, id]
  );

  // Correlation data
  const [correlationResult, setCorrelationResult] =
    useState<CorrelationResult | null>(null);
  const [coverageResult, setCoverageResult] =
    useState<CoverageAssessment | null>(null);

  useEffect(() => {
    if (!id || !event) return;
    let cancelled = false;

    invoke<CorrelationResult>("get_correlation_for_event", { eventId: id })
      .then((result) => {
        if (!cancelled) setCorrelationResult(result);
      })
      .catch(() => {});

    invoke<CoverageAssessment>("get_coverage_summary", {
      server: event.raw_event.server_name,
      hours: 24,
    })
      .then((result) => {
        if (!cancelled) setCoverageResult(result);
      })
      .catch(() => {});

    return () => {
      cancelled = true;
    };
  }, [id, event]);

  if (!event) {
    return (
      <div className="p-4">
        <PageHeader
          title="Event Detail"
          breadcrumbs={[
            { label: "Activity", to: "/activity" },
            { label: id ?? "Unknown" },
          ]}
        />
        <div className="flex flex-col items-center justify-center h-64 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)]">
          <p className="text-[var(--color-text-secondary)] mb-2">
            Event not found
          </p>
          <p className="text-xs text-[var(--color-text-muted)]">
            The event may have been evicted from the buffer or the ID is
            invalid.
          </p>
          <button
            onClick={() => navigate("/activity")}
            className="mt-4 text-sm text-[var(--color-accent)] hover:text-[var(--color-accent-hover)] transition-colors"
          >
            Back to Activity
          </button>
        </div>
      </div>
    );
  }

  const slmAnalysis = extractSlmAnalysis(event.raw_event.details);
  const policyRule = extractPolicyRule(event.raw_event.details);

  return (
    <div className="p-4 max-w-4xl">
      <PageHeader
        title="Event Detail"
        breadcrumbs={[
          { label: "Activity", to: "/activity" },
          { label: truncateEnd(event.one_liner, 40) },
        ]}
        actions={
          <div className="flex items-center gap-2">
            <select
              value={investigationDepth}
              onChange={(e) => setInvestigationDepth(e.target.value)}
              className="px-2 py-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] text-xs text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
            >
              <option value="quick">Quick</option>
              <option value="standard">Standard</option>
              <option value="deep">Deep</option>
            </select>
            <div className="relative group">
              <button
                onClick={async () => {
                  setStartingInvestigation(true);
                  try {
                    const result = await invoke<InvestigationProgress>("start_investigation", {
                      targetType: "event",
                      targetId: event.event_id,
                      targetData: JSON.parse(JSON.stringify(event.raw_event)),
                      depth: investigationDepth,
                    });
                    setInvestigationId(result.investigation_id);
                  } catch {
                    // ok
                  }
                  setStartingInvestigation(false);
                }}
                disabled={startingInvestigation || !!investigationId || !canInvestigate}
                className="text-sm px-4 py-1.5 rounded-lg bg-[var(--color-accent)] text-white hover:bg-[var(--color-accent-hover)] disabled:opacity-50 transition-colors"
              >
                {startingInvestigation ? "Starting..." : "Investigate with AI"}
              </button>
              {!canInvestigate && (
                <span className="absolute bottom-full left-1/2 -translate-x-1/2 mb-1 hidden group-hover:block whitespace-nowrap text-xs bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] border border-[var(--color-border)] rounded px-2 py-1">
                  Requires Cloud API -- set up in Settings
                </span>
              )}
            </div>
            <button
              onClick={() =>
                navigate("/ask", {
                  state: {
                    prefill: `Tell me about this event: ${event.one_liner} (event ${event.event_id})`,
                  },
                })
              }
              className="text-sm px-4 py-1.5 rounded-lg border border-[var(--color-border)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:border-[var(--color-accent)] transition-colors"
            >
              Ask Claw
            </button>
          </div>
        }
      />

      {/* Humanized summary header */}
      <div className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-xl p-5 mb-4">
        <div className="flex items-start gap-4 mb-4">
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-1">
              <span className="text-sm font-medium text-[var(--color-text-secondary)]">
                {event.server_display_name}
              </span>
              <ActionBadge action={event.action_taken} />
              <RiskBadge level={event.risk_level} />
            </div>
            <h2 className="text-lg font-semibold text-[var(--color-text-primary)]">
              {event.one_liner}
            </h2>
            <p className="text-sm text-[var(--color-text-secondary)] mt-2">
              {event.expanded_explanation}
            </p>
          </div>
        </div>

        {/* Behavioral context */}
        {event.behavioral_context && (
          <p className="text-xs text-[var(--color-text-secondary)] italic mb-3">
            {event.behavioral_context}
          </p>
        )}

        {/* Risk explanation */}
        {event.risk_explanation && (
          <p className="text-xs text-[var(--color-warning)] mb-3">
            {event.risk_explanation}
          </p>
        )}

        {/* Educational aside */}
        {event.educational_aside && (
          <div className="text-xs mb-3">
            <button
              onClick={() => setShowEducational(!showEducational)}
              className="text-[var(--color-accent)] hover:text-[var(--color-accent-hover)] transition-colors"
            >
              {showEducational ? "Hide" : "Learn more"}
            </button>
            {showEducational && (
              <p className="mt-1 text-[var(--color-text-secondary)] bg-[var(--color-info-subtle)] border border-[var(--color-info-border)] rounded-lg p-2">
                {event.educational_aside}
              </p>
            )}
          </div>
        )}

        {/* Kill chain link */}
        {event.kill_chain_id && (
          <div className="bg-[var(--color-danger-subtle)] border border-[var(--color-danger-border)] rounded-lg p-3 mb-3">
            <p className="text-sm text-[var(--color-danger)]">
              This event is part of a detected pattern.{" "}
              <button
                onClick={() => navigate(`/alerts/${event.kill_chain_id}`)}
                className="underline hover:no-underline"
              >
                View alert
              </button>
            </p>
          </div>
        )}

        {/* Metadata */}
        <div className="grid grid-cols-2 md:grid-cols-3 gap-4 text-sm mt-4 pt-4 border-t border-[var(--color-border-subtle)]">
          <div>
            <p className="text-xs text-[var(--color-text-muted)] mb-0.5">
              Event ID
            </p>
            <p className="font-mono text-[var(--color-text-primary)] text-xs break-all">
              {event.event_id}
            </p>
          </div>
          <div>
            <p className="text-xs text-[var(--color-text-muted)] mb-0.5">
              Timestamp
            </p>
            <p className="text-[var(--color-text-primary)]">
              {new Date(event.timestamp).toLocaleString()}
            </p>
          </div>
          <div>
            <p className="text-xs text-[var(--color-text-muted)] mb-0.5">
              Action Taken
            </p>
            <p className="text-[var(--color-text-primary)]">
              {event.action_taken}
              {event.action_reason && (
                <span className="text-[var(--color-text-muted)]">
                  {" "}
                  -- {event.action_reason}
                </span>
              )}
            </p>
          </div>
        </div>
      </div>

      {/* Technical details (collapsible) */}
      <div className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-xl mb-4">
        <button
          onClick={() => setShowTechnical(!showTechnical)}
          aria-expanded={showTechnical}
          className="w-full flex items-center justify-between px-4 py-3 text-sm font-semibold text-[var(--color-text-primary)] hover:bg-[var(--color-bg-tertiary)] transition-colors rounded-xl"
        >
          <span>Technical Details</span>
          <span
            className="text-xs text-[var(--color-text-secondary)] transition-transform"
            style={{
              transform: showTechnical ? "rotate(90deg)" : "rotate(0deg)",
            }}
          >
            {"\u25B6"}
          </span>
        </button>

        {showTechnical && (
          <div className="px-4 pb-4 border-t border-[var(--color-border-subtle)]">
            <div className="grid grid-cols-2 md:grid-cols-3 gap-4 text-sm mt-3">
              <div>
                <p className="text-xs text-[var(--color-text-muted)] mb-0.5">
                  Event Type
                </p>
                <p className="text-[var(--color-text-primary)]">
                  {event.raw_event.event_type}
                </p>
              </div>
              <div>
                <p className="text-xs text-[var(--color-text-muted)] mb-0.5">
                  Server (raw)
                </p>
                <p className="text-[var(--color-text-primary)]">
                  {event.raw_event.server_name}
                </p>
              </div>
              <div>
                <p className="text-xs text-[var(--color-text-muted)] mb-0.5">
                  Tool
                </p>
                <p className="text-[var(--color-text-primary)]">
                  {event.raw_event.tool_name ?? "N/A"}
                </p>
              </div>
              <div>
                <p className="text-xs text-[var(--color-text-muted)] mb-0.5">
                  Action
                </p>
                <p className="text-[var(--color-text-primary)]">
                  {event.raw_event.action}
                </p>
              </div>
              <div>
                <p className="text-xs text-[var(--color-text-muted)] mb-0.5">
                  Decision
                </p>
                <p className="text-[var(--color-text-primary)]">
                  {event.raw_event.decision}
                </p>
              </div>
              <div>
                <p className="text-xs text-[var(--color-text-muted)] mb-0.5">
                  Resource
                </p>
                <p className="text-[var(--color-text-primary)] font-mono text-xs break-all">
                  {event.raw_event.resource ?? "N/A"}
                </p>
              </div>
            </div>

            {policyRule && (
              <div className="mt-3">
                <h4 className="text-xs font-semibold text-[var(--color-text-primary)] mb-1">
                  Policy Rule Matched
                </h4>
                <p className="text-sm text-[var(--color-text-secondary)]">
                  {policyRule}
                </p>
              </div>
            )}

            {slmAnalysis && (
              <div className="mt-3">
                <h4 className="text-xs font-semibold text-[var(--color-text-primary)] mb-1 flex items-center gap-1.5">
                  <span className="inline-block w-2 h-2 rounded-full bg-[var(--color-accent)]" aria-hidden="true" />
                  AI Analysis
                </h4>
                <div className="text-sm text-[var(--color-text-primary)] bg-[var(--color-info-subtle)] border border-[var(--color-info-border)] rounded-lg p-3 whitespace-pre-wrap">
                  {slmAnalysis}
                </div>
              </div>
            )}

            <div className="mt-3">
              <h4 className="text-xs font-semibold text-[var(--color-text-primary)] mb-1">
                Raw Event JSON
              </h4>
              <ExpandableContent
                content={tryFormatJson(JSON.stringify(event.raw_event))}
                previewLines={8}
              />
            </div>
          </div>
        )}
      </div>

      {/* Mini timeline */}
      <MiniTimeline event={event} allEvents={events} />

      {/* Deep correlation timeline */}
      {correlationResult && (
        <div className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-xl p-4 mb-4 mt-4">
          <CorrelationTimeline
            result={correlationResult}
            onEventClick={(eventId) => navigate(`/activity/${eventId}`)}
          />
        </div>
      )}

      {/* Coverage insight */}
      {coverageResult && event && (
        <div className="mb-4 mt-4">
          <CoverageInsight
            assessment={coverageResult}
            serverName={event.raw_event.server_name}
          />
        </div>
      )}

      {/* Investigation results */}
      {investigationId && (
        <div className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-xl p-4 mb-4 mt-4">
          <h3 className="text-xs font-semibold text-[var(--color-text-muted)] uppercase tracking-wide mb-3">
            AI Investigation
          </h3>
          <LiveInvestigationView
            investigationId={investigationId}
            onComplete={() => {}}
            onCancel={() => setInvestigationId(null)}
          />
        </div>
      )}

      {/* Back button */}
      <div className="mt-6">
        <button
          onClick={() => navigate("/activity")}
          className="text-sm text-[var(--color-accent)] hover:text-[var(--color-accent-hover)] transition-colors"
        >
          Back to Activity
        </button>
      </div>
    </div>
  );
}
