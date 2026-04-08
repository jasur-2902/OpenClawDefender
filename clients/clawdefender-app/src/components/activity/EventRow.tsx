import { useState, memo } from "react";
import { useNavigate } from "react-router-dom";
import type { HumanizedEvent } from "../../types";
import { getThreatColor } from "../../utils/threatLevel";
import type { ThreatLevel } from "../../utils/threatLevel";
import { formatRelativeTime } from "../../utils/formatTime";
import { ExpandableContent } from "../shared/TruncatedText";
import { truncateEnd } from "../../utils/textUtils";

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

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
      className="text-xs px-2 py-0.5 rounded-full font-medium"
      style={{ backgroundColor: c.bg, color: c.color }}
    >
      {c.label}
    </span>
  );
}

function RiskDot({ riskLevel }: { riskLevel: HumanizedEvent["risk_level"] }) {
  const color = getThreatColor(riskLevel as ThreatLevel);
  return (
    <span
      className="inline-block w-2 h-2 rounded-full shrink-0"
      style={{ backgroundColor: color }}
      role="img"
      aria-label={`Risk level: ${riskLevel}`}
      title={`Risk: ${riskLevel}`}
    />
  );
}

function RiskBadge({ level }: { level: HumanizedEvent["risk_level"] }) {
  const color = getThreatColor(level as ThreatLevel);
  return (
    <span
      className="text-xs px-1.5 py-0.5 rounded"
      style={{ color, borderColor: color, border: "1px solid" }}
    >
      {level}
    </span>
  );
}

// ---------------------------------------------------------------------------
// SLM Analysis extraction (for technical detail level)
// ---------------------------------------------------------------------------

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

function tryFormatJson(str: string): string {
  try {
    return JSON.stringify(JSON.parse(str), null, 2);
  } catch {
    return str;
  }
}

// ---------------------------------------------------------------------------
// EventRow Component -- Three detail levels
// ---------------------------------------------------------------------------

interface EventRowProps {
  event: HumanizedEvent;
  defaultExpanded?: boolean;
}

export const EventRow = memo(function EventRow({ event, defaultExpanded = false }: EventRowProps) {
  const [level, setLevel] = useState<"glance" | "summary" | "full">(
    defaultExpanded ? "summary" : "glance"
  );
  const [showEducational, setShowEducational] = useState(false);
  const navigate = useNavigate();

  const handleClick = () => {
    if (level === "glance") setLevel("summary");
    else if (level === "summary") setLevel("glance");
  };

  const toggleFull = (e: React.MouseEvent) => {
    e.stopPropagation();
    setLevel(level === "full" ? "summary" : "full");
  };

  const slmAnalysis = extractSlmAnalysis(event.raw_event.details);
  const policyRule = extractPolicyRule(event.raw_event.details);

  // Notable events get subtle highlight
  const notableBg = event.is_notable
    ? "bg-[var(--color-warning-subtle)]/10"
    : "";

  return (
    <div
      className={`border-b border-[var(--color-border-subtle)] transition-colors ${notableBg}`}
      data-event-id={event.event_id}
    >
      {/* Glance row -- always visible */}
      <div
        onClick={handleClick}
        className="flex items-center gap-3 px-4 py-2.5 cursor-pointer hover:bg-[var(--color-bg-secondary)] transition-colors focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-[var(--color-accent)]"
        role="button"
        tabIndex={0}
        aria-expanded={level !== "glance"}
        aria-label={`${event.one_liner}, ${event.server_display_name}, risk ${event.risk_level}, ${event.action_taken}`}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            handleClick();
          }
        }}
      >
        {/* Left: risk dot + relative time */}
        <RiskDot riskLevel={event.risk_level} />
        <span className="text-xs text-[var(--color-text-secondary)] w-16 shrink-0 font-mono">
          {formatRelativeTime(event.timestamp)}
        </span>

        {/* Center: display name + one-liner */}
        <span className="text-xs font-medium text-[var(--color-text-secondary)] shrink-0" title={event.server_display_name}>
          {truncateEnd(event.server_display_name, 24)}
        </span>
        <span className="text-sm text-[var(--color-text-primary)] flex-1 truncate" title={event.one_liner}>
          {event.one_liner}
        </span>

        {/* Right: action badge */}
        <ActionBadge action={event.action_taken} />
      </div>

      {/* Summary level -- click to expand */}
      {(level === "summary" || level === "full") && (
        <div className="px-4 pb-3 pt-1 bg-[var(--color-bg-secondary)] border-t border-[var(--color-border-subtle)]">
          <div className="space-y-2 text-sm">
            {/* Expanded explanation */}
            <p className="text-sm text-[var(--color-text-primary)]">
              {event.expanded_explanation}
            </p>

            {/* Behavioral context */}
            {event.behavioral_context && (
              <p className="text-xs text-[var(--color-text-secondary)] italic">
                {event.behavioral_context}
              </p>
            )}

            {/* Risk explanation */}
            {event.risk_explanation && (
              <p className="text-xs text-[var(--color-warning)]">
                {event.risk_explanation}
              </p>
            )}

            {/* Educational aside */}
            {event.educational_aside && (
              <div className="text-xs">
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    setShowEducational(!showEducational);
                  }}
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
              <p className="text-xs">
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    navigate(`/alerts/${event.kill_chain_id}`);
                  }}
                  className="text-[var(--color-warning)] hover:text-[var(--color-warning-hover)] transition-colors"
                >
                  This is part of a larger pattern -- View full story
                </button>
              </p>
            )}

            {/* Action buttons */}
            <div className="flex items-center gap-2 pt-1">
              <RiskBadge level={event.risk_level} />
              <button
                onClick={toggleFull}
                className="text-xs text-[var(--color-accent)] hover:text-[var(--color-accent-hover)] transition-colors"
              >
                {level === "full"
                  ? "Hide technical details"
                  : "Show technical details"}
              </button>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  navigate(`/activity/${event.event_id}`);
                }}
                className="text-xs text-[var(--color-accent)] hover:text-[var(--color-accent-hover)] transition-colors"
              >
                Open detail page
              </button>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  navigate("/ask", {
                    state: {
                      prefill: `Tell me about this event: ${event.one_liner} (event ${event.event_id})`,
                    },
                  });
                }}
                className="text-xs text-[var(--color-accent)] hover:text-[var(--color-accent-hover)] transition-colors"
              >
                Ask Claw about this
              </button>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                }}
                className="text-xs text-[var(--color-text-muted)] cursor-default"
                title="Coming soon"
              >
                Show related events
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Full technical detail level */}
      {level === "full" && (
        <div className="px-4 pb-4 bg-[var(--color-bg-secondary)]">
          <div className="grid grid-cols-2 gap-3 mb-3 text-xs">
            <div>
              <span className="text-[var(--color-text-secondary)]">
                Event ID
              </span>
              <p className="font-mono text-[var(--color-text-primary)]">
                {event.event_id}
              </p>
            </div>
            <div>
              <span className="text-[var(--color-text-secondary)]">
                Timestamp
              </span>
              <p className="text-[var(--color-text-primary)]">
                {new Date(event.timestamp).toLocaleString()}
              </p>
            </div>
            <div>
              <span className="text-[var(--color-text-secondary)]">
                Event Type
              </span>
              <p className="text-[var(--color-text-primary)]">
                {event.raw_event.event_type}
              </p>
            </div>
            <div>
              <span className="text-[var(--color-text-secondary)]">
                Server (raw)
              </span>
              <p className="text-[var(--color-text-primary)]">
                {event.raw_event.server_name}
              </p>
            </div>
            <div>
              <span className="text-[var(--color-text-secondary)]">Tool</span>
              <p className="text-[var(--color-text-primary)]">
                {event.raw_event.tool_name ?? "N/A"}
              </p>
            </div>
            <div>
              <span className="text-[var(--color-text-secondary)]">
                Action
              </span>
              <p className="text-[var(--color-text-primary)]">
                {event.raw_event.action}
              </p>
            </div>
          </div>

          {policyRule && (
            <p className="text-xs text-[var(--color-text-secondary)] mb-2">
              <span className="font-medium text-[var(--color-text-primary)]">
                Policy rule:
              </span>{" "}
              {policyRule}
            </p>
          )}

          {slmAnalysis && (
            <div className="text-xs mb-2">
              <span className="inline-block w-2 h-2 rounded-full bg-[var(--color-accent)] mr-1.5" aria-hidden="true" />
              <span className="text-[var(--color-text-secondary)]">
                AI analysis:
              </span>
              <p className="mt-1 text-[var(--color-text-primary)] bg-[var(--color-info-subtle)] border border-[var(--color-info-border)] rounded-lg p-2 whitespace-pre-wrap">
                {slmAnalysis}
              </p>
            </div>
          )}

          <div>
            <span className="text-xs text-[var(--color-text-secondary)]">
              Raw Event JSON
            </span>
            <ExpandableContent
              content={tryFormatJson(JSON.stringify(event.raw_event))}
              previewLines={6}
              className="mt-1"
            />
          </div>
        </div>
      )}
    </div>
  );
});
