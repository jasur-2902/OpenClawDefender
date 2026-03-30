import { useState } from "react";
import type { CorrelationResult, CorrelatedEvent, UncorrelatedEvent } from "../../types";

// ---------------------------------------------------------------------------
// SVG Icons
// ---------------------------------------------------------------------------

function ChainIcon({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
      <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
    </svg>
  );
}

function BrokenChainIcon({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
      <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
      <line x1="2" y1="2" x2="22" y2="22" />
    </svg>
  );
}

function WarningIcon({ className, style }: { className?: string; style?: React.CSSProperties }) {
  return (
    <svg
      className={className}
      style={style}
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatTime(timestamp: string): string {
  try {
    return new Date(timestamp).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return timestamp;
  }
}

function confidenceColor(confidence: number): string {
  if (confidence >= 0.7) return "var(--color-safe)";
  if (confidence >= 0.4) return "var(--color-warning)";
  return "var(--color-text-muted)";
}

function confidenceLineStyle(confidence: number): string {
  if (confidence >= 0.7) return "solid";
  return "dashed";
}

function concernColor(level: string): string {
  switch (level) {
    case "high":
      return "var(--color-danger)";
    case "medium":
      return "var(--color-warning)";
    default:
      return "var(--color-text-muted)";
  }
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function CorrelatedEventItem({
  event,
  side,
  onClick,
}: {
  event: CorrelatedEvent;
  side: "left" | "right";
  onClick?: (eventId: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const color = confidenceColor(event.match_confidence);

  return (
    <div
      className={`flex flex-col gap-1 p-2 rounded-lg border cursor-pointer transition-colors hover:bg-[var(--color-bg-tertiary)] ${
        side === "left" ? "items-end text-right" : "items-start text-left"
      }`}
      style={{ borderColor: color }}
      onClick={() => {
        if (onClick) onClick(event.event_id);
        else setExpanded(!expanded);
      }}
      role="button"
      tabIndex={0}
      aria-label={`Correlated event: ${event.description}, ${(event.match_confidence * 100).toFixed(0)}% match confidence`}
      aria-expanded={expanded}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          if (onClick) onClick(event.event_id);
          else setExpanded(!expanded);
        }
      }}
    >
      <div className="flex items-center gap-1.5">
        <ChainIcon className="shrink-0" />
        <span className="text-xs font-mono text-[var(--color-text-secondary)]">
          {formatTime(event.timestamp)}
        </span>
      </div>
      <p className="text-xs text-[var(--color-text-primary)] leading-snug">
        {event.description}
      </p>
      <span
        className="text-[10px] font-medium"
        style={{ color }}
      >
        {(event.match_confidence * 100).toFixed(0)}% match
      </span>
      {expanded && (
        <p className="text-[10px] text-[var(--color-text-muted)] mt-1">
          {event.match_reason}
        </p>
      )}
    </div>
  );
}

function UncorrelatedEventItem({
  event,
  onClick,
}: {
  event: UncorrelatedEvent;
  onClick?: (eventId: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const color = concernColor(event.concern_level);

  return (
    <div
      className="flex flex-col gap-1 p-2 rounded-lg border cursor-pointer transition-colors hover:bg-[var(--color-bg-tertiary)]"
      style={{
        borderColor: color,
        backgroundColor: `${color}08`,
      }}
      onClick={() => {
        if (onClick) onClick(event.event_id);
        else setExpanded(!expanded);
      }}
      role="button"
      tabIndex={0}
      aria-label={`Uncorrelated event: ${event.description}, concern level ${event.concern_level}`}
      aria-expanded={expanded}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          if (onClick) onClick(event.event_id);
          else setExpanded(!expanded);
        }
      }}
    >
      <div className="flex items-center gap-1.5">
        <WarningIcon className="shrink-0" style={{ color }} />
        <span className="text-xs font-mono text-[var(--color-text-secondary)]">
          {formatTime(event.timestamp)}
        </span>
        <span
          className="text-[10px] px-1.5 py-0.5 rounded-full font-medium"
          style={{ color, backgroundColor: `${color}15` }}
        >
          {event.concern_level}
        </span>
      </div>
      <p className="text-xs text-[var(--color-text-primary)] leading-snug">
        {event.description}
      </p>
      {expanded && (
        <p className="text-[10px] text-[var(--color-text-muted)] mt-1">
          {event.explanation}
        </p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// CorrelationTimeline
// ---------------------------------------------------------------------------

interface CorrelationTimelineProps {
  result: CorrelationResult;
  onEventClick?: (eventId: string) => void;
}

export function CorrelationTimeline({
  result,
  onEventClick,
}: CorrelationTimelineProps) {
  if (
    result.correlated_events.length === 0 &&
    result.uncorrelated_events.length === 0
  ) {
    return (
      <div className="text-center py-6">
        <BrokenChainIcon className="mx-auto mb-2 text-[var(--color-text-muted)]" />
        <p className="text-sm text-[var(--color-text-secondary)]">
          No correlated events found for this activity
        </p>
        <p className="text-xs text-[var(--color-text-muted)] mt-1">
          This event has no matching OS-level activity in the time window
        </p>
      </div>
    );
  }

  // Sort all events by timestamp for the timeline
  const allCorrelated = [...result.correlated_events].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );
  const allUncorrelated = [...result.uncorrelated_events].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );

  return (
    <div className="space-y-4">
      {/* Overall confidence header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ChainIcon className="text-[var(--color-text-secondary)]" />
          <span className="text-sm font-medium text-[var(--color-text-primary)]">
            Event Correlation
          </span>
        </div>
        <span
          className="text-xs font-medium px-2 py-0.5 rounded-full"
          style={{
            color: confidenceColor(result.correlation_confidence),
            backgroundColor: `${confidenceColor(result.correlation_confidence)}15`,
          }}
        >
          {(result.correlation_confidence * 100).toFixed(0)}% overall confidence
        </span>
      </div>

      {/* Dual-lane timeline */}
      <div className="grid grid-cols-[1fr_auto_1fr] gap-x-3">
        {/* Column headers */}
        <div className="text-[10px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)] pb-2 text-right">
          MCP Protocol
        </div>
        <div />
        <div className="text-[10px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)] pb-2">
          Correlated Activity
        </div>

        {/* Correlated events in dual lanes */}
        {allCorrelated.map((event) => (
          <div key={event.event_id} className="contents">
            {/* Left lane (MCP side) - shows the match reason */}
            <div className="flex justify-end pb-2">
              <div className="text-[10px] text-[var(--color-text-muted)] py-2 text-right max-w-[160px]">
                {event.match_reason}
              </div>
            </div>

            {/* Center connector line */}
            <div className="flex flex-col items-center pb-2">
              <div
                className="w-px flex-1"
                style={{
                  borderLeft: `2px ${confidenceLineStyle(event.match_confidence)} ${confidenceColor(event.match_confidence)}`,
                }}
              />
              <div
                className="w-2 h-2 rounded-full shrink-0"
                style={{ backgroundColor: confidenceColor(event.match_confidence) }}
              />
              <div
                className="w-px flex-1"
                style={{
                  borderLeft: `2px ${confidenceLineStyle(event.match_confidence)} ${confidenceColor(event.match_confidence)}`,
                }}
              />
            </div>

            {/* Right lane (Correlated activity) */}
            <div className="pb-2">
              <CorrelatedEventItem
                event={event}
                side="right"
                onClick={onEventClick}
              />
            </div>
          </div>
        ))}
      </div>

      {/* Uncorrelated events section */}
      {allUncorrelated.length > 0 && (
        <div className="mt-4">
          <div className="flex items-center gap-2 mb-2">
            <WarningIcon className="text-[var(--color-warning)]" />
            <span className="text-sm font-medium text-[var(--color-text-primary)]">
              Unmatched OS Activity
            </span>
            <span className="text-xs text-[var(--color-text-muted)]">
              ({allUncorrelated.length} event{allUncorrelated.length !== 1 ? "s" : ""})
            </span>
          </div>
          <p className="text-xs text-[var(--color-text-secondary)] mb-3">
            These system-level events happened nearby but don't match any MCP
            request
          </p>
          <div className="space-y-2">
            {allUncorrelated.map((event) => (
              <UncorrelatedEventItem
                key={event.event_id}
                event={event}
                onClick={onEventClick}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
