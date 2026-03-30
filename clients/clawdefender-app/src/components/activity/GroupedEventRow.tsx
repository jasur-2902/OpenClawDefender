import { useState, memo } from "react";
import { useNavigate } from "react-router-dom";
import type { EventGroup } from "../../utils/eventGrouper";
import { formatTimestamp } from "../../utils/formatTime";
import { getThreatColor } from "../../utils/threatLevel";
import type { ThreatLevel } from "../../utils/threatLevel";
import { EventRow } from "./EventRow";

interface GroupedEventRowProps {
  group: EventGroup;
}

export const GroupedEventRow = memo(function GroupedEventRow({ group }: GroupedEventRowProps) {
  const [expanded, setExpanded] = useState(false);
  const navigate = useNavigate();

  const rep = group.representative;

  // Count actions within group
  const blockedCount = group.children.filter(
    (e) => e.action_taken === "Blocked" || e.action_taken === "AutoBlocked"
  ).length;
  const promptedCount = group.children.filter(
    (e) => e.action_taken === "Prompted"
  ).length;

  const hasNotable = blockedCount > 0 || promptedCount > 0;

  // Kill chain groups get a special visual treatment
  const isKillChain = group.type === "kill_chain";
  const isPromptSeq = group.type === "prompt_sequence";

  const borderClass = isKillChain
    ? "border-l-2 border-l-[var(--color-danger)]"
    : isPromptSeq
      ? "border-l-2 border-l-[var(--color-warning)]"
      : "";

  const bgClass = isKillChain
    ? "bg-[var(--color-danger-subtle)]/5"
    : "";

  // Determine highest risk in group for the dot
  const riskOrder: Record<string, number> = {
    dangerous: 5,
    suspicious: 4,
    unusual: 3,
    blocked: 2,
    normal: 1,
    info: 0,
  };
  const highestRisk = group.children.reduce((best, e) => {
    return (riskOrder[e.risk_level] ?? 0) > (riskOrder[best] ?? 0)
      ? e.risk_level
      : best;
  }, rep.risk_level);

  return (
    <div
      className={`border-b border-[var(--color-border-subtle)] ${borderClass} ${bgClass}`}
    >
      {/* Summary row */}
      <div
        onClick={() => setExpanded(!expanded)}
        className="flex items-center gap-3 px-4 py-2.5 cursor-pointer hover:bg-[var(--color-bg-secondary)] transition-colors focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-[var(--color-accent)]"
        role="button"
        tabIndex={0}
        aria-expanded={expanded}
        aria-label={`${group.summary}, ${group.count} events from ${rep.server_display_name}, ${expanded ? "collapse" : "expand"}`}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            setExpanded(!expanded);
          }
        }}
      >
        {/* Chevron */}
        <span
          className="text-xs text-[var(--color-text-secondary)] w-4 shrink-0 transition-transform"
          style={{ transform: expanded ? "rotate(90deg)" : "rotate(0deg)" }}
        >
          {"\u25B6"}
        </span>

        {/* Risk dot */}
        <span
          className="inline-block w-2 h-2 rounded-full shrink-0"
          style={{
            backgroundColor: getThreatColor(highestRisk as ThreatLevel),
          }}
          role="img"
          aria-label={`Highest risk: ${highestRisk}`}
        />

        <span className="text-xs text-[var(--color-text-secondary)] w-16 shrink-0 font-mono">
          {formatTimestamp(rep.timestamp)}
        </span>

        <span className="text-xs font-medium text-[var(--color-text-secondary)] shrink-0">
          {rep.server_display_name}
        </span>

        <span className="text-sm text-[var(--color-text-primary)] flex-1 truncate">
          {isKillChain && (
            <span className="text-xs font-medium text-[var(--color-danger)] mr-1.5">
              Threat Story
            </span>
          )}
          {isPromptSeq && (
            <span className="text-xs font-medium text-[var(--color-warning)] mr-1.5">
              Prompt
            </span>
          )}
          {group.summary}
        </span>

        {/* Notable counts */}
        {hasNotable && (
          <span className="flex items-center gap-1.5 shrink-0">
            {blockedCount > 0 && (
              <span
                className="text-xs px-1.5 py-0.5 rounded-full font-medium"
                style={{
                  backgroundColor: "var(--color-danger-subtle)",
                  color: "var(--color-danger)",
                }}
              >
                {blockedCount} blocked
              </span>
            )}
            {promptedCount > 0 && (
              <span
                className="text-xs px-1.5 py-0.5 rounded-full font-medium"
                style={{
                  backgroundColor: "var(--color-warning-subtle)",
                  color: "var(--color-warning)",
                }}
              >
                {promptedCount} prompted
              </span>
            )}
          </span>
        )}

        <span className="text-xs text-[var(--color-text-secondary)] shrink-0 tabular-nums">
          {group.count} events
        </span>
      </div>

      {/* Kill chain link */}
      {isKillChain && !expanded && group.kill_chain_id && (
        <div className="px-4 pb-2">
          <button
            onClick={(e) => {
              e.stopPropagation();
              navigate(`/alerts/${group.kill_chain_id}`);
            }}
            className="text-xs text-[var(--color-danger)] hover:underline transition-colors"
          >
            View full threat story
          </button>
        </div>
      )}

      {/* Expanded children */}
      {expanded && (
        <div className="bg-[var(--color-bg-sunken)] border-t border-[var(--color-border-subtle)]">
          {group.children.map((event) => (
            <EventRow key={event.event_id} event={event} />
          ))}
          {isKillChain && group.kill_chain_id && (
            <div className="px-4 py-2 bg-[var(--color-bg-secondary)] border-t border-[var(--color-border-subtle)]">
              <button
                onClick={() => navigate(`/alerts/${group.kill_chain_id}`)}
                className="text-xs text-[var(--color-danger)] hover:underline transition-colors"
              >
                View complete threat story and recommendations
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
});
