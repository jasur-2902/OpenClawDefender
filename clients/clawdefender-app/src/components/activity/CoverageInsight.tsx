import { useState } from "react";
import type { CoverageAssessment } from "../../types";

// ---------------------------------------------------------------------------
// SVG Icons
// ---------------------------------------------------------------------------

function InfoIcon({ className }: { className?: string }) {
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
      <circle cx="12" cy="12" r="10" />
      <path d="M12 16v-4" />
      <path d="M12 8h.01" />
    </svg>
  );
}

// ---------------------------------------------------------------------------
// CoverageInsight
// ---------------------------------------------------------------------------

interface CoverageInsightProps {
  assessment: CoverageAssessment;
  serverName: string;
}

export function CoverageInsight({ assessment, serverName }: CoverageInsightProps) {
  const [showTooltip, setShowTooltip] = useState(false);
  const percent = Math.round(assessment.coverage_percent);
  const isWarning = percent < 70;

  const barColor = isWarning
    ? "var(--color-warning)"
    : "var(--color-safe)";

  const textColor = isWarning
    ? "var(--color-warning)"
    : "var(--color-text-secondary)";

  return (
    <div
      className="rounded-lg border p-3"
      style={{
        borderColor: isWarning
          ? "var(--color-warning-border)"
          : "var(--color-border)",
        backgroundColor: isWarning
          ? "var(--color-warning-subtle)"
          : "var(--color-bg-secondary)",
      }}
    >
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-1.5">
          <span className="text-xs font-medium text-[var(--color-text-primary)]">
            MCP Coverage
          </span>
          <div
            className="relative"
            onMouseEnter={() => setShowTooltip(true)}
            onMouseLeave={() => setShowTooltip(false)}
            onFocus={() => setShowTooltip(true)}
            onBlur={() => setShowTooltip(false)}
            tabIndex={0}
            role="button"
            aria-label="What is MCP coverage?"
          >
            <InfoIcon className="text-[var(--color-text-muted)] cursor-help" />
            {showTooltip && (
              <div className="absolute left-1/2 -translate-x-1/2 bottom-full mb-2 w-56 bg-[var(--color-bg-primary)] border border-[var(--color-border)] rounded-lg p-2 shadow-[var(--shadow-dropdown)] z-[var(--z-dropdown)]">
                <p className="text-[10px] text-[var(--color-text-secondary)] leading-relaxed">
                  Coverage measures how many of {serverName}'s MCP protocol
                  requests have matching OS-level activity. High coverage means
                  I can verify what the tool is actually doing.
                </p>
              </div>
            )}
          </div>
        </div>
        <span
          className="text-sm font-semibold tabular-nums"
          style={{ color: barColor }}
        >
          {percent}%
        </span>
      </div>

      {/* Progress bar */}
      <div className="h-1.5 rounded-full bg-[var(--color-bg-tertiary)] overflow-hidden mb-2">
        <div
          className="h-full rounded-full transition-all"
          style={{
            width: `${percent}%`,
            backgroundColor: barColor,
            transition: "width var(--duration-moderate) var(--ease-out)",
          }}
        />
      </div>

      {/* Description text */}
      <p className="text-xs leading-relaxed" style={{ color: textColor }}>
        {isWarning
          ? `This tool is doing things I can't fully see through the MCP channel`
          : `${percent}% of this tool's activity has matching protocol requests`}
      </p>

      {/* Stats row */}
      {(assessment.mcp_events_with_match > 0 || assessment.uncorrelated_count > 0) && (
        <div className="flex gap-3 mt-2 text-[10px] text-[var(--color-text-muted)]">
          <span>{assessment.mcp_events_with_match} matched</span>
          <span>{assessment.mcp_events_without_match} unmatched</span>
          {assessment.uncorrelated_count > 0 && (
            <span style={{ color: "var(--color-warning)" }}>
              {assessment.uncorrelated_count} uncorrelated
            </span>
          )}
        </div>
      )}
    </div>
  );
}
