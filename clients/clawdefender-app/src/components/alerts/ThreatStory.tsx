/**
 * ThreatStory -- visual narrative for kill chain detection.
 *
 * Renders a vertical connected timeline from KillChainNarrative data,
 * with a verdict card at the bottom showing summary, outcome, and confidence.
 */

import { useState } from "react";
import { Link } from "react-router-dom";
import { getThreatColor, type ThreatLevel } from "../../utils/threatLevel";
import type { KillChainNarrative, KillChainStep } from "../../types";

interface ThreatStoryProps {
  narrative: KillChainNarrative;
  recommendation?: string;
  serverName?: string | null;
  onAction?: () => void;
  actionLabel?: string;
}

function formatTime(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch {
    return ts;
  }
}

function getStepLineColor(step: KillChainStep): string {
  if (step.was_blocked) return "var(--color-safe)";
  const severity = step.severity?.toLowerCase();
  if (severity === "dangerous") return "var(--color-danger)";
  if (severity === "suspicious") return "var(--color-warning)";
  return "var(--color-warning)";
}

function getConfidenceLabel(confidence: number): { label: string; color: string } {
  if (confidence >= 0.8) return { label: "High confidence", color: "var(--color-danger)" };
  if (confidence >= 0.5) return { label: "Possible", color: "var(--color-warning)" };
  return { label: "Low confidence", color: "var(--color-info)" };
}

function getTimeRange(steps: KillChainStep[]): { start: string; end: string } | null {
  if (steps.length === 0) return null;
  const sorted = [...steps].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );
  return { start: sorted[0].timestamp, end: sorted[sorted.length - 1].timestamp };
}

export function ThreatStory({
  narrative,
  recommendation,
  serverName,
  onAction,
  actionLabel = "Take Action",
}: ThreatStoryProps) {
  const [expandedStep, setExpandedStep] = useState<number | null>(null);
  const confidenceInfo = getConfidenceLabel(narrative.confidence);
  const timeRange = getTimeRange(narrative.steps);

  return (
    <div className="space-y-0">
      {/* Pattern name */}
      <div className="flex items-center gap-2 mb-3">
        <p className="text-xs font-semibold text-[var(--color-text-primary)] uppercase tracking-wide">
          {narrative.pattern_name}
        </p>
        <span
          className="text-[10px] font-semibold px-2 py-0.5 rounded-full"
          style={{
            color: confidenceInfo.color,
            backgroundColor: `color-mix(in srgb, ${confidenceInfo.color} 15%, transparent)`,
          }}
        >
          {confidenceInfo.label}
        </span>
      </div>

      {/* Summary */}
      <p className="text-sm text-[var(--color-text-secondary)] mb-4">
        {narrative.summary}
      </p>

      {/* Server label */}
      {serverName && (
        <p className="text-xs text-[var(--color-text-muted)] mb-3">
          Server:{" "}
          <Link
            to={`/tools/${encodeURIComponent(serverName)}`}
            className="text-[var(--color-accent)] hover:underline"
          >
            {serverName}
          </Link>
        </p>
      )}

      {/* Timeline */}
      <div className="relative pl-6" role="list" aria-label="Kill chain timeline">
        {narrative.steps.map((step, i) => {
          const isLast = i === narrative.steps.length - 1;
          const lineColor = getStepLineColor(step);
          const severityColor = getThreatColor(
            (step.severity?.toLowerCase() || "info") as ThreatLevel
          );
          const isExpanded = expandedStep === step.step_number;

          return (
            <div key={step.step_number} className="relative pb-4" role="listitem" aria-label={`Step ${step.step_number}: ${step.description}${step.was_blocked ? ", blocked by RookBot" : ", allowed"}`}>
              {/* Connecting line */}
              {!isLast && (
                <div
                  className="absolute left-[-18px] top-6 w-0.5 h-[calc(100%-8px)]"
                  style={{ backgroundColor: lineColor }}
                  aria-hidden="true"
                />
              )}

              {/* Step circle */}
              <div
                className="absolute left-[-24px] top-1 w-[13px] h-[13px] rounded-full border-2 flex items-center justify-center text-[7px] font-bold"
                style={{
                  borderColor: severityColor,
                  backgroundColor: step.was_blocked
                    ? "var(--color-safe)"
                    : severityColor,
                  color: "white",
                }}
                aria-hidden="true"
              >
                {step.step_number}
              </div>

              {/* Step content */}
              <button
                onClick={() =>
                  setExpandedStep(isExpanded ? null : step.step_number)
                }
                className="w-full text-left cursor-pointer"
                aria-expanded={isExpanded}
                aria-label={`Step ${step.step_number}: ${step.description}`}
              >
                <div className="flex items-start gap-3">
                  <span className="text-xs text-[var(--color-text-muted)] font-mono w-16 shrink-0 pt-0.5">
                    {formatTime(step.timestamp)}
                  </span>
                  <div className="flex-1">
                    <p className="text-sm text-[var(--color-text-primary)]">
                      {step.description}
                    </p>
                    <div className="flex items-center gap-2 mt-1">
                      <span
                        className="w-2 h-2 rounded-full inline-block"
                        style={{ backgroundColor: severityColor }}
                        aria-hidden="true"
                      />
                      {step.was_blocked ? (
                        <span className="text-[10px] uppercase font-medium px-1.5 py-0.5 rounded bg-[var(--color-safe-subtle)] text-[var(--color-safe)]">
                          Blocked
                        </span>
                      ) : (
                        <span className="text-[10px] uppercase font-medium px-1.5 py-0.5 rounded bg-[var(--color-danger-subtle)] text-[var(--color-danger)]">
                          Allowed
                        </span>
                      )}
                      {step.was_blocked && (
                        <span className="text-[10px] text-[var(--color-safe)]">
                          RookBot stopped this
                        </span>
                      )}
                    </div>

                    {/* Expanded detail */}
                    {isExpanded && (
                      <div className="mt-2 p-2 rounded bg-[var(--color-bg-tertiary)] text-xs text-[var(--color-text-secondary)]">
                        <p>Event ID: <span className="font-mono">{step.event_id}</span></p>
                        <p className="mt-1">Severity: <span className="capitalize">{step.severity}</span></p>
                      </div>
                    )}
                  </div>
                </div>
              </button>
            </div>
          );
        })}
      </div>

      {/* Verdict card */}
      <div className="mt-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4">
        <p className="text-sm font-medium text-[var(--color-text-primary)] mb-1">
          Verdict
        </p>
        <p className="text-sm text-[var(--color-text-secondary)] mb-2">
          {narrative.verdict}
        </p>
        <p className="text-xs text-[var(--color-text-muted)] mb-1">
          Outcome: {narrative.outcome}
        </p>

        {recommendation && (
          <div className="mt-3 mb-3 p-2 rounded border-l-2 border-[var(--color-accent)] bg-[var(--color-bg-tertiary)]">
            <p className="text-xs text-[var(--color-text-secondary)]">
              {recommendation}
            </p>
          </div>
        )}

        <div className="flex items-center gap-3 mt-3">
          {onAction && (
            <button
              onClick={onAction}
              className="text-xs px-3 py-1.5 rounded-lg bg-[var(--color-accent)] text-white hover:opacity-90 transition-opacity"
            >
              {actionLabel}
            </button>
          )}
          <Link
            to="/ask"
            state={{ prefill: `Tell me more about the ${narrative.pattern_name} kill chain.` }}
            className="text-xs text-[var(--color-accent)] hover:underline"
          >
            Ask Rook for more details
          </Link>
        </div>

        {/* View all events link */}
        {timeRange && (
          <div className="mt-2">
            <Link
              to={`/activity?from=${encodeURIComponent(timeRange.start)}&to=${encodeURIComponent(timeRange.end)}`}
              className="text-xs text-[var(--color-accent)] hover:underline"
            >
              View all events from this period
            </Link>
          </div>
        )}
      </div>
    </div>
  );
}
