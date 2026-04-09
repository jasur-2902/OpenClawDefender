import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { TimelineView } from "./TimelineView";
import type { InvestigationResult } from "../../types";

interface Props {
  investigationId: string;
  /** If provided, render this result directly instead of fetching. */
  result?: InvestigationResult;
}

const VERDICT_STYLES: Record<string, { color: string; bg: string; label: string }> = {
  FalsePositive: { color: "var(--color-text-secondary)", bg: "var(--color-bg-tertiary)", label: "False Positive" },
  Benign: { color: "var(--color-success)", bg: "color-mix(in srgb, var(--color-success) 15%, transparent)", label: "Benign" },
  Suspicious: { color: "var(--color-warning)", bg: "color-mix(in srgb, var(--color-warning) 15%, transparent)", label: "Suspicious" },
  ConfirmedThreat: { color: "var(--color-danger)", bg: "color-mix(in srgb, var(--color-danger) 15%, transparent)", label: "Confirmed Threat" },
};

function VerdictBadge({ verdict, confidence }: { verdict: string; confidence: number }) {
  const style = VERDICT_STYLES[verdict] || VERDICT_STYLES.Suspicious;
  return (
    <div className="flex items-center gap-2">
      <span
        className="text-xs font-semibold px-2.5 py-1 rounded-full uppercase tracking-wide"
        style={{ color: style.color, backgroundColor: style.bg }}
      >
        {style.label}
      </span>
      <span className="text-xs text-[var(--color-text-secondary)]">
        {(confidence * 100).toFixed(0)}% confidence
      </span>
    </div>
  );
}

function AccordionSection({
  title,
  children,
  defaultOpen = false,
}: {
  title: string;
  children: React.ReactNode;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="border border-[var(--color-border)] rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-4 py-3 text-sm font-medium text-[var(--color-text-primary)] hover:bg-[var(--color-bg-tertiary)] transition-colors"
      >
        <span>{title}</span>
        <span
          className="text-xs text-[var(--color-text-secondary)] transition-transform"
          style={{ transform: open ? "rotate(180deg)" : "rotate(0)" }}
        >
          {"\u25BC"}
        </span>
      </button>
      {open && (
        <div className="px-4 py-3 border-t border-[var(--color-border)] bg-[var(--color-bg-secondary)]">
          {children}
        </div>
      )}
    </div>
  );
}

export function InvestigationDetail({ investigationId, result: providedResult }: Props) {
  const [result, setResult] = useState<InvestigationResult | null>(providedResult ?? null);
  const [loading, setLoading] = useState(!providedResult);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (providedResult) return;
    setLoading(true);
    invoke<InvestigationResult>("get_investigation_result", { investigationId })
      .then((r) => {
        setResult(r);
        setLoading(false);
      })
      .catch((e) => {
        setError(String(e));
        setLoading(false);
      });
  }, [investigationId, providedResult]);

  // Also try loading from the store if the engine doesn't have it
  useEffect(() => {
    if (result || loading || !error) return;
    invoke<InvestigationResult>("get_investigation", { investigationId })
      .then((r) => {
        setResult(r);
        setError(null);
      })
      .catch(() => {});
  }, [investigationId, result, loading, error]);

  if (loading) {
    return (
      <div className="py-8 text-center text-sm text-[var(--color-text-muted)]">
        Loading investigation...
      </div>
    );
  }

  if (error && !result) {
    return (
      <div className="py-8 text-center text-sm text-[var(--color-danger)]">
        {error}
      </div>
    );
  }

  if (!result) {
    return (
      <div className="py-8 text-center text-sm text-[var(--color-text-muted)]">
        Investigation not found.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h3 className="text-lg font-semibold text-[var(--color-text-primary)]">
            {result.target_summary}
          </h3>
          <div className="flex items-center gap-2 mt-1 flex-wrap">
            <VerdictBadge verdict={result.verdict} confidence={result.confidence} />
            <span className="text-xs text-[var(--color-text-muted)]">
              {result.target_type}
            </span>
          </div>
        </div>
      </div>

      {/* Narrative */}
      <div className="rounded-lg bg-[var(--color-bg-secondary)] border border-[var(--color-border)] p-4">
        <h4 className="text-xs font-semibold text-[var(--color-text-muted)] uppercase tracking-wide mb-2">
          Narrative
        </h4>
        <p className="text-sm text-[var(--color-text-primary)] whitespace-pre-wrap leading-relaxed">
          {result.narrative}
        </p>
      </div>

      {/* 5 Questions */}
      <div className="space-y-2">
        <AccordionSection title="What Happened" defaultOpen>
          <p className="text-sm text-[var(--color-text-primary)] whitespace-pre-wrap">
            {result.what_happened}
          </p>
        </AccordionSection>

        <AccordionSection title="Why It Happened">
          <p className="text-sm text-[var(--color-text-primary)] whitespace-pre-wrap">
            {result.why_it_happened}
          </p>
        </AccordionSection>

        {result.part_of_larger && (
          <AccordionSection title="Part of Something Larger">
            <p className="text-sm text-[var(--color-text-primary)] whitespace-pre-wrap">
              {result.part_of_larger}
            </p>
          </AccordionSection>
        )}

        <AccordionSection title="Impact Assessment">
          <div className="space-y-3">
            {result.impact.data_accessed.length > 0 && (
              <div>
                <span className="text-xs font-medium text-[var(--color-text-muted)]">Data Accessed:</span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {result.impact.data_accessed.map((d, i) => (
                    <span
                      key={i}
                      className="text-xs px-2 py-0.5 rounded bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)]"
                    >
                      {d}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {result.impact.data_modified.length > 0 && (
              <div>
                <span className="text-xs font-medium text-[var(--color-warning)]">Data Modified:</span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {result.impact.data_modified.map((d, i) => (
                    <span
                      key={i}
                      className="text-xs px-2 py-0.5 rounded bg-[var(--color-warning)]/10 text-[var(--color-warning)]"
                    >
                      {d}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {result.impact.data_exfiltrated && (
              <div className="flex items-center gap-2 text-sm text-[var(--color-danger)] font-medium">
                <span className="w-2 h-2 rounded-full bg-[var(--color-danger)]" />
                Data Exfiltration Detected
              </div>
            )}
            <div className="flex gap-4 text-xs text-[var(--color-text-secondary)]">
              <span>Blast Radius: <strong className="text-[var(--color-text-primary)]">{result.impact.blast_radius}</strong></span>
              <span>Severity: <strong className="text-[var(--color-text-primary)]">{result.impact.severity}</strong></span>
            </div>
          </div>
        </AccordionSection>

        <AccordionSection title="Recommendations">
          {result.recommendations.length === 0 ? (
            <p className="text-sm text-[var(--color-text-muted)]">No specific recommendations.</p>
          ) : (
            <ul className="list-disc list-inside space-y-1">
              {result.recommendations.map((r, i) => (
                <li key={i} className="text-sm text-[var(--color-text-primary)]">
                  {r}
                </li>
              ))}
            </ul>
          )}
        </AccordionSection>
      </div>

      {/* Timeline */}
      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4">
        <h4 className="text-xs font-semibold text-[var(--color-text-muted)] uppercase tracking-wide mb-3">
          Timeline
        </h4>
        <TimelineView investigationId={investigationId} />
      </div>

      {/* Cost footer */}
      <div className="flex items-center gap-6 text-xs text-[var(--color-text-muted)] pt-2 border-t border-[var(--color-border)]">
        <span>Tool calls: {result.total_tool_calls}</span>
        <span>Cost: ${result.estimated_cost_usd.toFixed(4)}</span>
        <span>Started: {new Date(result.started_at).toLocaleString()}</span>
        {result.completed_at && (
          <span>Completed: {new Date(result.completed_at).toLocaleString()}</span>
        )}
      </div>
    </div>
  );
}
