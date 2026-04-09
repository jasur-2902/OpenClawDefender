import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { InvestigationTimeline, TimelineEntry } from "../../types";

interface Props {
  investigationId: string;
}

const ENTRY_TYPE_ICONS: Record<string, string> = {
  McpToolCall: "\u{1F5A5}",
  FileAccess: "\u{1F4C4}",
  NetworkConnection: "\u{1F310}",
  ProcessExecution: "\u{2699}",
  PolicyDecision: "\u{1F6E1}",
  UserAction: "\u{1F464}",
  AiAssessment: "\u{1F9E0}",
  InvestigatorNote: "\u{1F50D}",
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "var(--color-danger)",
  high: "#f97316",
  medium: "#eab308",
  low: "var(--color-accent)",
  info: "var(--color-text-secondary)",
};

function getEntryIcon(entryType: string): string {
  return ENTRY_TYPE_ICONS[entryType] || "\u{1F50D}";
}

function getSeverityColor(severity: string): string {
  return SEVERITY_COLORS[severity] || SEVERITY_COLORS.info;
}

function formatTime(iso: string): string {
  try {
    return new Date(iso).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return iso;
  }
}

function TimelineNode({ entry }: { entry: TimelineEntry }) {
  const color = getSeverityColor(entry.severity);
  const isKey = entry.is_key_moment;

  return (
    <div className="flex gap-3 relative">
      {/* Timestamp */}
      <div className="w-20 shrink-0 text-right">
        <span className="text-xs font-mono text-[var(--color-text-secondary)]">
          {formatTime(entry.timestamp)}
        </span>
      </div>

      {/* Dot + connector line */}
      <div className="flex flex-col items-center shrink-0">
        <div
          className={`rounded-full flex items-center justify-center shrink-0 ${
            isKey ? "w-6 h-6" : "w-4 h-4"
          }`}
          style={{
            backgroundColor: isKey
              ? `color-mix(in srgb, ${color} 25%, transparent)`
              : "var(--color-bg-tertiary)",
            border: `2px solid ${color}`,
          }}
        >
          {isKey && (
            <span className="text-[10px]">{getEntryIcon(entry.entry_type)}</span>
          )}
        </div>
        <div className="timeline-connector-line flex-1 w-px bg-[var(--color-border)]" />
      </div>

      {/* Content */}
      <div
        className={`flex-1 pb-4 ${isKey ? "pb-5" : ""}`}
      >
        <div
          className={`rounded-lg px-3 py-2 ${
            isKey
              ? "bg-[var(--color-bg-secondary)] border border-[var(--color-border)]"
              : ""
          }`}
        >
          <div className="flex items-center gap-2 flex-wrap">
            {!isKey && (
              <span className="text-xs">{getEntryIcon(entry.entry_type)}</span>
            )}
            <span
              className={`text-sm ${
                isKey
                  ? "font-semibold text-[var(--color-text-primary)]"
                  : "text-[var(--color-text-secondary)]"
              }`}
            >
              {entry.description}
            </span>
          </div>
          <div className="flex items-center gap-2 mt-1 flex-wrap">
            {entry.server && (
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--color-bg-tertiary)] text-[var(--color-text-muted)]">
                {entry.server}
              </span>
            )}
            {entry.stage && (
              <span
                className="text-[10px] px-1.5 py-0.5 rounded font-medium"
                style={{
                  color,
                  backgroundColor: `color-mix(in srgb, ${color} 15%, transparent)`,
                }}
              >
                {entry.stage}
              </span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export function TimelineView({ investigationId }: Props) {
  const [timeline, setTimeline] = useState<InvestigationTimeline | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    invoke<InvestigationTimeline>("get_investigation_timeline", {
      investigationId,
    })
      .then((t) => {
        setTimeline(t);
        setLoading(false);
      })
      .catch((e) => {
        setError(String(e));
        setLoading(false);
      });
  }, [investigationId]);

  if (loading) {
    return (
      <div className="py-4 text-sm text-[var(--color-text-muted)] text-center">
        Loading timeline...
      </div>
    );
  }

  if (error) {
    return (
      <div className="py-4 text-sm text-[var(--color-danger)] text-center">
        {error}
      </div>
    );
  }

  if (!timeline || timeline.entries.length === 0) {
    return (
      <div className="py-4 text-sm text-[var(--color-text-muted)] text-center">
        No timeline entries available.
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {/* Narrative summary */}
      {timeline.narrative_summary && (
        <div className="rounded-lg bg-[var(--color-bg-tertiary)] px-4 py-3 text-sm text-[var(--color-text-secondary)] mb-4">
          {timeline.narrative_summary}
        </div>
      )}

      {/* Servers involved */}
      {timeline.servers_involved.length > 0 && (
        <div className="flex items-center gap-2 mb-3 flex-wrap">
          <span className="text-xs text-[var(--color-text-muted)]">Servers:</span>
          {timeline.servers_involved.map((s) => (
            <span
              key={s}
              className="text-xs px-2 py-0.5 rounded-full bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)]"
            >
              {s}
            </span>
          ))}
        </div>
      )}

      {/* Timeline entries */}
      <div className="relative">
        {timeline.entries.map((entry) => (
          <TimelineNode key={entry.id} entry={entry} />
        ))}
      </div>
    </div>
  );
}
