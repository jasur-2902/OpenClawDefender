import { useEffect, useState } from "react";
import { useToolStore } from "../../stores/toolStore";
import type { ServerSummary } from "../../types";

interface BehavioralProfileProps {
  serverName: string;
  behavioralStatus: string;
  learningProgress: number;
}

export function BehavioralProfile({
  serverName,
  behavioralStatus,
  learningProgress,
}: BehavioralProfileProps) {
  const getServerSummary = useToolStore((s) => s.getServerSummary);
  const [summary, setSummary] = useState<ServerSummary | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    getServerSummary(serverName).then((s) => {
      if (!cancelled) {
        setSummary(s);
        setLoading(false);
      }
    });
    return () => { cancelled = true; };
  }, [serverName, getServerSummary]);

  if (loading) {
    return (
      <div className="space-y-3">
        <div className="h-4 w-48 rounded bg-[var(--color-bg-tertiary)] animate-pulse" />
        <div className="h-20 rounded bg-[var(--color-bg-tertiary)] animate-pulse" />
      </div>
    );
  }

  // Learning state
  if (behavioralStatus === "learning") {
    const pct = Math.round(learningProgress * 100);
    const eventsNeeded = summary?.learning_status?.events_needed ?? 0;
    return (
      <div className="rounded-lg border border-[var(--color-info-border)] bg-[var(--color-info-light)] p-4">
        <div className="flex items-center gap-2 mb-2">
          <span aria-hidden="true"><BrainIcon /></span>
          <span className="text-sm font-medium text-[var(--color-text-primary)]">
            Still getting to know this tool
          </span>
        </div>
        <div
          className="w-full h-1.5 rounded-full bg-[var(--color-bg-tertiary)] mb-2"
          role="progressbar"
          aria-valuenow={pct}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label={`Learning progress: ${pct}%`}
        >
          <div
            className="h-full rounded-full bg-[var(--color-info)] transition-[width] duration-300 ease-out"
            style={{ width: `${pct}%` }}
          />
        </div>
        <p className="text-xs text-[var(--color-text-muted)]">
          {pct}% complete{eventsNeeded > 0 ? ` — ${eventsNeeded} more events needed` : ""}
        </p>
      </div>
    );
  }

  // No summary available
  if (!summary) {
    return (
      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4 text-center">
        <p className="text-sm text-[var(--color-text-muted)]">
          Behavioral profile not available yet
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Territory */}
      {summary.territory.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold text-[var(--color-text-muted)] uppercase tracking-wide mb-2">
            Territory
          </h4>
          <div className="space-y-1">
            {summary.territory.slice(0, 3).map((t) => (
              <div
                key={t.path}
                className="flex items-center justify-between text-xs p-2 rounded bg-[var(--color-bg-secondary)]"
              >
                <span className="font-mono text-[var(--color-text-primary)] truncate flex-1">
                  {t.path}
                </span>
                <span className="text-[var(--color-text-muted)] ml-2 shrink-0">
                  {t.percentage}% ({t.access_count} accesses)
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Common tools */}
      {summary.common_tools.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold text-[var(--color-text-muted)] uppercase tracking-wide mb-2">
            Most Used Tools
          </h4>
          <div className="space-y-1">
            {summary.common_tools.slice(0, 5).map((t) => (
              <div
                key={t.tool_name}
                className="flex items-center justify-between text-xs p-2 rounded bg-[var(--color-bg-secondary)]"
              >
                <span className="text-[var(--color-text-primary)]">
                  {t.tool_name}
                </span>
                <div className="flex items-center gap-2">
                  <div className="w-16 h-1 rounded-full bg-[var(--color-bg-tertiary)]">
                    <div
                      className="h-full rounded-full bg-[var(--color-accent)]"
                      style={{ width: `${t.percentage}%` }}
                    />
                  </div>
                  <span className="text-[var(--color-text-muted)] w-8 text-right">
                    {t.percentage}%
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Network summary */}
      {summary.network_summary && (
        <div>
          <h4 className="text-xs font-semibold text-[var(--color-text-muted)] uppercase tracking-wide mb-2">
            Network
          </h4>
          <div className="text-xs p-2 rounded bg-[var(--color-bg-secondary)]">
            {summary.network_summary.type === "none" ? (
              <span className="text-[var(--color-text-muted)]">
                No network activity observed
              </span>
            ) : (
              <div>
                {summary.network_summary.hosts && (
                  <p className="text-[var(--color-text-primary)]">
                    Connects to: {summary.network_summary.hosts.slice(0, 3).join(", ")}
                    {(summary.network_summary.hosts.length ?? 0) > 3 && " ..."}
                  </p>
                )}
                {summary.network_summary.total_connections != null && (
                  <p className="text-[var(--color-text-muted)] mt-1">
                    {summary.network_summary.total_connections} total connections
                  </p>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Activity pattern */}
      {summary.activity_pattern && (
        <div>
          <h4 className="text-xs font-semibold text-[var(--color-text-muted)] uppercase tracking-wide mb-2">
            Activity Pattern
          </h4>
          <div className="text-xs p-2 rounded bg-[var(--color-bg-secondary)] text-[var(--color-text-secondary)]">
            ~{summary.activity_pattern.avg_actions_per_hour} actions/hour on average
            {summary.activity_pattern.peak_period && (
              <span> · Peak: {summary.activity_pattern.peak_period}</span>
            )}
          </div>
        </div>
      )}

      {/* Notable observations */}
      {summary.notable_observations.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold text-[var(--color-text-muted)] uppercase tracking-wide mb-2">
            Notable
          </h4>
          <div className="space-y-1">
            {summary.notable_observations.map((obs, i) => (
              <p key={i} className="text-xs text-[var(--color-text-secondary)] p-2 rounded bg-[var(--color-bg-secondary)]">
                {obs}
              </p>
            ))}
          </div>
        </div>
      )}

      {/* Trust recommendation */}
      {summary.trust_recommendation && (
        <div className="rounded-lg border border-[var(--color-info-border)] bg-[var(--color-info-light)] p-3">
          <p className="text-xs text-[var(--color-info)]">
            {summary.trust_recommendation}
          </p>
        </div>
      )}
    </div>
  );
}

function BrainIcon() {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke="var(--color-info)"
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12 5a3 3 0 1 0-5.997.125 4 4 0 0 0-2.526 5.77 4 4 0 0 0 .556 6.588A4 4 0 1 0 12 18Z" />
      <path d="M12 5a3 3 0 1 1 5.997.125 4 4 0 0 1 2.526 5.77 4 4 0 0 1-.556 6.588A4 4 0 1 1 12 18Z" />
      <path d="M15 13a4.5 4.5 0 0 1-3-4 4.5 4.5 0 0 1-3 4" />
      <path d="M12 18v-5" />
    </svg>
  );
}
