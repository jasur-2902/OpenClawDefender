import { useState, useEffect, useCallback, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { PageHeader } from "../components/PageHeader";
import { InvestigationDetail } from "../components/investigation/InvestigationDetail";
import { LiveInvestigationView } from "../components/investigation/LiveInvestigationView";
import type {
  InvestigationIndexEntry,
  InvestigationProgress,
  HuntProgress,
  HuntResult,
} from "../types";

// ---------------------------------------------------------------------------
// Verdict badge
// ---------------------------------------------------------------------------

const VERDICT_COLORS: Record<string, { color: string; bg: string }> = {
  FalsePositive: { color: "var(--color-text-secondary)", bg: "var(--color-bg-tertiary)" },
  Benign: { color: "var(--color-success)", bg: "color-mix(in srgb, var(--color-success) 15%, transparent)" },
  Suspicious: { color: "var(--color-warning)", bg: "color-mix(in srgb, var(--color-warning) 15%, transparent)" },
  ConfirmedThreat: { color: "var(--color-danger)", bg: "color-mix(in srgb, var(--color-danger) 15%, transparent)" },
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "var(--color-danger)",
  high: "#f97316",
  medium: "#eab308",
  low: "var(--color-accent)",
  info: "var(--color-text-secondary)",
};

function VerdictBadge({ verdict }: { verdict: string }) {
  const style = VERDICT_COLORS[verdict] || VERDICT_COLORS.Suspicious;
  return (
    <span
      className="text-[10px] font-semibold px-2 py-0.5 rounded-full uppercase tracking-wide"
      style={{ color: style.color, backgroundColor: style.bg }}
    >
      {verdict.replace(/([a-z])([A-Z])/g, "$1 $2")}
    </span>
  );
}

function SeverityDot({ severity }: { severity: string }) {
  const color = SEVERITY_COLORS[severity] || SEVERITY_COLORS.info;
  return (
    <span
      className="inline-block w-2 h-2 rounded-full shrink-0"
      style={{ backgroundColor: color }}
      aria-label={severity}
    />
  );
}

// ---------------------------------------------------------------------------
// Hunt Card
// ---------------------------------------------------------------------------

function HuntProgressCard({ huntId }: { huntId: string }) {
  const [progress, setProgress] = useState<HuntProgress | null>(null);
  const [result, setResult] = useState<HuntResult | null>(null);
  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    const interval = setInterval(async () => {
      try {
        const p = await invoke<HuntProgress>("get_hunt_progress", { huntId });
        setProgress(p);
        if (p.status === "Complete" || p.status === "Failed") {
          clearInterval(interval);
          try {
            const r = await invoke<HuntResult>("get_hunt_results", { huntId });
            setResult(r);
          } catch {
            // ok
          }
        }
      } catch {
        clearInterval(interval);
      }
    }, 2000);
    return () => clearInterval(interval);
  }, [huntId]);

  const isComplete = progress?.status === "Complete" || progress?.status === "Failed";

  return (
    <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4 space-y-2">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {!isComplete && (
            <span className="inline-block w-2 h-2 rounded-full bg-[var(--color-accent)] animate-pulse" />
          )}
          <span className="text-sm font-medium text-[var(--color-text-primary)]">
            Threat Hunt {isComplete ? "Complete" : "Running"}
          </span>
        </div>
        <span className="text-xs text-[var(--color-text-muted)]">
          {progress?.hunt_type ?? "general"}
        </span>
      </div>

      {progress && !isComplete && (
        <div className="flex gap-4 text-xs text-[var(--color-text-secondary)]">
          <span>Patterns: {progress.patterns_checked.length}</span>
          <span>Findings: {progress.findings_count}</span>
          <span>Tool calls: {progress.tool_calls_count}</span>
          <span>{progress.elapsed_secs}s</span>
        </div>
      )}

      {result && (
        <div>
          <button
            onClick={() => setExpanded(!expanded)}
            className="text-xs text-[var(--color-accent)] hover:underline"
          >
            {expanded ? "Hide results" : `View results (${result.findings.length} findings)`}
          </button>
          {expanded && (
            <div className="mt-2 space-y-2">
              <p className="text-sm text-[var(--color-text-secondary)]">{result.summary}</p>
              {result.findings.map((f) => (
                <div
                  key={f.id}
                  className="rounded border border-[var(--color-border)] bg-[var(--color-bg-tertiary)] p-3 text-xs space-y-1"
                >
                  <div className="flex items-center gap-2">
                    <SeverityDot severity={f.severity} />
                    <span className="font-medium text-[var(--color-text-primary)]">{f.pattern_name}</span>
                    <span className="text-[var(--color-text-muted)] ml-auto">
                      {(f.confidence * 100).toFixed(0)}%
                    </span>
                  </div>
                  <p className="text-[var(--color-text-secondary)]">{f.description}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Investigation Card
// ---------------------------------------------------------------------------

function InvestigationCard({
  entry,
  onPin,
  onDelete,
  onSelect,
  selected,
}: {
  entry: InvestigationIndexEntry;
  onPin: (id: string, pinned: boolean) => void;
  onDelete: (id: string) => void;
  onSelect: (id: string) => void;
  selected: boolean;
}) {
  return (
    <div
      className={`rounded-lg border bg-[var(--color-bg-secondary)] p-4 space-y-2 transition-colors cursor-pointer investigation-card ${
        selected
          ? "border-[var(--color-accent)]"
          : "border-[var(--color-border)] hover:border-[var(--color-accent-subtle)]"
      }`}
      onClick={() => onSelect(entry.id)}
    >
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 flex-wrap min-w-0">
          <SeverityDot severity={entry.severity} />
          <VerdictBadge verdict={entry.verdict} />
          <span className="text-sm font-medium text-[var(--color-text-primary)] truncate">
            {entry.target_summary}
          </span>
        </div>
        <div className="flex items-center gap-1 shrink-0">
          <button
            onClick={(e) => {
              e.stopPropagation();
              onPin(entry.id, !entry.pinned);
            }}
            className={`px-1.5 py-0.5 rounded text-xs transition-colors ${
              entry.pinned
                ? "text-[var(--color-accent)]"
                : "text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)]"
            }`}
            aria-label={entry.pinned ? "Unpin" : "Pin"}
          >
            {entry.pinned ? "\u{2605}" : "\u{2606}"}
          </button>
          <button
            onClick={(e) => {
              e.stopPropagation();
              onDelete(entry.id);
            }}
            className="px-1.5 py-0.5 rounded text-xs text-[var(--color-text-muted)] hover:text-[var(--color-danger)] transition-colors"
            aria-label="Delete"
          >
            {"\u{2715}"}
          </button>
        </div>
      </div>

      <div className="flex items-center gap-3 text-xs text-[var(--color-text-secondary)]">
        <span>{new Date(entry.started_at).toLocaleDateString()}</span>
        <span>{(entry.confidence * 100).toFixed(0)}% confidence</span>
        {entry.servers_involved.length > 0 && (
          <span>{entry.servers_involved.join(", ")}</span>
        )}
      </div>

      <p className="text-xs text-[var(--color-text-muted)] line-clamp-2">
        {entry.narrative_preview}
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------

export function Investigations() {
  const [entries, setEntries] = useState<InvestigationIndexEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchText, setSearchText] = useState("");
  const [verdictFilter, setVerdictFilter] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Active investigation tracking
  const [activeInvestigationId, setActiveInvestigationId] = useState<string | null>(null);

  // Hunt tracking
  const [activeHuntId, setActiveHuntId] = useState<string | null>(null);
  const [startingHunt, setStartingHunt] = useState(false);

  const fetchList = useCallback(async () => {
    try {
      const filter = verdictFilter ? { verdict: verdictFilter } : undefined;
      const list = await invoke<InvestigationIndexEntry[]>("list_investigations", {
        filter: filter ? JSON.parse(JSON.stringify(filter)) : null,
      });
      setEntries(list);
    } catch {
      setEntries([]);
    }
    setLoading(false);
  }, [verdictFilter]);

  useEffect(() => {
    fetchList();
  }, [fetchList]);

  const filtered = useMemo(() => {
    if (!searchText) return entries;
    const lower = searchText.toLowerCase();
    return entries.filter(
      (e) =>
        e.target_summary.toLowerCase().includes(lower) ||
        e.narrative_preview.toLowerCase().includes(lower) ||
        e.verdict.toLowerCase().includes(lower) ||
        e.servers_involved.some((s) => s.toLowerCase().includes(lower))
    );
  }, [entries, searchText]);

  // Sort: pinned first, then by date
  const sorted = useMemo(() => {
    return [...filtered].sort((a, b) => {
      if (a.pinned && !b.pinned) return -1;
      if (!a.pinned && b.pinned) return 1;
      return new Date(b.started_at).getTime() - new Date(a.started_at).getTime();
    });
  }, [filtered]);

  async function handlePin(id: string, pinned: boolean) {
    try {
      await invoke("pin_investigation", { investigationId: id, pinned });
      setEntries((prev) =>
        prev.map((e) => (e.id === id ? { ...e, pinned } : e))
      );
    } catch {
      // ok
    }
  }

  async function handleDelete(id: string) {
    try {
      await invoke("delete_investigation", { investigationId: id });
      setEntries((prev) => prev.filter((e) => e.id !== id));
      if (selectedId === id) setSelectedId(null);
    } catch {
      // ok
    }
  }

  async function startThreatHunt() {
    setStartingHunt(true);
    setError(null);
    try {
      const result = await invoke<{ hunt_id: string }>("start_threat_hunt", {
        huntType: "general",
      });
      setActiveHuntId(result.hunt_id);
    } catch (e) {
      setError(String(e));
    } finally {
      setStartingHunt(false);
    }
  }

  return (
    <div className="p-6 space-y-6 max-w-6xl">
      <PageHeader
        title="Investigations"
        subtitle="AI-powered security investigations and threat hunts"
        actions={
          <button
            onClick={startThreatHunt}
            disabled={startingHunt || !!activeHuntId}
            className="px-4 py-2 rounded-lg bg-[var(--color-accent)] text-white text-sm font-medium hover:bg-[var(--color-accent-hover)] disabled:opacity-50 transition-colors"
          >
            {startingHunt ? "Starting..." : "Start Threat Hunt"}
          </button>
        }
      />

      {error && (
        <div className="rounded-lg border border-[var(--color-danger)] bg-[var(--color-danger)]/10 p-3 text-sm text-[var(--color-danger)]">
          {error}
        </div>
      )}

      {/* Active investigation */}
      {activeInvestigationId && (
        <section aria-label="Active investigation">
          <h2 className="text-xs font-semibold text-[var(--color-text-muted)] uppercase tracking-wide mb-3">
            Active Investigation
          </h2>
          <LiveInvestigationView
            investigationId={activeInvestigationId}
            onComplete={() => {
              setActiveInvestigationId(null);
              fetchList();
            }}
            onCancel={() => setActiveInvestigationId(null)}
          />
        </section>
      )}

      {/* Active hunt */}
      {activeHuntId && (
        <section aria-label="Active threat hunt">
          <h2 className="text-xs font-semibold text-[var(--color-text-muted)] uppercase tracking-wide mb-3">
            Active Threat Hunt
          </h2>
          <HuntProgressCard huntId={activeHuntId} />
        </section>
      )}

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <input
          type="text"
          value={searchText}
          onChange={(e) => setSearchText(e.target.value)}
          placeholder="Search investigations..."
          className="flex-1 min-w-[200px] px-3 py-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] text-sm text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] focus:outline-none focus:border-[var(--color-accent)]"
        />
        <select
          value={verdictFilter}
          onChange={(e) => setVerdictFilter(e.target.value)}
          className="px-3 py-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] text-sm text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
        >
          <option value="">All Verdicts</option>
          <option value="FalsePositive">False Positive</option>
          <option value="Benign">Benign</option>
          <option value="Suspicious">Suspicious</option>
          <option value="ConfirmedThreat">Confirmed Threat</option>
        </select>
      </div>

      {/* Investigation list */}
      {loading ? (
        <div className="space-y-2">
          {[1, 2, 3].map((i) => (
            <div
              key={i}
              className="h-24 rounded-lg bg-[var(--color-bg-secondary)] border border-[var(--color-border)] animate-pulse"
            />
          ))}
        </div>
      ) : sorted.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-center">
          <div className="w-12 h-12 rounded-full bg-[var(--color-bg-tertiary)] flex items-center justify-center mb-4">
            <span className="text-lg text-[var(--color-text-secondary)]">{"\u{1F50D}"}</span>
          </div>
          <p className="text-sm font-medium text-[var(--color-text-primary)] mb-1">
            No investigations yet
          </p>
          <p className="text-sm text-[var(--color-text-secondary)] max-w-sm">
            Click "Investigate" on any event or alert, or start a Threat Hunt to begin.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Left: list */}
          <div className="space-y-2">
            {sorted.map((entry) => (
              <InvestigationCard
                key={entry.id}
                entry={entry}
                onPin={handlePin}
                onDelete={handleDelete}
                onSelect={setSelectedId}
                selected={selectedId === entry.id}
              />
            ))}
          </div>

          {/* Right: detail */}
          <div>
            {selectedId ? (
              <div className="sticky top-6">
                <InvestigationDetail investigationId={selectedId} />
              </div>
            ) : (
              <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-8 text-center">
                <p className="text-sm text-[var(--color-text-muted)]">
                  Select an investigation to view details
                </p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
