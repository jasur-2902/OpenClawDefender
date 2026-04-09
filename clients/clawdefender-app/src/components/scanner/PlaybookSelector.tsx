import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { PlaybookSummary } from "../../types";

interface Props {
  onStart: (playbookId: string) => void;
  disabled: boolean;
}

function formatDuration(secs: number): string {
  if (secs < 60) return `~${secs}s`;
  return `~${Math.ceil(secs / 60)} min`;
}

function formatCost(usd: number): string {
  if (usd < 0.01) return "<$0.01";
  return `~$${usd.toFixed(2)}`;
}

const QUICK_PLAYBOOKS = [
  { id: "mcp_security_audit", label: "Quick Scan", description: "Fast MCP configuration check" },
  { id: "full_audit", label: "Full Audit", description: "Comprehensive security assessment" },
];

export function PlaybookSelector({ onStart, disabled }: Props) {
  const [playbooks, setPlaybooks] = useState<PlaybookSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      try {
        const data = await invoke<PlaybookSummary[]>("get_scan_playbooks");
        setPlaybooks(data);
      } catch (e) {
        setError(String(e));
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  if (loading) {
    return (
      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-6">
        <div className="flex items-center gap-2 text-sm text-[var(--color-text-secondary)]">
          <span className="inline-block w-2 h-2 rounded-full bg-[var(--color-accent)] animate-pulse" />
          Loading playbooks...
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-lg border border-[var(--color-danger)] bg-[var(--color-danger)]/10 p-4 text-sm text-[var(--color-danger)]">
        Failed to load playbooks: {error}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Quick action buttons */}
      <div className="flex gap-3">
        {QUICK_PLAYBOOKS.map((qp) => {
          const pb = playbooks.find((p) => p.id === qp.id);
          return (
            <button
              key={qp.id}
              onClick={() => onStart(qp.id)}
              disabled={disabled}
              className="flex-1 rounded-lg border border-[var(--color-accent)] bg-[var(--color-accent)]/10 px-4 py-3 text-left transition-colors hover:bg-[var(--color-accent)]/20 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <div className="text-sm font-medium text-[var(--color-accent)]">{qp.label}</div>
              <div className="text-xs text-[var(--color-text-secondary)] mt-0.5">{qp.description}</div>
              {pb && (
                <div className="flex items-center gap-3 mt-2 text-xs text-[var(--color-text-secondary)]">
                  <span>{pb.stage_count} stages</span>
                  <span>{formatDuration(pb.estimated_duration_secs)}</span>
                  <span>{formatCost(pb.estimated_cost_usd)}</span>
                </div>
              )}
            </button>
          );
        })}
      </div>

      {/* All playbooks grid */}
      {playbooks.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-sm font-medium text-[var(--color-text-secondary)]">All Playbooks</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {playbooks.map((pb) => (
              <button
                key={pb.id}
                onClick={() => onStart(pb.id)}
                disabled={disabled}
                className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4 text-left transition-colors hover:border-[var(--color-accent)] hover:bg-[var(--color-bg-tertiary)] disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <div className="text-sm font-medium text-[var(--color-text-primary)]">{pb.name}</div>
                <div className="text-xs text-[var(--color-text-secondary)] mt-1 line-clamp-2">
                  {pb.description}
                </div>
                <div className="flex items-center gap-3 mt-3 text-xs text-[var(--color-text-secondary)]">
                  <span className="px-1.5 py-0.5 rounded bg-[var(--color-bg-tertiary)]">
                    {pb.stage_count} stages
                  </span>
                  <span>{formatDuration(pb.estimated_duration_secs)}</span>
                  <span>{formatCost(pb.estimated_cost_usd)}</span>
                </div>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
