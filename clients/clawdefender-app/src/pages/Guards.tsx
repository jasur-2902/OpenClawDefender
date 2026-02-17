import { useEffect, useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { GuardSummary } from "../types";

export function Guards() {
  const [guards, setGuards] = useState<GuardSummary[]>([]);
  const [error, setError] = useState<string | null>(null);

  const loadGuards = useCallback(async () => {
    try {
      const data = await invoke<GuardSummary[]>("list_guards");
      setGuards(data);
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    loadGuards();
    const interval = setInterval(loadGuards, 5000);
    return () => clearInterval(interval);
  }, [loadGuards]);

  function formatTime(ts: string | null): string {
    if (!ts) return "Never";
    try {
      return new Date(ts).toLocaleString();
    } catch {
      return ts;
    }
  }

  function typeBadgeColor(guardType: string): string {
    switch (guardType.toLowerCase()) {
      case "input":
        return "bg-[var(--color-accent)]/20 text-[var(--color-accent)]";
      case "output":
        return "bg-[var(--color-warning)]/20 text-[var(--color-warning)]";
      case "network":
        return "bg-purple-500/20 text-purple-400";
      case "filesystem":
        return "bg-[var(--color-success)]/20 text-[var(--color-success)]";
      default:
        return "bg-[var(--color-border)]/40 text-[var(--color-text-secondary)]";
    }
  }

  if (error) {
    return (
      <div className="p-6 space-y-6">
        <h1 className="text-2xl font-bold">Guards</h1>
        <div className="rounded-lg border border-[var(--color-danger)] bg-[var(--color-danger)]/10 p-4 text-sm text-[var(--color-danger)]">
          {error}
        </div>
      </div>
    );
  }

  if (guards.length === 0) {
    return (
      <div className="p-6 space-y-6">
        <h1 className="text-2xl font-bold">Guards</h1>
        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-8 text-center">
          <div className="text-4xl mb-4 text-[var(--color-text-secondary)]">{"\u2261"}</div>
          <h2 className="text-lg font-semibold mb-2">No Active Guards</h2>
          <p className="text-[var(--color-text-secondary)] text-sm max-w-md mx-auto mb-4">
            No agents are currently using self-protection. Guards are automatically
            created when MCP servers register protection rules.
          </p>
          <div className="text-left max-w-sm mx-auto space-y-2 text-sm text-[var(--color-text-secondary)]">
            <p className="font-medium text-[var(--color-text-primary)]">To get started:</p>
            <p>1. Ensure the ClawDefender daemon is running</p>
            <p>2. Connect MCP servers through your client</p>
            <p>3. Guards will appear as servers register protection rules</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Guards</h1>
        <span className="text-sm text-[var(--color-text-secondary)]">
          {guards.filter((g) => g.enabled).length} of {guards.length} active
        </span>
      </div>

      <div className="grid gap-4">
        {guards.map((guard) => (
          <div
            key={guard.name}
            className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4"
          >
            <div className="flex items-start justify-between">
              <div className="space-y-2">
                <div className="flex items-center gap-3">
                  <span className="font-medium text-base">{guard.name}</span>
                  <span
                    className={`px-2 py-0.5 rounded-full text-xs font-medium ${typeBadgeColor(
                      guard.guard_type
                    )}`}
                  >
                    {guard.guard_type}
                  </span>
                </div>
                <p className="text-sm text-[var(--color-text-secondary)]">
                  {guard.description}
                </p>
              </div>
              <button
                onClick={() => {
                  setGuards((prev) =>
                    prev.map((g) =>
                      g.name === guard.name ? { ...g, enabled: !g.enabled } : g
                    )
                  );
                }}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors flex-shrink-0 ${
                  guard.enabled
                    ? "bg-[var(--color-accent)]"
                    : "bg-[var(--color-border)]"
                }`}
              >
                <span
                  className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                    guard.enabled ? "translate-x-6" : "translate-x-1"
                  }`}
                />
              </button>
            </div>
            <div className="flex gap-6 mt-3 text-sm text-[var(--color-text-secondary)]">
              <span>
                Triggers: <span className="font-medium text-[var(--color-text-primary)]">{guard.triggers_count}</span>
              </span>
              <span>Last triggered: {formatTime(guard.last_triggered)}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
