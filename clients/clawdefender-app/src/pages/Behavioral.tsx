import { useEffect, useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { BehavioralStatus, ServerProfileSummary } from "../types";

export function Behavioral() {
  const [status, setStatus] = useState<BehavioralStatus | null>(null);
  const [profiles, setProfiles] = useState<ServerProfileSummary[]>([]);
  const [expandedServer, setExpandedServer] = useState<string | null>(null);
  const [autoBlockEnabled, setAutoBlockEnabled] = useState(false);
  const [threshold, setThreshold] = useState(0.7);
  const [error, setError] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    try {
      const [s, p] = await Promise.all([
        invoke<BehavioralStatus>("get_behavioral_status"),
        invoke<ServerProfileSummary[]>("get_profiles"),
      ]);
      setStatus(s);
      setProfiles(p);
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, [loadData]);

  function statusColor(s: ServerProfileSummary["status"]): string {
    switch (s) {
      case "learning":
        return "bg-[var(--color-accent)]";
      case "anomalous":
        return "bg-[var(--color-danger)]";
      default:
        return "bg-[var(--color-success)]";
    }
  }

  function anomalyColor(score: number): string {
    if (score >= 0.7) return "text-[var(--color-danger)]";
    if (score >= 0.3) return "text-[var(--color-warning)]";
    return "text-[var(--color-success)]";
  }

  function anomalyBg(score: number): string {
    if (score >= 0.7) return "bg-[var(--color-danger)]";
    if (score >= 0.3) return "bg-[var(--color-warning)]";
    return "bg-[var(--color-success)]";
  }

  function formatTime(ts: string): string {
    try {
      return new Date(ts).toLocaleString();
    } catch {
      return ts;
    }
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-bold">Behavioral Analysis</h1>
          {status && (
            <span
              className={`px-2.5 py-0.5 rounded-full text-xs font-medium ${
                status.enabled
                  ? "bg-[var(--color-success)]/20 text-[var(--color-success)]"
                  : "bg-[var(--color-danger)]/20 text-[var(--color-danger)]"
              }`}
            >
              {status.enabled ? "Enabled" : "Disabled"}
            </span>
          )}
        </div>
      </div>

      {status && (
        <div className="grid grid-cols-4 gap-4">
          {[
            { label: "Profiles", value: status.profiles_count },
            { label: "Total Anomalies", value: status.total_anomalies },
            { label: "Learning", value: status.learning_servers },
            { label: "Monitoring", value: status.monitoring_servers },
          ].map((stat) => (
            <div
              key={stat.label}
              className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4"
            >
              <p className="text-xs text-[var(--color-text-secondary)]">{stat.label}</p>
              <p className="text-xl font-bold mt-1">{stat.value}</p>
            </div>
          ))}
        </div>
      )}

      {error && (
        <div className="rounded-lg border border-[var(--color-danger)] bg-[var(--color-danger)]/10 p-4 text-sm text-[var(--color-danger)]">
          {error}
        </div>
      )}

      <div className="space-y-3">
        <h2 className="text-lg font-semibold">Server Profiles</h2>
        {profiles.length === 0 && !error && (
          <p className="text-[var(--color-text-secondary)] text-sm">
            No server profiles available yet. Profiles are created as servers are monitored.
          </p>
        )}
        {profiles.map((profile) => (
          <div
            key={profile.server_name}
            className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] overflow-hidden"
          >
            <button
              onClick={() =>
                setExpandedServer(
                  expandedServer === profile.server_name ? null : profile.server_name
                )
              }
              className="w-full px-4 py-3 flex items-center justify-between hover:bg-[var(--color-bg-tertiary)] transition-colors"
            >
              <div className="flex items-center gap-4">
                <span className="font-medium">{profile.server_name}</span>
                <span
                  className={`px-2 py-0.5 rounded-full text-xs font-medium text-white ${statusColor(
                    profile.status
                  )}`}
                >
                  {profile.status.charAt(0).toUpperCase() + profile.status.slice(1)}
                </span>
              </div>
              <div className="flex items-center gap-6 text-sm">
                <span className="text-[var(--color-text-secondary)]">
                  {profile.tools_count} tools
                </span>
                <span className="text-[var(--color-text-secondary)]">
                  {profile.total_calls} calls
                </span>
                <div className="flex items-center gap-2">
                  <span className={`font-medium ${anomalyColor(profile.anomaly_score)}`}>
                    {profile.anomaly_score.toFixed(2)}
                  </span>
                  <span
                    className={`inline-block w-2 h-2 rounded-full ${anomalyBg(
                      profile.anomaly_score
                    )}`}
                  />
                </div>
                <span className="text-[var(--color-text-secondary)] text-xs">
                  {formatTime(profile.last_activity)}
                </span>
                <span className="text-[var(--color-text-secondary)]">
                  {expandedServer === profile.server_name ? "\u25B2" : "\u25BC"}
                </span>
              </div>
            </button>

            {expandedServer === profile.server_name && (
              <div className="px-4 py-4 border-t border-[var(--color-border)] bg-[var(--color-bg-primary)] space-y-4">
                <div className="grid grid-cols-3 gap-4">
                  <div>
                    <h4 className="text-xs font-medium text-[var(--color-text-secondary)] mb-2 uppercase tracking-wide">
                      Tool Frequency
                    </h4>
                    <p className="text-sm text-[var(--color-text-secondary)]">
                      {profile.tools_count} tools registered, {profile.total_calls} total invocations
                    </p>
                  </div>
                  <div>
                    <h4 className="text-xs font-medium text-[var(--color-text-secondary)] mb-2 uppercase tracking-wide">
                      File Territory
                    </h4>
                    <p className="text-sm text-[var(--color-text-secondary)]">
                      Monitoring file access patterns
                    </p>
                  </div>
                  <div>
                    <h4 className="text-xs font-medium text-[var(--color-text-secondary)] mb-2 uppercase tracking-wide">
                      Network Status
                    </h4>
                    <p className="text-sm text-[var(--color-text-secondary)]">
                      Tracking network connection patterns
                    </p>
                  </div>
                </div>
                <div>
                  <h4 className="text-xs font-medium text-[var(--color-text-secondary)] mb-2 uppercase tracking-wide">
                    Anomaly History
                  </h4>
                  <p className="text-sm text-[var(--color-text-secondary)]">
                    Anomaly history will appear here as events are recorded.
                  </p>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>

      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4 space-y-4">
        <h2 className="text-lg font-semibold">Auto-Block Control</h2>
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium">Auto-block anomalous servers</p>
            <p className="text-xs text-[var(--color-text-secondary)]">
              Automatically block servers that exceed the anomaly threshold
            </p>
          </div>
          <button
            onClick={() => setAutoBlockEnabled(!autoBlockEnabled)}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
              autoBlockEnabled ? "bg-[var(--color-accent)]" : "bg-[var(--color-border)]"
            }`}
          >
            <span
              className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                autoBlockEnabled ? "translate-x-6" : "translate-x-1"
              }`}
            />
          </button>
        </div>
        <div>
          <div className="flex items-center justify-between mb-1">
            <label className="text-sm text-[var(--color-text-secondary)]">
              Anomaly Threshold
            </label>
            <span className="text-sm font-medium">{threshold.toFixed(2)}</span>
          </div>
          <input
            type="range"
            min="0.1"
            max="1.0"
            step="0.05"
            value={threshold}
            onChange={(e) => setThreshold(parseFloat(e.target.value))}
            className="w-full accent-[var(--color-accent)]"
          />
          <div className="flex justify-between text-xs text-[var(--color-text-secondary)] mt-1">
            <span>Sensitive (0.1)</span>
            <span>Permissive (1.0)</span>
          </div>
        </div>
      </div>
    </div>
  );
}
