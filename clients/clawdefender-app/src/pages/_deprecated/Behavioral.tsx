import { useEffect, useState, useCallback, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { AppSettings, BehavioralStatus, ServerProfileSummary } from "../types";

// Shape of the full profile JSON stored in SQLite
interface ProfileDetail {
  server_name: string;
  client_name: string;
  first_seen: string;
  last_updated: string;
  learning_mode: boolean;
  observation_count: number;
  tool_profile: {
    tool_counts: Record<string, number>;
    call_rate: number;
  };
  file_profile: {
    directory_prefixes: string[];
    extension_counts: Record<string, number>;
    read_count: number;
    write_count: number;
  };
  network_profile: {
    observed_hosts: string[];
    observed_ports: number[];
    request_rate: number;
    has_networked: boolean;
  };
}

const LEARNING_THRESHOLD = 100;

export function Behavioral() {
  const [status, setStatus] = useState<BehavioralStatus | null>(null);
  const [profiles, setProfiles] = useState<ServerProfileSummary[]>([]);
  const [expandedServer, setExpandedServer] = useState<string | null>(null);
  const [profileDetail, setProfileDetail] = useState<ProfileDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [autoBlockEnabled, setAutoBlockEnabled] = useState(false);
  const [threshold, setThreshold] = useState(0.7);
  const [error, setError] = useState<string | null>(null);
  const settingsRef = useRef<AppSettings | null>(null);

  // Load persisted settings on mount
  useEffect(() => {
    invoke<AppSettings>("get_settings").then((s) => {
      settingsRef.current = s;
      setAutoBlockEnabled(s.behavioral_auto_block);
      setThreshold(s.behavioral_threshold);
    }).catch(() => {});
  }, []);

  const persistSettings = useCallback(async (autoBlock: boolean, thresh: number) => {
    try {
      const current = settingsRef.current ?? await invoke<AppSettings>("get_settings");
      const updated = { ...current, behavioral_auto_block: autoBlock, behavioral_threshold: thresh };
      await invoke("update_settings", { settings: updated });
      settingsRef.current = updated;
    } catch {
      // Settings save is best-effort
    }
  }, []);

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

  // Fetch full profile detail when a server is expanded
  useEffect(() => {
    if (!expandedServer) {
      setProfileDetail(null);
      setDetailError(null);
      return;
    }
    setDetailLoading(true);
    setDetailError(null);
    invoke<ProfileDetail>("get_profile_detail", { serverName: expandedServer })
      .then((detail) => {
        setProfileDetail(detail);
        setDetailLoading(false);
      })
      .catch((e) => {
        setDetailError(String(e));
        setProfileDetail(null);
        setDetailLoading(false);
      });
  }, [expandedServer]);

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

  function renderExpandedDetail(profile: ServerProfileSummary) {
    // If behavioral engine is disabled, show a message
    if (status && !status.enabled) {
      return (
        <div className="px-4 py-4 border-t border-[var(--color-border)] bg-[var(--color-bg-primary)]">
          <p className="text-sm text-[var(--color-text-secondary)]">
            Behavioral analysis is disabled. Enable it in Settings &gt; Protection.
          </p>
        </div>
      );
    }

    if (detailLoading) {
      return (
        <div className="px-4 py-6 border-t border-[var(--color-border)] bg-[var(--color-bg-primary)] text-center">
          <p className="text-sm text-[var(--color-text-secondary)]">Loading profile details...</p>
        </div>
      );
    }

    if (detailError) {
      return (
        <div className="px-4 py-4 border-t border-[var(--color-border)] bg-[var(--color-bg-primary)]">
          <p className="text-sm text-[var(--color-danger)]">{detailError}</p>
        </div>
      );
    }

    if (!profileDetail) return null;

    const d = profileDetail;

    // Learning mode banner
    if (d.learning_mode) {
      return (
        <div className="px-4 py-4 border-t border-[var(--color-border)] bg-[var(--color-bg-primary)] space-y-4">
          <div className="rounded-lg bg-[var(--color-accent)]/10 border border-[var(--color-accent)]/30 px-4 py-3">
            <p className="text-sm text-[var(--color-accent)]">
              Learning this server's behavior &mdash; {d.observation_count}/{LEARNING_THRESHOLD} events observed.
              Full profile will be available after {LEARNING_THRESHOLD} events and 30 minutes of activity.
            </p>
          </div>
          {renderPartialStats(d, profile)}
        </div>
      );
    }

    return (
      <div className="px-4 py-4 border-t border-[var(--color-border)] bg-[var(--color-bg-primary)] space-y-4">
        {renderPartialStats(d, profile)}
      </div>
    );
  }

  function renderPartialStats(d: ProfileDetail, profile: ServerProfileSummary) {
    const toolEntries = Object.entries(d.tool_profile.tool_counts).sort(
      (a, b) => b[1] - a[1]
    );
    const fileExtEntries = Object.entries(d.file_profile.extension_counts).sort(
      (a, b) => b[1] - a[1]
    );
    const dirPrefixes = Array.isArray(d.file_profile.directory_prefixes)
      ? d.file_profile.directory_prefixes
      : [];
    const hosts = Array.isArray(d.network_profile.observed_hosts)
      ? d.network_profile.observed_hosts
      : [];
    const ports = Array.isArray(d.network_profile.observed_ports)
      ? d.network_profile.observed_ports
      : [];

    return (
      <>
        {/* Overview stats */}
        <div className="grid grid-cols-4 gap-4">
          <div>
            <p className="text-xs font-medium text-[var(--color-text-secondary)] mb-1 uppercase tracking-wide">
              Observations
            </p>
            <p className="text-lg font-bold text-[var(--color-text-primary)]">
              {d.observation_count.toLocaleString()}
            </p>
          </div>
          <div>
            <p className="text-xs font-medium text-[var(--color-text-secondary)] mb-1 uppercase tracking-wide">
              Tools
            </p>
            <p className="text-lg font-bold text-[var(--color-text-primary)]">
              {profile.tools_count}
            </p>
          </div>
          <div>
            <p className="text-xs font-medium text-[var(--color-text-secondary)] mb-1 uppercase tracking-wide">
              Anomaly Score
            </p>
            <p className={`text-lg font-bold ${anomalyColor(profile.anomaly_score)}`}>
              {profile.anomaly_score.toFixed(2)}
            </p>
          </div>
          <div>
            <p className="text-xs font-medium text-[var(--color-text-secondary)] mb-1 uppercase tracking-wide">
              Last Activity
            </p>
            <p className="text-sm text-[var(--color-text-primary)]">
              {formatTime(d.last_updated)}
            </p>
          </div>
        </div>

        {/* Tool usage */}
        {toolEntries.length > 0 && (
          <div>
            <h4 className="text-xs font-medium text-[var(--color-text-secondary)] mb-2 uppercase tracking-wide">
              Tool Usage
            </h4>
            <div className="grid grid-cols-2 gap-x-6 gap-y-1">
              {toolEntries.map(([tool, count]) => (
                <div key={tool} className="flex items-center justify-between text-sm">
                  <span className="font-mono text-xs text-[var(--color-text-primary)] truncate mr-2">
                    {tool}
                  </span>
                  <span className="text-xs text-[var(--color-text-secondary)] shrink-0">
                    {count.toLocaleString()} calls
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* File territory */}
        {(dirPrefixes.length > 0 || fileExtEntries.length > 0) && (
          <div>
            <h4 className="text-xs font-medium text-[var(--color-text-secondary)] mb-2 uppercase tracking-wide">
              File Territory
            </h4>
            <div className="space-y-2">
              {dirPrefixes.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {dirPrefixes.map((dir) => (
                    <span
                      key={dir}
                      className="px-2 py-0.5 rounded text-xs font-mono bg-[var(--color-bg-tertiary)] text-[var(--color-text-primary)]"
                    >
                      {dir}
                    </span>
                  ))}
                </div>
              )}
              {fileExtEntries.length > 0 && (
                <div className="flex items-center gap-3 text-xs text-[var(--color-text-secondary)]">
                  <span>{d.file_profile.read_count.toLocaleString()} reads</span>
                  <span>{d.file_profile.write_count.toLocaleString()} writes</span>
                  <span className="ml-2">
                    Extensions: {fileExtEntries.slice(0, 8).map(([ext, n]) => `${ext} (${n})`).join(", ")}
                    {fileExtEntries.length > 8 && ` +${fileExtEntries.length - 8} more`}
                  </span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Network behavior */}
        {d.network_profile.has_networked && (
          <div>
            <h4 className="text-xs font-medium text-[var(--color-text-secondary)] mb-2 uppercase tracking-wide">
              Network Behavior
            </h4>
            <div className="space-y-1">
              {hosts.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {hosts.slice(0, 12).map((host) => (
                    <span
                      key={host}
                      className="px-2 py-0.5 rounded text-xs font-mono bg-[var(--color-bg-tertiary)] text-[var(--color-text-primary)]"
                    >
                      {host}
                    </span>
                  ))}
                  {hosts.length > 12 && (
                    <span className="text-xs text-[var(--color-text-secondary)]">
                      +{hosts.length - 12} more
                    </span>
                  )}
                </div>
              )}
              <div className="flex items-center gap-4 text-xs text-[var(--color-text-secondary)]">
                {ports.length > 0 && (
                  <span>Ports: {ports.sort((a, b) => a - b).join(", ")}</span>
                )}
                {d.network_profile.request_rate > 0 && (
                  <span>{d.network_profile.request_rate.toFixed(1)} req/min</span>
                )}
              </div>
            </div>
          </div>
        )}

        {/* No network activity */}
        {!d.network_profile.has_networked && (
          <div>
            <h4 className="text-xs font-medium text-[var(--color-text-secondary)] mb-2 uppercase tracking-wide">
              Network Behavior
            </h4>
            <p className="text-xs text-[var(--color-text-secondary)]">
              No network connections observed from this server.
            </p>
          </div>
        )}

        {/* First seen / client */}
        <div className="flex items-center gap-6 text-xs text-[var(--color-text-secondary)] pt-1 border-t border-[var(--color-border)]">
          <span>Client: {d.client_name}</span>
          <span>First seen: {formatTime(d.first_seen)}</span>
        </div>
      </>
    );
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
          <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-6 text-center">
            <p className="text-sm text-[var(--color-text-primary)] font-medium mb-2">
              No server profiles available yet
            </p>
            <p className="text-sm text-[var(--color-text-secondary)] max-w-md mx-auto">
              Behavioral profiles build automatically as your MCP servers are used. Start using your AI tools to begin building baselines.
            </p>
          </div>
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

            {expandedServer === profile.server_name && renderExpandedDetail(profile)}
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
            onClick={() => {
              const next = !autoBlockEnabled;
              setAutoBlockEnabled(next);
              persistSettings(next, threshold);
            }}
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
            onChange={(e) => {
              const val = parseFloat(e.target.value);
              setThreshold(val);
              persistSettings(autoBlockEnabled, val);
            }}
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
