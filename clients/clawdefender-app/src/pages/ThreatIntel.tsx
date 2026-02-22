import { useEffect, useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import type {
  FeedStatus,
  BlocklistAlert,
  RulePackInfo,
  IoCStats,
  TelemetryStatus,
  TelemetryPreview,
} from "../types";

export function ThreatIntel() {
  const [feedStatus, setFeedStatus] = useState<FeedStatus | null>(null);
  const [blocklistAlerts, setBlocklistAlerts] = useState<BlocklistAlert[]>([]);
  const [rulePacks, setRulePacks] = useState<RulePackInfo[]>([]);
  const [iocStats, setIocStats] = useState<IoCStats | null>(null);
  const [telemetryStatus, setTelemetryStatus] =
    useState<TelemetryStatus | null>(null);
  const [telemetryPreview, setTelemetryPreview] =
    useState<TelemetryPreview | null>(null);
  const [updating, setUpdating] = useState(false);

  useEffect(() => {
    invoke<FeedStatus>("get_feed_status")
      .then(setFeedStatus)
      .catch(() => {});
    invoke<BlocklistAlert[]>("get_blocklist_matches")
      .then(setBlocklistAlerts)
      .catch(() => {});
    invoke<RulePackInfo[]>("get_rule_packs")
      .then(setRulePacks)
      .catch(() => {});
    invoke<IoCStats>("get_ioc_stats")
      .then(setIocStats)
      .catch(() => {});
    invoke<TelemetryStatus>("get_telemetry_status")
      .then(setTelemetryStatus)
      .catch(() => {});
    invoke<TelemetryPreview>("get_telemetry_preview")
      .then(setTelemetryPreview)
      .catch(() => {});
  }, []);

  const handleFeedUpdate = useCallback(async () => {
    setUpdating(true);
    try {
      await invoke("force_feed_update");
      const status = await invoke<FeedStatus>("get_feed_status");
      setFeedStatus(status);
    } catch {
      // ignore
    }
    setUpdating(false);
  }, []);

  const handleTogglePack = useCallback(
    async (id: string, installed: boolean) => {
      try {
        if (installed) {
          await invoke("uninstall_rule_pack", { id });
        } else {
          await invoke("install_rule_pack", { id });
        }
        const packs = await invoke<RulePackInfo[]>("get_rule_packs");
        setRulePacks(packs);
      } catch {
        // ignore
      }
    },
    []
  );

  const handleToggleTelemetry = useCallback(
    async (enabled: boolean) => {
      try {
        await invoke("toggle_telemetry", { enabled });
        const status = await invoke<TelemetryStatus>("get_telemetry_status");
        setTelemetryStatus(status);
      } catch {
        // ignore
      }
    },
    []
  );

  function formatTime(ts: string): string {
    try {
      return new Date(ts).toLocaleString();
    } catch {
      return ts;
    }
  }

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-xl font-bold text-[var(--color-text-primary)]">
        Threat Intelligence
      </h1>

      {/* Feed Status Card */}
      <section
        aria-label="Feed status"
        className="bg-[var(--color-bg-secondary)] rounded-xl border border-[var(--color-border)] p-5"
      >
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wide">
            Feed Status
          </h2>
          <button
            onClick={handleFeedUpdate}
            disabled={updating}
            className="px-3 py-1.5 text-xs font-medium rounded-md bg-[var(--color-accent)] text-white hover:opacity-90 disabled:opacity-50 transition-opacity"
          >
            {updating ? "Updating..." : "Update Now"}
          </button>
        </div>
        {feedStatus ? (
          feedStatus.version === "not configured" || feedStatus.entries_count === 0 ? (
            <div className="text-sm">
              <p className="text-[var(--color-warning)] font-medium mb-1">
                Threat feed not initialized.
              </p>
              <p className="text-[var(--color-text-secondary)]">
                Run <code className="px-1.5 py-0.5 rounded bg-[var(--color-bg-tertiary)] font-mono text-xs">clawdefender feed update</code> from the terminal to set up the threat intelligence database.
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-[var(--color-text-secondary)]">
                  Version:{" "}
                </span>
                <span className="text-[var(--color-text-primary)] font-medium">
                  {feedStatus.version}
                </span>
              </div>
              <div>
                <span className="text-[var(--color-text-secondary)]">
                  Entries:{" "}
                </span>
                <span className="text-[var(--color-text-primary)] font-medium">
                  {feedStatus.entries_count}
                </span>
              </div>
              <div>
                <span className="text-[var(--color-text-secondary)]">
                  Last Updated:{" "}
                </span>
                <span className="text-[var(--color-text-primary)]">
                  {formatTime(feedStatus.last_updated)}
                </span>
              </div>
              <div>
                <span className="text-[var(--color-text-secondary)]">
                  Next Check:{" "}
                </span>
                <span className="text-[var(--color-text-primary)]">
                  {formatTime(feedStatus.next_check)}
                </span>
              </div>
            </div>
          )
        ) : (
          <p className="text-sm text-[var(--color-text-secondary)]">
            Loading feed status...
          </p>
        )}
      </section>

      {/* Blocklist Warnings */}
      <section
        aria-label="Blocklist warnings"
        className="bg-[var(--color-bg-secondary)] rounded-xl border border-[var(--color-border)] p-5"
      >
        <h2 className="text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wide mb-3">
          Blocklist Warnings
        </h2>
        {blocklistAlerts.length === 0 ? (
          <p className="text-sm text-[var(--color-text-secondary)]">
            No blocklist matches. All monitored servers appear clean.
          </p>
        ) : (
          <div className="space-y-2">
            {blocklistAlerts.map((alert) => (
              <div
                key={alert.entry_id}
                className="p-3 rounded-lg border border-[var(--color-danger)] bg-[rgba(239,68,68,0.08)]"
              >
                <div className="flex items-center gap-2 mb-1">
                  <span className="inline-block w-2 h-2 rounded-full bg-[var(--color-danger)]" />
                  <span className="text-xs font-medium uppercase text-[var(--color-danger)]">
                    {alert.severity}
                  </span>
                  <span className="text-xs text-[var(--color-text-secondary)]">
                    {alert.entry_id}
                  </span>
                </div>
                <p className="text-sm text-[var(--color-text-primary)]">
                  {alert.server_name}: {alert.description}
                </p>
              </div>
            ))}
          </div>
        )}
      </section>

      <div className="grid grid-cols-2 gap-6">
        {/* Rule Packs Browser */}
        <section
          aria-label="Rule packs"
          className="bg-[var(--color-bg-secondary)] rounded-xl border border-[var(--color-border)] p-5"
        >
          <h2 className="text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wide mb-3">
            Community Rule Packs
          </h2>
          <div className="space-y-3">
            {rulePacks.length === 0 && (
              <p className="text-sm text-[var(--color-text-secondary)]">
                No community rule packs installed. Rule packs add specialized detection rules for common MCP threat patterns.
              </p>
            )}
            {rulePacks.map((pack) => (
              <div
                key={pack.id}
                className="p-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-primary)]"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium text-[var(--color-text-primary)]">
                    {pack.name}
                  </span>
                  <button
                    onClick={() => handleTogglePack(pack.id, pack.installed)}
                    className={`px-2 py-1 text-xs rounded-md transition-colors ${
                      pack.installed
                        ? "bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] hover:text-[var(--color-danger)]"
                        : "bg-[var(--color-accent)] text-white hover:opacity-90"
                    }`}
                  >
                    {pack.installed ? "Uninstall" : "Install"}
                  </button>
                </div>
                <p className="text-xs text-[var(--color-text-secondary)] mb-1">
                  {pack.description}
                </p>
                <div className="flex gap-3 text-xs text-[var(--color-text-secondary)]">
                  <span>v{pack.version}</span>
                  <span>{pack.rule_count} rules</span>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* IoC Statistics */}
        <section
          aria-label="IoC statistics"
          className="bg-[var(--color-bg-secondary)] rounded-xl border border-[var(--color-border)] p-5"
        >
          <h2 className="text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wide mb-3">
            IoC Database
          </h2>
          {iocStats ? (
            iocStats.total === 0 ? (
              <div className="text-sm">
                <p className="text-[var(--color-text-secondary)] mb-1">
                  IoC database is empty.
                </p>
                <p className="text-xs text-[var(--color-text-secondary)]">
                  Indicators of Compromise will be populated when the threat feed is initialized. Run <code className="px-1.5 py-0.5 rounded bg-[var(--color-bg-tertiary)] font-mono text-xs">clawdefender feed update</code> to get started.
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                <div className="grid grid-cols-2 gap-3">
                  <IoCStatCard label="Network" value={iocStats.network} />
                  <IoCStatCard label="File" value={iocStats.file} />
                  <IoCStatCard label="Behavioral" value={iocStats.behavioral} />
                  <IoCStatCard label="Total" value={iocStats.total} color="var(--color-accent)" />
                </div>
                <p className="text-xs text-[var(--color-text-secondary)]">
                  Last updated: {formatTime(iocStats.last_updated)}
                </p>
              </div>
            )
          ) : (
            <p className="text-sm text-[var(--color-text-secondary)]">
              Loading IoC stats...
            </p>
          )}
        </section>
      </div>

      {/* Telemetry Settings */}
      <section
        aria-label="Telemetry settings"
        className="bg-[var(--color-bg-secondary)] rounded-xl border border-[var(--color-border)] p-5"
      >
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wide">
            Anonymous Telemetry
          </h2>
          {telemetryStatus && (
            <button
              onClick={() => handleToggleTelemetry(!telemetryStatus.enabled)}
              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                telemetryStatus.enabled
                  ? "bg-[var(--color-accent)]"
                  : "bg-[var(--color-bg-tertiary)]"
              }`}
            >
              <span
                className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                  telemetryStatus.enabled ? "translate-x-6" : "translate-x-1"
                }`}
              />
            </button>
          )}
        </div>
        {telemetryPreview && (
          <div>
            <p className="text-sm text-[var(--color-text-secondary)] mb-2">
              {telemetryPreview.description}
            </p>
            <div className="text-xs text-[var(--color-text-secondary)] space-y-1">
              <p className="font-medium">What we collect:</p>
              <ul className="list-disc list-inside">
                {telemetryPreview.categories.map((cat) => (
                  <li key={cat}>{cat}</li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}

function IoCStatCard({
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color?: string;
}) {
  return (
    <div className="p-3 rounded-lg bg-[var(--color-bg-tertiary)]">
      <p className="text-xs text-[var(--color-text-secondary)]">{label}</p>
      <p
        className="text-lg font-bold mt-0.5"
        style={{ color: color ?? "var(--color-text-primary)" }}
      >
        {value}
      </p>
    </div>
  );
}
