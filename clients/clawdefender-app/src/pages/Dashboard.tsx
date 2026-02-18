import { useEffect, useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useEventStore } from "../stores/eventStore";
import { useTauriEvent } from "../hooks/useTauriEvent";
import type {
  DaemonStatus,
  AuditEvent,
  GuardSummary,
  McpServer,
  PendingPrompt,
  FeedStatus,
  BlocklistAlert,
  NetworkExtensionStatus,
  NetworkSummaryData,
} from "../types";

type ProtectionLevel = "protected" | "warning" | "danger";

function getProtectionLevel(
  daemonRunning: boolean,
  blockedCount: number,
  pendingCount: number
): ProtectionLevel {
  if (!daemonRunning) return "danger";
  if (blockedCount > 0 || pendingCount > 0) return "warning";
  return "protected";
}

const protectionConfig: Record<
  ProtectionLevel,
  { label: string; color: string; bg: string }
> = {
  protected: {
    label: "You're Protected",
    color: "var(--color-success)",
    bg: "rgba(34, 197, 94, 0.1)",
  },
  warning: {
    label: "Action Needed",
    color: "var(--color-warning)",
    bg: "rgba(245, 158, 11, 0.1)",
  },
  danger: {
    label: "Threat Detected",
    color: "var(--color-danger)",
    bg: "rgba(239, 68, 68, 0.1)",
  },
};

function formatTime(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  } catch {
    return ts;
  }
}

function StatusBadge({ decision }: { decision: string }) {
  const lower = decision.toLowerCase();
  if (lower === "allowed" || lower === "allow") {
    return (
      <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-[rgba(34,197,94,0.15)] text-[var(--color-success)]">
        ✓ Allowed
      </span>
    );
  }
  if (lower === "blocked" || lower === "deny") {
    return (
      <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-[rgba(239,68,68,0.15)] text-[var(--color-danger)]">
        ✗ Blocked
      </span>
    );
  }
  if (lower === "prompted" || lower === "prompt") {
    return (
      <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-[rgba(245,158,11,0.15)] text-[var(--color-warning)]">
        ? Prompted
      </span>
    );
  }
  return (
    <span className="inline-flex items-center text-xs px-2 py-0.5 rounded-full bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)]">
      {decision}
    </span>
  );
}

export function Dashboard() {
  const events = useEventStore((s) => s.events);
  const pendingPrompts = useEventStore((s) => s.pendingPrompts);
  const daemonRunning = useEventStore((s) => s.daemonRunning);
  const setEvents = useEventStore((s) => s.setEvents);
  const setDaemonRunning = useEventStore((s) => s.setDaemonRunning);
  const addEvent = useEventStore((s) => s.addEvent);
  const addPrompt = useEventStore((s) => s.addPrompt);

  const [status, setStatus] = useState<DaemonStatus | null>(null);
  const [guards, setGuards] = useState<GuardSummary[]>([]);
  const [servers, setServers] = useState<McpServer[]>([]);
  const [feedStatus, setFeedStatus] = useState<FeedStatus | null>(null);
  const [blocklistAlerts, setBlocklistAlerts] = useState<BlocklistAlert[]>([]);
  const [netExtStatus, setNetExtStatus] = useState<NetworkExtensionStatus | null>(null);
  const [networkSummary, setNetworkSummary] = useState<NetworkSummaryData | null>(null);

  useEffect(() => {
    invoke<DaemonStatus>("get_daemon_status")
      .then((s) => {
        setStatus(s);
        setDaemonRunning(s.running);
      })
      .catch(() => {});

    invoke<AuditEvent[]>("get_recent_events")
      .then((evts) => setEvents(evts))
      .catch(() => {});

    invoke<GuardSummary[]>("list_guards")
      .then((g) => setGuards(g))
      .catch(() => {});

    invoke<McpServer[]>("list_servers")
      .then((s) => setServers(s))
      .catch(() => {});

    invoke<FeedStatus>("get_feed_status")
      .then(setFeedStatus)
      .catch(() => {});

    invoke<BlocklistAlert[]>("get_blocklist_matches")
      .then(setBlocklistAlerts)
      .catch(() => {});

    invoke<NetworkExtensionStatus>("get_network_extension_status")
      .then(setNetExtStatus)
      .catch(() => {});

    invoke<NetworkSummaryData>("get_network_summary")
      .then(setNetworkSummary)
      .catch(() => {});
  }, [setEvents, setDaemonRunning]);

  const handleNewEvent = useCallback(
    (payload: AuditEvent) => addEvent(payload),
    [addEvent]
  );
  const handleStatusChange = useCallback(
    (payload: { daemon_running: boolean }) =>
      setDaemonRunning(payload.daemon_running),
    [setDaemonRunning]
  );
  const handlePrompt = useCallback(
    (payload: PendingPrompt) => addPrompt(payload),
    [addPrompt]
  );

  useTauriEvent<AuditEvent>("clawdefender://event", handleNewEvent);
  useTauriEvent<{ daemon_running: boolean }>(
    "clawdefender://status-change",
    handleStatusChange
  );
  useTauriEvent<PendingPrompt>("clawdefender://prompt", handlePrompt);

  const blockedCount = events.filter(
    (e) => e.decision === "blocked" || e.decision === "deny"
  ).length;
  const level = getProtectionLevel(
    daemonRunning,
    blockedCount,
    pendingPrompts.length
  );
  const config = protectionConfig[level];
  const activeGuards = guards.filter((g) => g.enabled).length;

  const recentEvents = events.slice(0, 10);
  const alerts = events.filter(
    (e) => e.risk_level === "critical" || e.risk_level === "high"
  );
  const unresolvedAlerts = alerts.slice(0, 5);

  return (
    <div className="p-6 space-y-6">
      {/* Protection Status Hero */}
      <section aria-label="Protection status" className="rounded-xl p-6 border" style={{
          backgroundColor: config.bg,
          borderColor: config.color,
        }}
      >
        <div className="flex items-center gap-3" role="status" aria-label={`Protection status: ${config.label}`}>
          <span
            aria-hidden="true"
            className="inline-block w-3 h-3 rounded-full"
            style={{ backgroundColor: config.color }}
          />
          <h1 className="text-2xl font-bold" style={{ color: config.color }}>
            {config.label}
          </h1>
        </div>
        <p className="mt-2 text-sm text-[var(--color-text-secondary)]">
          {status?.servers_proxied ?? 0} MCP servers monitored &bull;{" "}
          {events.length} events today &bull; {blockedCount} blocked
        </p>
      </section>

      {/* Quick Stats Row */}
      <section aria-label="Quick statistics" className="grid grid-cols-4 gap-4">
        <StatCard label="Events Today" value={events.length} />
        <StatCard label="Blocked" value={blockedCount} color="var(--color-danger)" />
        <StatCard
          label="Pending Prompts"
          value={pendingPrompts.length}
          color="var(--color-warning)"
        />
        <StatCard
          label="Active Guards"
          value={activeGuards}
          color="var(--color-accent)"
        />
      </section>

      {/* Threat Intelligence Card */}
      <section
        aria-label="Threat intelligence"
        className="bg-[var(--color-bg-secondary)] rounded-xl border border-[var(--color-border)] p-4"
      >
        <h2 className="text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wide mb-2">
          Threat Intelligence
        </h2>
        <div className="flex items-center gap-6 text-sm">
          <div>
            <span className="text-[var(--color-text-secondary)]">Feed: </span>
            <span className="text-[var(--color-text-primary)] font-medium">
              {feedStatus ? `v${feedStatus.version}` : "loading..."}
            </span>
          </div>
          <div>
            <span className="text-[var(--color-text-secondary)]">
              Blocklist Warnings:{" "}
            </span>
            <span
              className={`font-medium ${
                blocklistAlerts.length > 0
                  ? "text-[var(--color-danger)]"
                  : "text-[var(--color-success)]"
              }`}
            >
              {blocklistAlerts.length}
            </span>
          </div>
          {feedStatus && (
            <div>
              <span className="text-[var(--color-text-secondary)]">
                Entries:{" "}
              </span>
              <span className="text-[var(--color-text-primary)]">
                {feedStatus.entries_count}
              </span>
            </div>
          )}
        </div>
      </section>

      {/* Network Protection Card */}
      <section
        aria-label="Network protection"
        className="bg-[var(--color-bg-secondary)] rounded-xl border border-[var(--color-border)] p-4"
      >
        <h2 className="text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wide mb-2">
          Network Protection
        </h2>
        <div className="flex items-center gap-6 text-sm">
          <div className="flex items-center gap-2">
            <span
              className={`inline-block w-2 h-2 rounded-full ${
                netExtStatus?.filter_active
                  ? "bg-[var(--color-success)]"
                  : "bg-[var(--color-text-secondary)]"
              }`}
            />
            <span className="text-[var(--color-text-primary)] font-medium">
              {netExtStatus?.filter_active ? "Active" : "Inactive"}
            </span>
          </div>
          {netExtStatus?.filter_active && (
            <div>
              <span className="text-[var(--color-text-secondary)]">Connections filtered: </span>
              <span className="text-[var(--color-text-primary)]">{netExtStatus.filtering_count}</span>
            </div>
          )}
          {!netExtStatus?.filter_active && (
            <a
              href="/settings"
              className="text-[var(--color-accent)] hover:underline text-sm"
            >
              Enable in Settings
            </a>
          )}
        </div>
      </section>

      {/* Network Activity Card */}
      {networkSummary && (
        <section
          aria-label="Network activity"
          className="bg-[var(--color-bg-secondary)] rounded-xl border border-[var(--color-border)] p-4"
        >
          <h2 className="text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wide mb-2">
            Network Activity
          </h2>
          <div className="flex items-center gap-6 text-sm">
            <div>
              <span className="text-[var(--color-success)] font-bold text-lg">
                {networkSummary.total_allowed}
              </span>
              <span className="text-[var(--color-text-secondary)] ml-1">allowed</span>
            </div>
            <div>
              <span className="text-[var(--color-danger)] font-bold text-lg">
                {networkSummary.total_blocked}
              </span>
              <span className="text-[var(--color-text-secondary)] ml-1">blocked</span>
            </div>
            <div>
              <span className="text-[var(--color-warning)] font-bold text-lg">
                {networkSummary.total_prompted}
              </span>
              <span className="text-[var(--color-text-secondary)] ml-1">prompted</span>
            </div>
            <div className="ml-auto flex items-center gap-3">
              {networkSummary.top_destinations.slice(0, 3).map((d) => (
                <span key={d.destination} className="text-xs text-[var(--color-text-secondary)]">
                  {d.destination}{" "}
                  <span className="text-[var(--color-text-primary)] font-medium">
                    ({d.count})
                  </span>
                </span>
              ))}
            </div>
          </div>
        </section>
      )}

      <div className="grid grid-cols-3 gap-6">
        {/* Recent Activity Feed */}
        <section aria-label="Recent activity" className="col-span-2 bg-[var(--color-bg-secondary)] rounded-xl border border-[var(--color-border)] p-4">
          <h2 className="text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wide mb-3">
            Recent Activity
          </h2>
          {recentEvents.length === 0 ? (
            <p className="text-sm text-[var(--color-text-secondary)]">
              No events yet.
            </p>
          ) : (
            <div className="space-y-1">
              {recentEvents.map((evt) => (
                <div
                  key={evt.id}
                  className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-[var(--color-bg-tertiary)] transition-colors"
                >
                  <span className="text-xs text-[var(--color-text-secondary)] w-14 shrink-0 font-mono">
                    {formatTime(evt.timestamp)}
                  </span>
                  <span className="text-xs text-[var(--color-accent)] w-24 truncate shrink-0">
                    {evt.server_name}
                  </span>
                  <span className="text-sm text-[var(--color-text-primary)] flex-1 truncate">
                    {evt.tool_name ?? evt.event_type}
                  </span>
                  <StatusBadge decision={evt.decision} />
                </div>
              ))}
            </div>
          )}
        </section>

        {/* Alerts Panel */}
        <section aria-label="Security alerts" className="bg-[var(--color-bg-secondary)] rounded-xl border border-[var(--color-border)] p-4">
          <h2 className="text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wide mb-3">
            Alerts
          </h2>
          {unresolvedAlerts.length === 0 ? (
            <p className="text-sm text-[var(--color-text-secondary)]">
              No alerts. All clear.
            </p>
          ) : (
            <div className="space-y-2">
              {unresolvedAlerts.map((alert) => (
                <div
                  key={alert.id}
                  className="p-3 rounded-lg border border-[var(--color-danger)] bg-[rgba(239,68,68,0.08)]"
                >
                  <div className="flex items-center gap-2 mb-1">
                    <span
                      className={`inline-block w-2 h-2 rounded-full ${
                        alert.risk_level === "critical"
                          ? "bg-[var(--color-danger)]"
                          : "bg-[var(--color-warning)]"
                      }`}
                    />
                    <span className="text-xs font-medium uppercase text-[var(--color-danger)]">
                      {alert.risk_level}
                    </span>
                  </div>
                  <p className="text-sm text-[var(--color-text-primary)] truncate">
                    {alert.details}
                  </p>
                  <p className="text-xs text-[var(--color-text-secondary)] mt-1">
                    {alert.server_name} &bull; {formatTime(alert.timestamp)}
                  </p>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>

      {/* Server Overview */}
      {servers.length > 0 && (
        <div>
          <h2 className="text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wide mb-3">
            Server Overview
          </h2>
          <div className="grid grid-cols-3 gap-4">
            {servers.map((srv) => (
              <div
                key={srv.name}
                className="bg-[var(--color-bg-secondary)] rounded-xl border border-[var(--color-border)] p-4"
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-[var(--color-text-primary)]">
                    {srv.name}
                  </span>
                  <span
                    className={`inline-block w-2 h-2 rounded-full ${
                      srv.status === "running"
                        ? "bg-[var(--color-success)]"
                        : srv.status === "error"
                          ? "bg-[var(--color-danger)]"
                          : "bg-[var(--color-text-secondary)]"
                    }`}
                  />
                </div>
                <div className="flex items-center justify-between text-xs text-[var(--color-text-secondary)]">
                  <span>{srv.status}</span>
                  <span>{srv.events_count} events</span>
                </div>
                {srv.wrapped && (
                  <span className="inline-block mt-2 text-xs px-2 py-0.5 rounded bg-[rgba(59,130,246,0.15)] text-[var(--color-accent)]">
                    wrapped
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function StatCard({
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color?: string;
}) {
  return (
    <div className="bg-[var(--color-bg-secondary)] rounded-xl border border-[var(--color-border)] p-4">
      <p className="text-xs text-[var(--color-text-secondary)] uppercase tracking-wide">
        {label}
      </p>
      <p
        className="text-2xl font-bold mt-1"
        style={{ color: color ?? "var(--color-text-primary)" }}
      >
        {value}
      </p>
    </div>
  );
}
