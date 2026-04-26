import { useEffect, useState, useCallback, useMemo } from "react";
import { useParams } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { PageHeader } from "../components/PageHeader";
import { ShieldIcon, getTrustColor, getTrustLabel } from "../components/tools/ShieldIcon";
import { CapabilityIcons } from "../components/tools/CapabilityIcons";
import { TrustLevelSelector } from "../components/tools/TrustLevelSelector";
import { PermissionGrid } from "../components/tools/PermissionGrid";
import { BehavioralProfile } from "../components/tools/BehavioralProfile";
import { useToolStore } from "../stores/toolStore";
import { useTauriEvent } from "../hooks/useTauriEvent";
import { useToastStore } from "../components/notifications/ToastContainer";
import type { ToolCardData, TrustLevelInfo, AuditEvent } from "../types";

const DETAIL_POLL_INTERVAL = 10_000;

export function ToolDetail() {
  const { id } = useParams<{ id: string }>();
  const serverName = id ? decodeURIComponent(id) : "";

  const tools = useToolStore((s) => s.tools);
  const fetchTools = useToolStore((s) => s.fetchTools);
  const getTrustLevel = useToolStore((s) => s.getTrustLevel);

  const [tool, setTool] = useState<ToolCardData | null>(null);
  const [trustInfo, setTrustInfo] = useState<TrustLevelInfo | null>(null);
  const [recentEvents, setRecentEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("permissions");
  const addToast = useToastStore((s) => s.addToast);

  // Find tool from store
  useEffect(() => {
    const found = tools.find((t) => t.server_name === serverName);
    if (found) {
      setTool(found);
      setLoading(false);
    }
  }, [tools, serverName]);

  // Fetch detail data
  const fetchDetail = useCallback(async () => {
    try {
      await fetchTools();
      const trust = await getTrustLevel(serverName);
      setTrustInfo(trust);
    } catch {
      // Commands may not exist yet
    }

    try {
      const events = await invoke<AuditEvent[]>("get_recent_events", {
        count: 50,
      });
      setRecentEvents(
        events.filter((e) => e.server_name === serverName)
      );
    } catch {
      // Fallback: no events
    }

    setLoading(false);
  }, [serverName, fetchTools, getTrustLevel]);

  useEffect(() => {
    fetchDetail();
  }, [fetchDetail]);

  // Polling
  useEffect(() => {
    const interval = setInterval(fetchDetail, DETAIL_POLL_INTERVAL);
    return () => clearInterval(interval);
  }, [fetchDetail]);

  // Listen for events
  const handleNewEvent = useCallback(
    (event: AuditEvent) => {
      if (event.server_name === serverName) {
        setRecentEvents((prev) => [event, ...prev].slice(0, 50));
      }
    },
    [serverName]
  );
  useTauriEvent<AuditEvent>("rookbot://event", handleNewEvent);

  const handleScan = useCallback(async () => {
    setScanning(true);
    try {
      await invoke("start_scan", {
        serverCommand: serverName ?? "system-scan",
        modules: [],
        timeout: 300,
      });
    } catch {
      addToast({
        title: "Could not start the scan right now. Try again in a moment.",
        severity: "warning",
      });
    }
    setScanning(false);
    await fetchDetail();
  }, [serverName, fetchDetail, addToast]);

  const handleProtect = useCallback(async () => {
    if (!tool) return;
    try {
      await invoke("wrap_server", {
        serverName: tool.server_name,
        clientName: tool.client_name,
      });
      addToast({ title: "Protection enabled. Restart the tool to activate.", severity: "success" });
      await fetchDetail();
    } catch {
      addToast({
        title: `Could not set up protection for ${tool.server_name}. Check that the daemon is running.`,
        severity: "warning",
      });
    }
  }, [tool, fetchDetail, addToast]);

  // Quick stats
  const quickStats = useMemo(() => {
    if (!tool) return [];
    return [
      { label: "Events today", value: String(tool.event_count_today ?? 0) },
      { label: "Blocked today", value: String(tool.blocked_count_today ?? 0), color: (tool.blocked_count_today ?? 0) > 0 ? "var(--color-danger)" : undefined },
      { label: "Status", value: tool.behavioral_status === "learning" ? `Learning (${Math.round((tool.learning_progress ?? 0) * 100)}%)` : (tool.behavioral_status ?? "unknown") },
    ];
  }, [tool]);

  if (loading && !tool) {
    return (
      <div className="p-6 space-y-6 max-w-4xl">
        <PageHeader
          title=""
          breadcrumbs={[
            { label: "My Tools", to: "/tools" },
            { label: serverName },
          ]}
        />
        <DetailSkeleton />
      </div>
    );
  }

  if (!tool) {
    return (
      <div className="p-6 space-y-6 max-w-4xl">
        <PageHeader
          title="Tool not found"
          breadcrumbs={[
            { label: "My Tools", to: "/tools" },
            { label: serverName },
          ]}
        />
        <p className="text-sm text-[var(--color-text-muted)]">
          I could not find a tool named "{serverName}". It may have been removed or renamed.
        </p>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 max-w-4xl">
      {/* Header */}
      <PageHeader
        title={tool.server_name}
        breadcrumbs={[
          { label: "My Tools", to: "/tools" },
          { label: tool.server_name },
        ]}
        subtitle={tool.client_app}
      />

      {/* Status header bar */}
      <div className="flex flex-wrap items-center gap-4 p-4 rounded-lg bg-[var(--color-bg-secondary)] border border-[var(--color-border)]">
        {/* Trust badge */}
        <div className="flex items-center gap-2">
          <ShieldIcon level={tool.trust_level} size={20} />
          <span
            role="status"
            aria-label={`Trust level: ${getTrustLabel(tool.trust_level)}${tool.trust_customized ? " (customized)" : ""}`}
            className="text-sm font-medium"
            style={{ color: getTrustColor(tool.trust_level) }}
          >
            {getTrustLabel(tool.trust_level)}
            {tool.trust_customized && (
              <span className="text-xs opacity-70 ml-1">(customized)</span>
            )}
          </span>
        </div>

        {/* Wrap status */}
        <div className="flex items-center gap-1.5">
          {tool.is_wrapped ? (
            <span className="inline-flex items-center gap-1 text-xs text-[var(--color-safe)]">
              <CheckIcon />
              Protected
            </span>
          ) : (
            <button
              onClick={handleProtect}
              className="inline-flex items-center gap-1 text-xs font-medium text-[var(--color-accent)] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] rounded"
            >
              Not protected — click to wrap
            </button>
          )}
        </div>

        {/* Capabilities */}
        <div className="ml-auto">
          <CapabilityIcons capabilities={tool.capabilities} />
        </div>

        {/* Quick stats */}
        <div className="flex items-center gap-4 ml-4">
          {quickStats.map((stat) => (
            <div key={stat.label} className="text-center">
              <p
                className="text-lg font-semibold"
                style={{ color: stat.color ?? "var(--color-text-primary)" }}
              >
                {stat.value}
              </p>
              <p className="text-[10px] text-[var(--color-text-muted)]">
                {stat.label}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* Health warnings */}
      {(tool.health_warnings?.length ?? 0) > 0 && (
        <div className="space-y-2">
          {tool.health_warnings!.map((warning: any, i: number) => (
            <div
              key={i}
              role={warning.severity === "critical" ? "alert" : "status"}
              className={`flex items-start gap-3 p-3 rounded-lg border-l-[3px] bg-[var(--color-bg-secondary)] border border-[var(--color-border)] ${
                warning.severity === "critical"
                  ? "border-l-[var(--color-danger-border)]"
                  : warning.severity === "warning"
                    ? "border-l-[var(--color-warning-border)]"
                    : "border-l-[var(--color-info-border)]"
              }`}
            >
              <div className="flex-1">
                <p className="text-sm font-medium text-[var(--color-text-primary)]">
                  {warning.title}
                </p>
                <p className="text-xs text-[var(--color-text-secondary)] mt-0.5">
                  {warning.description}
                </p>
              </div>
              {warning.recommended_action && (
                <span className="text-xs text-[var(--color-accent)] shrink-0">
                  {warning.recommended_action}
                </span>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Tab navigation */}
      <div role="tablist" aria-label="Tool detail sections" className="flex gap-1 border-b border-[var(--color-border)]">
        {[
          { id: "permissions", label: "Permissions" },
          { id: "behavior", label: "Behavior" },
          { id: "activity", label: "Activity" },
          { id: "security", label: "Security" },
        ].map((tab) => (
          <button
            key={tab.id}
            role="tab"
            id={`tab-${tab.id}`}
            aria-selected={activeSection === tab.id}
            aria-controls={`tabpanel-${tab.id}`}
            tabIndex={activeSection === tab.id ? 0 : -1}
            onClick={() => setActiveSection(tab.id)}
            onKeyDown={(e) => {
              const tabs = ["permissions", "behavior", "activity", "security"];
              const idx = tabs.indexOf(tab.id);
              let nextIdx = -1;
              if (e.key === "ArrowRight") {
                e.preventDefault();
                nextIdx = (idx + 1) % tabs.length;
              } else if (e.key === "ArrowLeft") {
                e.preventDefault();
                nextIdx = (idx - 1 + tabs.length) % tabs.length;
              }
              if (nextIdx >= 0) {
                setActiveSection(tabs[nextIdx]);
                document.getElementById(`tab-${tabs[nextIdx]}`)?.focus();
              }
            }}
            className={`px-4 py-2 text-sm font-medium transition-colors duration-100 border-b-2 -mb-px focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-inset ${
              activeSection === tab.id
                ? "border-[var(--color-accent)] text-[var(--color-accent)]"
                : "border-transparent text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)]"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="min-h-[300px]" role="tabpanel" id={`tabpanel-${activeSection}`} aria-labelledby={`tab-${activeSection}`}>
        {/* Permissions tab */}
        {activeSection === "permissions" && (
          <div className="space-y-6">
            <div>
              <h3 className="text-sm font-medium text-[var(--color-text-primary)] mb-3">
                Trust Level
              </h3>
              <TrustLevelSelector
                serverName={tool.server_name}
                currentLevel={tool.trust_level}
                customized={tool.trust_customized ?? false}
                onLevelChanged={fetchDetail}
              />
            </div>
            {trustInfo && (
              <div>
                <h3 className="text-sm font-medium text-[var(--color-text-primary)] mb-3">
                  Permission Details
                </h3>
                <PermissionGrid
                  serverName={tool.server_name}
                  permissions={trustInfo.permissions}
                  onChanged={fetchDetail}
                />
              </div>
            )}
          </div>
        )}

        {/* Behavior tab */}
        {activeSection === "behavior" && (
          <BehavioralProfile
            serverName={tool.server_name}
            behavioralStatus={tool.behavioral_status ?? "unknown"}
            learningProgress={tool.learning_progress ?? 0}
          />
        )}

        {/* Activity tab */}
        {activeSection === "activity" && (
          <div>
            {recentEvents.length === 0 ? (
              <div className="flex flex-col items-center py-12 text-center">
                <p className="text-sm text-[var(--color-text-muted)]">
                  No recent activity for this tool
                </p>
              </div>
            ) : (
              <div className="space-y-1">
                {recentEvents.map((event) => (
                  <EventRow key={event.id} event={event} />
                ))}
              </div>
            )}
          </div>
        )}

        {/* Security tab */}
        {activeSection === "security" && (
          <div className="space-y-4">
            {/* Scan button */}
            <div className="flex items-center justify-between p-4 rounded-lg bg-[var(--color-bg-secondary)] border border-[var(--color-border)]">
              <div>
                <p className="text-sm font-medium text-[var(--color-text-primary)]">
                  Security Scan
                </p>
                <p className="text-xs text-[var(--color-text-muted)] mt-0.5">
                  {tool.scan_status
                    ? `Last scan: ${tool.scan_findings_count ?? 0} findings`
                    : "This tool has not been scanned yet"}
                </p>
              </div>
              <button
                onClick={handleScan}
                disabled={scanning}
                className="px-3 py-1.5 rounded-md text-xs font-medium bg-[var(--color-accent)] text-white hover:bg-[var(--color-accent-hover)] disabled:opacity-40 transition-colors duration-100"
              >
                {scanning ? "Scanning..." : "Scan this tool"}
              </button>
            </div>

            {/* Guard status */}
            {tool.guard_name && (
              <div className="p-4 rounded-lg bg-[var(--color-bg-secondary)] border border-[var(--color-border)]">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-[var(--color-text-primary)]">
                      Guard: {tool.guard_name}
                    </p>
                    <p className="text-xs text-[var(--color-text-muted)] mt-0.5">
                      {tool.guard_enabled ? "Active" : "Disabled"}
                    </p>
                  </div>
                  <span
                    className="inline-flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded-full"
                    style={{
                      color: tool.guard_enabled
                        ? "var(--color-safe)"
                        : "var(--color-text-muted)",
                      backgroundColor: tool.guard_enabled
                        ? "var(--color-safe-subtle)"
                        : "var(--color-bg-tertiary)",
                    }}
                  >
                    {tool.guard_enabled ? "Active" : "Disabled"}
                  </span>
                </div>
              </div>
            )}

            {/* Scan findings count */}
            {tool.scan_findings_count != null && tool.scan_findings_count > 0 && (
              <div className="p-4 rounded-lg border-l-[3px] border-l-[var(--color-warning-border)] bg-[var(--color-bg-secondary)] border border-[var(--color-border)]">
                <p className="text-sm font-medium text-[var(--color-text-primary)]">
                  {tool.scan_findings_count} finding{tool.scan_findings_count !== 1 ? "s" : ""} from last scan
                </p>
                <p className="text-xs text-[var(--color-text-muted)] mt-0.5">
                  Review scan results for details and recommended fixes
                </p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// Inline event row for the activity tab
function EventRow({ event }: { event: AuditEvent }) {
  const decisionColor = useMemo(() => {
    const d = event.decision.toLowerCase();
    if (d === "blocked" || d === "block" || d === "denied" || d === "deny")
      return "var(--color-danger)";
    if (d === "prompted") return "var(--color-warning)";
    return "var(--color-text-muted)";
  }, [event.decision]);

  return (
    <div className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-[var(--color-bg-tertiary)] transition-colors">
      <span className="text-xs text-[var(--color-text-muted)] font-mono w-16 shrink-0">
        {formatTime(event.timestamp)}
      </span>
      <span className="text-sm text-[var(--color-text-primary)] flex-1 truncate">
        {event.tool_name || event.action}
      </span>
      <span className="text-xs text-[var(--color-text-secondary)] max-w-[200px] truncate">
        {event.details}
      </span>
      <span
        className="text-[10px] font-medium px-2 py-0.5 rounded-full shrink-0"
        style={{
          color: decisionColor,
          backgroundColor: `color-mix(in srgb, ${decisionColor} 15%, transparent)`,
        }}
      >
        {event.decision}
      </span>
    </div>
  );
}

function formatTime(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  } catch {
    return ts;
  }
}

function CheckIcon() {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}

function DetailSkeleton() {
  return (
    <div className="space-y-6">
      <div className="h-24 rounded-lg bg-[var(--color-bg-secondary)] border border-[var(--color-border)] animate-pulse" />
      <div className="h-10 rounded bg-[var(--color-bg-tertiary)] animate-pulse" />
      <div className="space-y-2">
        {[1, 2, 3, 4, 5, 6].map((i) => (
          <div key={i} className="h-14 rounded-lg bg-[var(--color-bg-secondary)] animate-pulse" />
        ))}
      </div>
    </div>
  );
}
