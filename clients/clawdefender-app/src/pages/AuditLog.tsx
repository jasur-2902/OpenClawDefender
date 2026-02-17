import { useEffect, useState, useCallback, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { AuditEvent } from "../types";

type SortField = "timestamp" | "server_name" | "tool_name" | "resource" | "action" | "risk_level";
type SortDir = "asc" | "desc";

export function AuditLog() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [serverFilter, setServerFilter] = useState("");
  const [actionFilter, setActionFilter] = useState("");
  const [riskFilter, setRiskFilter] = useState("");
  const [sortField, setSortField] = useState<SortField>("timestamp");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [expandedRow, setExpandedRow] = useState<string | null>(null);

  const loadEvents = useCallback(async () => {
    try {
      const data = await invoke<AuditEvent[]>("get_recent_events");
      setEvents(data);
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    loadEvents();
    const interval = setInterval(loadEvents, 5000);
    return () => clearInterval(interval);
  }, [loadEvents]);

  const servers = useMemo(
    () => Array.from(new Set(events.map((e) => e.server_name))).sort(),
    [events]
  );

  const filtered = useMemo(() => {
    let result = events;

    if (search) {
      const q = search.toLowerCase();
      result = result.filter(
        (e) =>
          e.server_name.toLowerCase().includes(q) ||
          (e.tool_name && e.tool_name.toLowerCase().includes(q)) ||
          e.action.toLowerCase().includes(q) ||
          (e.resource && e.resource.toLowerCase().includes(q)) ||
          e.details.toLowerCase().includes(q)
      );
    }

    if (serverFilter) {
      result = result.filter((e) => e.server_name === serverFilter);
    }
    if (actionFilter) {
      result = result.filter((e) => e.decision === actionFilter);
    }
    if (riskFilter) {
      result = result.filter((e) => e.risk_level === riskFilter);
    }

    result.sort((a, b) => {
      const aVal = a[sortField] ?? "";
      const bVal = b[sortField] ?? "";
      const cmp = String(aVal).localeCompare(String(bVal));
      return sortDir === "asc" ? cmp : -cmp;
    });

    return result;
  }, [events, search, serverFilter, actionFilter, riskFilter, sortField, sortDir]);

  function toggleSort(field: SortField) {
    if (sortField === field) {
      setSortDir(sortDir === "asc" ? "desc" : "asc");
    } else {
      setSortField(field);
      setSortDir("desc");
    }
  }

  function riskBadge(level: AuditEvent["risk_level"]) {
    const styles: Record<string, string> = {
      low: "bg-[var(--color-success)]/20 text-[var(--color-success)]",
      medium: "bg-[var(--color-warning)]/20 text-[var(--color-warning)]",
      high: "bg-[var(--color-danger)]/20 text-[var(--color-danger)]",
      critical: "bg-red-900/40 text-red-300",
    };
    return (
      <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${styles[level]}`}>
        {level}
      </span>
    );
  }

  function decisionBadge(decision: string) {
    const styles: Record<string, string> = {
      allowed: "text-[var(--color-success)]",
      blocked: "text-[var(--color-danger)]",
      prompted: "text-[var(--color-warning)]",
    };
    return (
      <span className={`text-xs font-medium ${styles[decision] ?? "text-[var(--color-text-secondary)]"}`}>
        {decision}
      </span>
    );
  }

  function sortIndicator(field: SortField) {
    if (sortField !== field) return null;
    return <span className="ml-1">{sortDir === "asc" ? "\u25B2" : "\u25BC"}</span>;
  }

  function formatTime(ts: string): string {
    try {
      return new Date(ts).toLocaleString();
    } catch {
      return ts;
    }
  }

  const headerCls =
    "px-3 py-2 text-left text-xs font-medium text-[var(--color-text-secondary)] uppercase tracking-wide cursor-pointer hover:text-[var(--color-text-primary)] select-none";

  return (
    <div className="p-6 space-y-4">
      <h1 className="text-2xl font-bold">Audit Log</h1>

      {error && (
        <div className="rounded-lg border border-[var(--color-danger)] bg-[var(--color-danger)]/10 p-4 text-sm text-[var(--color-danger)]">
          {error}
        </div>
      )}

      <div className="space-y-3">
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search events..."
          className="w-full px-3 py-2 rounded-md bg-[var(--color-bg-secondary)] border border-[var(--color-border)] text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-secondary)]/50 focus:outline-none focus:border-[var(--color-accent)]"
        />

        <div className="flex gap-3">
          <select
            value={serverFilter}
            onChange={(e) => setServerFilter(e.target.value)}
            className="px-3 py-1.5 rounded-md bg-[var(--color-bg-secondary)] border border-[var(--color-border)] text-sm text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
          >
            <option value="">All Servers</option>
            {servers.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>

          <select
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            className="px-3 py-1.5 rounded-md bg-[var(--color-bg-secondary)] border border-[var(--color-border)] text-sm text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
          >
            <option value="">All Actions</option>
            <option value="allowed">Allowed</option>
            <option value="blocked">Blocked</option>
            <option value="prompted">Prompted</option>
          </select>

          <select
            value={riskFilter}
            onChange={(e) => setRiskFilter(e.target.value)}
            className="px-3 py-1.5 rounded-md bg-[var(--color-bg-secondary)] border border-[var(--color-border)] text-sm text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
          >
            <option value="">All Risk Levels</option>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
        </div>
      </div>

      <div className="rounded-lg border border-[var(--color-border)] overflow-hidden">
        <table className="w-full">
          <thead className="bg-[var(--color-bg-tertiary)]">
            <tr>
              <th className={headerCls} onClick={() => toggleSort("timestamp")}>
                Time{sortIndicator("timestamp")}
              </th>
              <th className={headerCls} onClick={() => toggleSort("server_name")}>
                Server{sortIndicator("server_name")}
              </th>
              <th className={headerCls} onClick={() => toggleSort("tool_name")}>
                Tool{sortIndicator("tool_name")}
              </th>
              <th className={headerCls} onClick={() => toggleSort("resource")}>
                Resource{sortIndicator("resource")}
              </th>
              <th className={headerCls} onClick={() => toggleSort("action")}>
                Action{sortIndicator("action")}
              </th>
              <th className={headerCls} onClick={() => toggleSort("risk_level")}>
                Risk{sortIndicator("risk_level")}
              </th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td
                  colSpan={6}
                  className="px-3 py-8 text-center text-sm text-[var(--color-text-secondary)]"
                >
                  No events found.
                </td>
              </tr>
            ) : (
              filtered.map((event, i) => (
                <>
                  <tr
                    key={event.id}
                    onClick={() =>
                      setExpandedRow(expandedRow === event.id ? null : event.id)
                    }
                    className={`cursor-pointer hover:bg-[var(--color-bg-tertiary)] transition-colors ${
                      i % 2 === 0
                        ? "bg-[var(--color-bg-secondary)]"
                        : "bg-[var(--color-bg-primary)]"
                    }`}
                  >
                    <td className="px-3 py-2 text-xs text-[var(--color-text-secondary)] whitespace-nowrap">
                      {formatTime(event.timestamp)}
                    </td>
                    <td className="px-3 py-2 text-sm">{event.server_name}</td>
                    <td className="px-3 py-2 text-sm font-mono">
                      {event.tool_name ?? "-"}
                    </td>
                    <td className="px-3 py-2 text-sm text-[var(--color-text-secondary)] max-w-xs truncate">
                      {event.resource ?? "-"}
                    </td>
                    <td className="px-3 py-2">{decisionBadge(event.decision)}</td>
                    <td className="px-3 py-2">{riskBadge(event.risk_level)}</td>
                  </tr>
                  {expandedRow === event.id && (
                    <tr key={`${event.id}-detail`} className="bg-[var(--color-bg-primary)]">
                      <td colSpan={6} className="px-4 py-3 border-t border-[var(--color-border)]">
                        <div className="grid grid-cols-2 gap-4 text-sm">
                          <div>
                            <span className="text-[var(--color-text-secondary)]">Event ID: </span>
                            <span className="font-mono">{event.id}</span>
                          </div>
                          <div>
                            <span className="text-[var(--color-text-secondary)]">Event Type: </span>
                            <span>{event.event_type}</span>
                          </div>
                          <div>
                            <span className="text-[var(--color-text-secondary)]">Action: </span>
                            <span>{event.action}</span>
                          </div>
                          <div>
                            <span className="text-[var(--color-text-secondary)]">Decision: </span>
                            <span>{event.decision}</span>
                          </div>
                          <div className="col-span-2">
                            <span className="text-[var(--color-text-secondary)]">Details: </span>
                            <span>{event.details}</span>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="text-xs text-[var(--color-text-secondary)]">
        Showing {filtered.length} of {events.length} events
      </div>
    </div>
  );
}
