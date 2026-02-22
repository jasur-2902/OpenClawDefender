import { useEffect, useState, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import type {
  NetworkConnectionEvent,
  NetworkExtensionStatus,
  NetworkSummaryData,
} from "../types";

function formatTimestamp(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return ts;
  }
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function ActionBadge({ action }: { action: string }) {
  const a = action.toLowerCase();
  if (a === "allowed") {
    return (
      <span className="inline-flex items-center text-xs px-2 py-0.5 rounded-full bg-[rgba(34,197,94,0.15)] text-[var(--color-success)]">
        Allowed
      </span>
    );
  }
  if (a === "blocked") {
    return (
      <span className="inline-flex items-center text-xs px-2 py-0.5 rounded-full bg-[rgba(239,68,68,0.15)] text-[var(--color-danger)]">
        Blocked
      </span>
    );
  }
  if (a === "prompted") {
    return (
      <span className="inline-flex items-center text-xs px-2 py-0.5 rounded-full bg-[rgba(245,158,11,0.15)] text-[var(--color-warning)]">
        Prompted
      </span>
    );
  }
  return (
    <span className="inline-flex items-center text-xs px-2 py-0.5 rounded-full bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)]">
      {action}
    </span>
  );
}

function ConnectionDetail({
  conn,
  onClose,
}: {
  conn: NetworkConnectionEvent;
  onClose: () => void;
}) {
  return (
    <div className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-xl p-5 mb-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-[var(--color-text-primary)]">
          Connection Details
        </h3>
        <button
          onClick={onClose}
          className="text-xs text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors px-2 py-1 rounded hover:bg-[var(--color-bg-tertiary)]"
        >
          Close
        </button>
      </div>

      <div className="grid grid-cols-3 gap-4 mb-4">
        <div>
          <p className="text-xs text-[var(--color-text-secondary)] mb-1">Server</p>
          <p className="text-sm text-[var(--color-text-primary)]">
            {conn.server_name ?? "N/A"}
          </p>
        </div>
        <div>
          <p className="text-xs text-[var(--color-text-secondary)] mb-1">PID</p>
          <p className="text-sm font-mono text-[var(--color-text-primary)]">
            {conn.pid}
          </p>
        </div>
        <div>
          <p className="text-xs text-[var(--color-text-secondary)] mb-1">Timestamp</p>
          <p className="text-sm text-[var(--color-text-primary)]">
            {new Date(conn.timestamp).toLocaleString()}
          </p>
        </div>
        <div>
          <p className="text-xs text-[var(--color-text-secondary)] mb-1">Destination</p>
          <p className="text-sm font-mono text-[var(--color-text-primary)]">
            {conn.destination_domain ?? conn.destination_ip}:{conn.destination_port}
          </p>
        </div>
        <div>
          <p className="text-xs text-[var(--color-text-secondary)] mb-1">Protocol</p>
          <p className="text-sm text-[var(--color-text-primary)]">
            {conn.protocol.toUpperCase()} {conn.tls && "(TLS)"}
          </p>
        </div>
        <div>
          <p className="text-xs text-[var(--color-text-secondary)] mb-1">Decision</p>
          <ActionBadge action={conn.action} />
        </div>
      </div>

      <div className="mb-4">
        <p className="text-xs text-[var(--color-text-secondary)] mb-1">Reason</p>
        <p className="text-sm text-[var(--color-text-primary)]">{conn.reason}</p>
      </div>

      {conn.rule && (
        <div className="mb-4">
          <p className="text-xs text-[var(--color-text-secondary)] mb-1">Rule</p>
          <p className="text-sm font-mono text-[var(--color-text-primary)]">{conn.rule}</p>
        </div>
      )}

      <div className="grid grid-cols-3 gap-4 mb-4">
        <div>
          <p className="text-xs text-[var(--color-text-secondary)] mb-1">Bytes Sent</p>
          <p className="text-sm text-[var(--color-text-primary)]">
            {formatBytes(conn.bytes_sent)}
          </p>
        </div>
        <div>
          <p className="text-xs text-[var(--color-text-secondary)] mb-1">Bytes Received</p>
          <p className="text-sm text-[var(--color-text-primary)]">
            {formatBytes(conn.bytes_received)}
          </p>
        </div>
        <div>
          <p className="text-xs text-[var(--color-text-secondary)] mb-1">Duration</p>
          <p className="text-sm text-[var(--color-text-primary)]">{conn.duration_ms}ms</p>
        </div>
      </div>

      {/* Signals section */}
      <div>
        <p className="text-xs text-[var(--color-text-secondary)] mb-2 font-semibold uppercase tracking-wide">
          Signals
        </p>
        <div className="grid grid-cols-2 gap-3">
          <div className="flex items-center gap-2">
            <span
              className={`inline-block w-2 h-2 rounded-full ${
                conn.ioc_match ? "bg-[var(--color-danger)]" : "bg-[var(--color-text-secondary)]"
              }`}
            />
            <span className="text-xs text-[var(--color-text-primary)]">
              IoC Match: {conn.ioc_match ? "Yes" : "No"}
            </span>
          </div>
          {conn.anomaly_score != null && (
            <div>
              <span className="text-xs text-[var(--color-text-secondary)]">
                Anomaly Score:{" "}
              </span>
              <span
                className={`text-xs font-medium ${
                  conn.anomaly_score > 0.7
                    ? "text-[var(--color-danger)]"
                    : conn.anomaly_score > 0.4
                      ? "text-[var(--color-warning)]"
                      : "text-[var(--color-text-primary)]"
                }`}
              >
                {conn.anomaly_score.toFixed(2)}
              </span>
            </div>
          )}
          {conn.behavioral && (
            <div className="col-span-2">
              <span className="text-xs text-[var(--color-text-secondary)]">
                Behavioral:{" "}
              </span>
              <span className="text-xs text-[var(--color-warning)]">
                {conn.behavioral}
              </span>
            </div>
          )}
          {conn.kill_chain && (
            <div className="col-span-2">
              <span className="text-xs text-[var(--color-text-secondary)]">
                Kill Chain:{" "}
              </span>
              <span className="text-xs text-[var(--color-danger)]">
                {conn.kill_chain}
              </span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export function NetworkLog() {
  const [connections, setConnections] = useState<NetworkConnectionEvent[]>([]);
  const [summary, setSummary] = useState<NetworkSummaryData | null>(null);
  const [netStatus, setNetStatus] = useState<NetworkExtensionStatus | null>(null);
  const [searchText, setSearchText] = useState("");
  const [protocolFilter, setProtocolFilter] = useState("");
  const [actionFilter, setActionFilter] = useState("");
  const [selectedConn, setSelectedConn] = useState<NetworkConnectionEvent | null>(null);

  useEffect(() => {
    invoke<NetworkConnectionEvent[]>("get_network_connections", { limit: 50 })
      .then(setConnections)
      .catch(() => {});

    invoke<NetworkSummaryData>("get_network_summary")
      .then(setSummary)
      .catch(() => {});

    invoke<NetworkExtensionStatus>("get_network_extension_status")
      .then(setNetStatus)
      .catch(() => {});
  }, []);

  const filteredConnections = useMemo(() => {
    let result = connections;

    if (searchText) {
      const lower = searchText.toLowerCase();
      result = result.filter(
        (c) =>
          (c.server_name?.toLowerCase().includes(lower) ?? false) ||
          c.destination_ip.toLowerCase().includes(lower) ||
          (c.destination_domain?.toLowerCase().includes(lower) ?? false) ||
          c.reason.toLowerCase().includes(lower) ||
          c.process_name.toLowerCase().includes(lower)
      );
    }

    if (protocolFilter) {
      result = result.filter((c) => c.protocol === protocolFilter);
    }

    if (actionFilter) {
      result = result.filter((c) => c.action === actionFilter);
    }

    return result;
  }, [connections, searchText, protocolFilter, actionFilter]);

  const handleExport = async () => {
    try {
      const path = await invoke<string>("export_network_log", {
        format: "json",
        range: "last_24h",
      });
      alert(`Exported to: ${path}`);
    } catch {
      // ignore
    }
  };

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-[var(--color-border)]">
        <h1 className="text-xl font-bold text-[var(--color-text-primary)]">
          Network Log
        </h1>
        <button
          onClick={handleExport}
          className="text-xs px-3 py-1.5 rounded-lg border border-[var(--color-border)] text-[var(--color-text-secondary)] hover:bg-[var(--color-bg-tertiary)] transition-colors"
        >
          Export
        </button>
      </div>

      {/* Summary Card — hidden when all counts are zero */}
      {summary &&
        (summary.total_allowed > 0 ||
          summary.total_blocked > 0 ||
          summary.total_prompted > 0) && (
        <div className="mx-6 mt-4 bg-[var(--color-bg-secondary)] rounded-xl border border-[var(--color-border)] p-4">
          <div className="flex items-center gap-6 text-sm">
            <div>
              <span className="text-[var(--color-success)] font-bold text-lg">
                {summary.total_allowed}
              </span>
              <span className="text-[var(--color-text-secondary)] ml-1">allowed</span>
            </div>
            <div>
              <span className="text-[var(--color-danger)] font-bold text-lg">
                {summary.total_blocked}
              </span>
              <span className="text-[var(--color-text-secondary)] ml-1">blocked</span>
            </div>
            <div>
              <span className="text-[var(--color-warning)] font-bold text-lg">
                {summary.total_prompted}
              </span>
              <span className="text-[var(--color-text-secondary)] ml-1">prompted</span>
            </div>
            <span className="text-xs text-[var(--color-text-secondary)] ml-auto">
              Last 24 hours
            </span>
          </div>
        </div>
      )}

      {/* Filter Bar */}
      <div className="flex items-center gap-3 px-6 py-3 border-b border-[var(--color-border)] bg-[var(--color-bg-secondary)] mt-4">
        <input
          type="text"
          placeholder="Search connections..."
          aria-label="Search connections"
          value={searchText}
          onChange={(e) => setSearchText(e.target.value)}
          className="flex-1 max-w-xs bg-[var(--color-bg-primary)] border border-[var(--color-border)] rounded-lg px-3 py-1.5 text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-secondary)] focus:outline-none focus:border-[var(--color-accent)]"
        />

        <select
          value={protocolFilter}
          onChange={(e) => setProtocolFilter(e.target.value)}
          aria-label="Filter by protocol"
          className="bg-[var(--color-bg-primary)] border border-[var(--color-border)] rounded-lg px-3 py-1.5 text-sm text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
        >
          <option value="">All Protocols</option>
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
        </select>

        <select
          value={actionFilter}
          onChange={(e) => setActionFilter(e.target.value)}
          aria-label="Filter by action"
          className="bg-[var(--color-bg-primary)] border border-[var(--color-border)] rounded-lg px-3 py-1.5 text-sm text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
        >
          <option value="">All Actions</option>
          <option value="allowed">Allowed</option>
          <option value="blocked">Blocked</option>
          <option value="prompted">Prompted</option>
        </select>

        <span className="text-xs text-[var(--color-text-secondary)] ml-auto">
          {filteredConnections.length} connections
          {filteredConnections.length !== connections.length &&
            ` (${connections.length} total)`}
        </span>
      </div>

      {/* Selected Connection Detail */}
      {selectedConn && (
        <div className="px-6 pt-4">
          <ConnectionDetail
            conn={selectedConn}
            onClose={() => setSelectedConn(null)}
          />
        </div>
      )}

      {/* Connection Table */}
      <div className="flex-1 overflow-y-auto">
        <table className="w-full text-sm">
          <thead className="sticky top-0 bg-[var(--color-bg-secondary)] border-b border-[var(--color-border)]">
            <tr className="text-xs text-[var(--color-text-secondary)] uppercase tracking-wide">
              <th className="text-left px-6 py-2 font-medium">Time</th>
              <th className="text-left px-2 py-2 font-medium">Server</th>
              <th className="text-left px-2 py-2 font-medium">Destination</th>
              <th className="text-left px-2 py-2 font-medium">Port</th>
              <th className="text-left px-2 py-2 font-medium">Proto</th>
              <th className="text-left px-2 py-2 font-medium">Action</th>
              <th className="text-right px-2 py-2 font-medium">Bytes</th>
              <th className="text-right px-6 py-2 font-medium">Duration</th>
            </tr>
          </thead>
          <tbody>
            {filteredConnections.map((conn) => (
              <tr
                key={conn.id}
                onClick={() =>
                  setSelectedConn(
                    selectedConn?.id === conn.id ? null : conn
                  )
                }
                className={`cursor-pointer transition-colors border-b border-[var(--color-border)] ${
                  selectedConn?.id === conn.id
                    ? "bg-[var(--color-bg-tertiary)]"
                    : "hover:bg-[var(--color-bg-secondary)]"
                }`}
              >
                <td className="px-6 py-2 font-mono text-xs text-[var(--color-text-secondary)]">
                  {formatTimestamp(conn.timestamp)}
                </td>
                <td className="px-2 py-2 text-xs text-[var(--color-accent)]">
                  {conn.server_name ?? "---"}
                </td>
                <td className="px-2 py-2 text-xs text-[var(--color-text-primary)] font-mono truncate max-w-[200px]">
                  {conn.destination_domain ?? conn.destination_ip}
                </td>
                <td className="px-2 py-2 text-xs text-[var(--color-text-secondary)] font-mono">
                  {conn.destination_port}
                </td>
                <td className="px-2 py-2 text-xs text-[var(--color-text-secondary)] uppercase">
                  {conn.protocol}
                  {conn.tls && (
                    <span className="ml-1 text-[var(--color-success)]" title="TLS">
                      S
                    </span>
                  )}
                </td>
                <td className="px-2 py-2">
                  <ActionBadge action={conn.action} />
                </td>
                <td className="px-2 py-2 text-xs text-[var(--color-text-secondary)] text-right font-mono">
                  {formatBytes(conn.bytes_sent + conn.bytes_received)}
                </td>
                <td className="px-6 py-2 text-xs text-[var(--color-text-secondary)] text-right font-mono">
                  {conn.duration_ms}ms
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {filteredConnections.length === 0 && (
          <div className="flex flex-col items-center justify-center py-12 px-6 text-center">
            {connections.length === 0 ? (
              <>
                <p className="text-sm text-[var(--color-text-secondary)] mb-2">
                  No network connections recorded.
                </p>
                <p className="text-xs text-[var(--color-text-secondary)] max-w-md">
                  {netStatus && !netStatus.loaded
                    ? "The Network Extension is not installed. Network filtering requires a macOS system extension."
                    : "Network events appear here when MCP servers make outbound connections through the ClawDefender proxy."}
                </p>
              </>
            ) : (
              <p className="text-sm text-[var(--color-text-secondary)]">
                No connections match your filters.
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
