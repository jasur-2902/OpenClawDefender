import { useEffect, useCallback, useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { useTauriEvent } from "../hooks/useTauriEvent";
import { Btn, Dot, Rook, SectionTitle, Icon } from "../components/design";
import type { DetectedToolStats, McpServerInfo } from "../types";
import { PermissionBanner } from "../components/PermissionBanner";

const POLL_INTERVAL = 10_000;

// Module-level cache so data persists across page navigations
let _cachedTools: DetectedToolStats[] | null = null;

export function MyTools() {
  const navigate = useNavigate();
  const [tools, setTools] = useState<DetectedToolStats[]>(_cachedTools ?? []);
  const [loading, setLoading] = useState(_cachedTools === null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchTools = useCallback(async () => {
    try {
      const result = await invoke<DetectedToolStats[]>("get_detected_tools_with_stats");
      _cachedTools = result;
      setTools(result);
    } catch (e) {
      console.error("Failed to fetch detected tools:", e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchTools();
    intervalRef.current = setInterval(fetchTools, POLL_INTERVAL);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [fetchTools]);

  const handleRefresh = useCallback(() => {
    setLoading(true);
    fetchTools();
  }, [fetchTools]);

  useTauriEvent("rookbot://new-tool-detected", fetchTools);

  const installedTools = tools.filter((t) => t.installed);
  const activeCount = installedTools.filter((t) => t.running).length;

  return (
    <div className="cd-scroll" style={{ padding: 24, maxWidth: 1080, margin: "0 auto", overflowY: "auto", height: "100%" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between" }}>
        <SectionTitle sub="Each AI tool on this Mac is monitored at the OS level.">My Tools</SectionTitle>
        <Btn kind="ghost" size="sm" icon="refresh" onClick={handleRefresh} disabled={loading}>
          Refresh
        </Btn>
      </div>

      {/* Loading state */}
      {loading && tools.length === 0 && (
        <div style={{ textAlign: "center", padding: 48, color: "var(--ink-3)", fontSize: 13 }}>
          Detecting AI tools...
        </div>
      )}

      {/* Summary bar */}
      {installedTools.length > 0 && (
        <div style={{
          padding: "10px 16px",
          marginBottom: 16,
          borderRadius: 10,
          background: "color-mix(in oklch, var(--green) 8%, var(--bg-1))",
          border: "1px solid color-mix(in oklch, var(--green) 20%, transparent)",
          fontSize: 13,
          color: "var(--ink-1)",
          display: "flex",
          alignItems: "center",
          gap: 8,
        }}>
          <Icon name="shield" size={15} color="var(--green)" />
          <span>
            Found <strong>{installedTools.length}</strong> AI tool{installedTools.length !== 1 ? "s" : ""} on this Mac
            {" "}&middot;{" "}
            <strong>{activeCount}</strong> active now
          </span>
        </div>
      )}

      <PermissionBanner />

      {/* Tool cards */}
      {installedTools.length > 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {installedTools.map((tool) => (
            <ToolCard key={tool.name} tool={tool} navigate={navigate} onRefresh={fetchTools} />
          ))}
        </div>
      )}

      {/* Empty state */}
      {!loading && installedTools.length === 0 && (
        <EmptyState onRefresh={handleRefresh} />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// ToolCard
// ---------------------------------------------------------------------------

function ToolCard({
  tool,
  navigate,
  onRefresh,
}: {
  tool: DetectedToolStats;
  navigate: ReturnType<typeof useNavigate>;
  onRefresh: () => void;
}) {
  const hasMcp = tool.mcp_servers.length > 0;

  const handleProtect = async (serverName: string) => {
    try {
      await invoke("wrap_server", { client: tool.name, server: serverName });
      onRefresh();
    } catch (e) {
      console.error("Failed to wrap server:", e);
    }
  };

  return (
    <div
      style={{
        background: "var(--bg-1)",
        border: "1px solid var(--line)",
        borderRadius: "var(--radius-lg, 12px)",
        padding: 20,
        transition: "border-color 0.15s ease",
      }}
      onMouseEnter={(e) => { (e.currentTarget as HTMLDivElement).style.borderColor = "var(--line-strong)"; }}
      onMouseLeave={(e) => { (e.currentTarget as HTMLDivElement).style.borderColor = "var(--line)"; }}
    >
      {/* Header row: icon + name + status badge */}
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
        <div style={{
          width: 40, height: 40, borderRadius: 9,
          background: "var(--bg-2)", border: "1px solid var(--line)",
          display: "grid", placeItems: "center",
          color: tool.running ? "var(--accent)" : "var(--ink-3)",
          flexShrink: 0,
        }}>
          <Rook size={22} color="currentColor" />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 14, fontWeight: 600, color: "var(--ink-0)" }}>
            {tool.display_name}
          </div>
          <div style={{ fontSize: 12, color: "var(--ink-3)" }}>
            {tool.description}
          </div>
        </div>
        <StatusBadge running={tool.running} />
      </div>

      {/* Stats rows */}
      <div style={{ display: "flex", flexDirection: "column", gap: 6, marginBottom: 16 }}>
        <StatsRow
          label="Process Monitoring"
          value={
            tool.running ? (
              <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                <Dot color="var(--green)" size={7} pulse />
                <span>Watching (PID {tool.pid}{tool.children_count > 0 ? ` + ${tool.children_count} children` : ""})</span>
              </span>
            ) : (
              <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                <Dot color="var(--ink-3)" size={7} />
                <span>Not running</span>
              </span>
            )
          }
        />

        {tool.running && (
          <>
            <StatsRow
              label="Memory"
              value={formatBytes(tool.memory_bytes)}
            />
            <StatsRow
              label="Disk I/O"
              value={`${formatBytes(tool.disk_read_bytes)} read · ${formatBytes(tool.disk_written_bytes)} written`}
            />
          </>
        )}

        {!tool.running && tool.last_active && (
          <StatsRow
            label="Last active"
            value={formatTimestamp(tool.last_active)}
          />
        )}

        {/* MCP Servers section */}
        {!hasMcp && (
          <StatsRow
            label="MCP Servers"
            value={
              <span style={{ color: "var(--ink-3)" }}>
                None detected
              </span>
            }
          />
        )}
      </div>

      {/* MCP server list */}
      {hasMcp && (
        <div style={{ marginBottom: 16 }}>
          <div style={{
            fontSize: 12, fontFamily: "var(--font-mono)", color: "var(--ink-3)",
            marginBottom: 8,
          }}>
            MCP Servers ({tool.mcp_servers.length}):
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            {tool.mcp_servers.map((srv) => (
              <McpServerRow key={srv.name} server={srv} onProtect={handleProtect} />
            ))}
          </div>
        </div>
      )}

      {/* Action buttons */}
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        {tool.running && (
          <Btn kind="soft" size="sm" onClick={() => navigate(`/tools/${encodeURIComponent(tool.name)}/activity`)}>
            View Activity
          </Btn>
        )}
        {!tool.running && (
          <Btn kind="soft" size="sm" onClick={() => navigate("/activity")}>View History</Btn>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// StatusBadge
// ---------------------------------------------------------------------------

function StatusBadge({ running }: { running: boolean }) {
  return (
    <div style={{
      display: "inline-flex", alignItems: "center", gap: 6,
      fontSize: 12, fontWeight: 500, flexShrink: 0,
    }}>
      <Dot
        color={running ? "var(--green)" : "var(--ink-3)"}
        size={7}
        pulse={running}
      />
      <span style={{ color: running ? "var(--green)" : "var(--ink-3)" }}>
        {running ? "Active" : "Not Running"}
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// StatsRow
// ---------------------------------------------------------------------------

function StatsRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div style={{
      display: "flex", justifyContent: "space-between", alignItems: "center",
      fontSize: 12, fontFamily: "var(--font-mono)",
    }}>
      <span style={{ color: "var(--ink-3)" }}>{label}</span>
      <span style={{ color: "var(--ink-1)" }}>{value}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// McpServerRow
// ---------------------------------------------------------------------------

function McpServerRow({
  server,
  onProtect,
}: {
  server: McpServerInfo;
  onProtect: (name: string) => void;
}) {
  const isWrapped = server.wrapped;
  const dotColor = isWrapped ? "var(--green)" : "var(--amber)";

  return (
    <div style={{
      display: "flex", alignItems: "center", gap: 8,
      fontSize: 12, fontFamily: "var(--font-mono)",
      padding: "4px 8px",
      background: "var(--bg-2)",
      borderRadius: 6,
    }}>
      <Dot color={dotColor} size={6} />
      <span style={{ color: "var(--ink-1)", flex: 1 }}>{server.name}</span>
      {isWrapped ? (
        <span style={{ color: "var(--ink-2)" }}>
          Wrapped &middot; {server.tool_calls_today} tool call{server.tool_calls_today !== 1 ? "s" : ""} today
        </span>
      ) : (
        <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
          <span style={{ color: "var(--amber)" }}>Unwrapped</span>
          <Btn kind="accent" size="sm" onClick={() => onProtect(server.name)} style={{ fontSize: 11, padding: "2px 8px" }}>
            Protect
          </Btn>
        </span>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// EmptyState
// ---------------------------------------------------------------------------

const SUPPORTED_TOOLS = [
  { name: "Claude Desktop", description: "Anthropic's desktop app for Claude" },
  { name: "Cursor", description: "AI-first code editor" },
  { name: "VS Code", description: "With MCP or Copilot extensions" },
  { name: "Windsurf", description: "Codeium's AI editor" },
  { name: "Claude Code", description: "Anthropic's CLI coding agent" },
  { name: "Codex", description: "OpenAI's AI coding app" },
];

function EmptyState({ onRefresh }: { onRefresh: () => void }) {
  return (
    <div style={{ textAlign: "center", padding: "48px 0" }}>
      <div style={{ marginBottom: 16 }}>
        <Rook size={48} color="var(--ink-3)" />
      </div>
      <div style={{ fontSize: 18, fontWeight: 600, color: "var(--ink-0)", marginBottom: 8 }}>
        No AI tools found on this Mac
      </div>
      <div style={{ fontSize: 13, color: "var(--ink-2)", marginBottom: 24, maxWidth: 400, margin: "0 auto 24px" }}>
        RookBot monitors AI coding tools at the OS level.
        Install one of the supported tools to get started.
      </div>

      <div style={{
        textAlign: "left",
        maxWidth: 400,
        margin: "0 auto 24px",
        background: "var(--bg-1)",
        border: "1px solid var(--line)",
        borderRadius: "var(--radius-lg, 12px)",
        padding: 16,
      }}>
        {SUPPORTED_TOOLS.map((t, i) => (
          <div
            key={t.name}
            style={{
              display: "flex", alignItems: "center", gap: 12,
              padding: "8px 0",
              borderTop: i > 0 ? "1px solid var(--line)" : "none",
            }}
          >
            <Rook size={16} color="var(--ink-3)" />
            <div>
              <div style={{ fontSize: 13, fontWeight: 500, color: "var(--ink-0)" }}>{t.name}</div>
              <div style={{ fontSize: 11, color: "var(--ink-3)" }}>{t.description}</div>
            </div>
          </div>
        ))}
      </div>

      <Btn kind="soft" size="md" icon="refresh" onClick={onRefresh}>Refresh</Btn>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  const val = bytes / Math.pow(1024, i);
  return `${val < 10 ? val.toFixed(1) : Math.round(val)} ${units[i]}`;
}

function formatTimestamp(isoString: string): string {
  const date = new Date(isoString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

  if (diffDays === 0) {
    return `Today at ${date.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" })}`;
  }
  if (diffDays === 1) {
    return `Yesterday at ${date.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" })}`;
  }
  return date.toLocaleDateString(undefined, { month: "short", day: "numeric" }) +
    ` at ${date.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" })}`;
}
