import { useEffect, useState, useCallback, useMemo } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { Icon, Dot, Btn, SectionTitle } from "../components/design";
import type { ToolLiveActivity } from "../types";

const REFRESH_INTERVAL = 5_000;

const TOOL_DISPLAY: Record<string, string> = {
  claude: "Claude Desktop",
  cursor: "Cursor",
  vscode: "VS Code",
  windsurf: "Windsurf",
  claude_code: "Claude Code",
  codex: "Codex",
};

export function ToolActivity() {
  const { name } = useParams<{ name: string }>();
  const navigate = useNavigate();
  const toolName = name ?? "";
  const displayName = TOOL_DISPLAY[toolName] ?? toolName;

  const [activity, setActivity] = useState<ToolLiveActivity | null>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [tab, setTab] = useState<"network" | "files">("network");

  const fetchActivity = useCallback(async () => {
    try {
      const result = await invoke<ToolLiveActivity>("get_tool_live_activity", { toolName });
      setActivity(result);
    } catch (e) {
      console.error("Failed to fetch live activity:", e);
    }
    setLoading(false);
  }, [toolName]);

  useEffect(() => {
    fetchActivity();
    const interval = setInterval(fetchActivity, REFRESH_INTERVAL);
    return () => clearInterval(interval);
  }, [fetchActivity]);

  const filteredFiles = useMemo(() => {
    if (!activity) return [];
    const lower = search.toLowerCase();
    return activity.open_files.filter((f) =>
      !search || f.path.toLowerCase().includes(lower)
    );
  }, [activity, search]);

  const filteredNets = useMemo(() => {
    if (!activity) return [];
    const lower = search.toLowerCase();
    return activity.network_connections.filter((n) =>
      !search || n.connection.toLowerCase().includes(lower) || n.state.toLowerCase().includes(lower)
    );
  }, [activity, search]);

  return (
    <div style={{ display: "grid", gridTemplateRows: "auto auto 1fr", height: "100%" }}>
      {/* Header */}
      <div style={{ padding: "16px 24px 0" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
          <button
            onClick={() => navigate("/tools")}
            style={{
              background: "none", border: "none", cursor: "pointer",
              color: "var(--ink-3)", fontSize: 12, padding: 0,
            }}
          >
            My Tools
          </button>
          <span style={{ color: "var(--ink-3)", fontSize: 12 }}>/</span>
          <span style={{ color: "var(--ink-2)", fontSize: 12 }}>{displayName}</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <SectionTitle sub={`Live activity for ${displayName} processes`}>
            {displayName} Activity
          </SectionTitle>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            {activity && (
              <span style={{ fontSize: 12, color: "var(--ink-3)", fontFamily: "var(--font-mono)" }}>
                {activity.pids.length} process{activity.pids.length !== 1 ? "es" : ""}
                {" · PID "}
                {activity.pids.slice(0, 3).join(", ")}
                {activity.pids.length > 3 ? "..." : ""}
              </span>
            )}
            <Btn kind="ghost" size="sm" icon="refresh" onClick={fetchActivity}>Refresh</Btn>
          </div>
        </div>
      </div>

      {/* Toolbar */}
      <div style={{
        padding: "12px 24px",
        borderBottom: "1px solid var(--line)",
        display: "flex",
        alignItems: "center",
        gap: 10,
      }}>
        <Dot color="var(--green)" size={7} pulse />
        <span style={{ fontSize: 13, fontWeight: 600 }}>
          {tab === "network" ? filteredNets.length : filteredFiles.length} {tab === "network" ? "connections" : "files"}
        </span>
        <span style={{ fontSize: 12, color: "var(--ink-3)" }}>· live</span>

        <div style={{ marginLeft: "auto", display: "flex", gap: 8, alignItems: "center" }}>
          <input
            placeholder="Search…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{
              background: "var(--bg-2)", border: "none", borderRadius: 6,
              padding: "5px 10px", fontSize: 12.5, color: "var(--ink-0)",
              width: 200, outline: "none",
            }}
          />
          <TabPill label="Network" active={tab === "network"} count={activity?.network_connections.length ?? 0} onClick={() => setTab("network")} />
          <TabPill label="Files" active={tab === "files"} count={activity?.open_files.length ?? 0} onClick={() => setTab("files")} />
        </div>
      </div>

      {/* Content */}
      <div className="cd-scroll" style={{ overflowY: "auto" }}>
        {loading && (
          <div style={{ padding: 40, textAlign: "center", color: "var(--ink-3)", fontSize: 13 }}>
            Loading activity...
          </div>
        )}

        {!loading && tab === "network" && (
          <NetworkTable connections={filteredNets} />
        )}

        {!loading && tab === "files" && (
          <FileTable files={filteredFiles} />
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tab pill
// ---------------------------------------------------------------------------

function TabPill({ label, active, count, onClick }: {
  label: string;
  active: boolean;
  count: number;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: "5px 10px",
        borderRadius: 6,
        fontSize: 12,
        background: active ? "var(--accent-soft)" : "var(--bg-2)",
        color: active ? "var(--accent)" : "var(--ink-2)",
        border: "none",
        cursor: "pointer",
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
      }}
    >
      {label}
      <span style={{
        fontSize: 10,
        padding: "1px 5px",
        borderRadius: 4,
        background: active ? "var(--accent)" : "var(--bg-1)",
        color: active ? "white" : "var(--ink-3)",
      }}>
        {count}
      </span>
    </button>
  );
}

// ---------------------------------------------------------------------------
// Network table
// ---------------------------------------------------------------------------

function NetworkTable({ connections }: { connections: ToolLiveActivity["network_connections"] }) {
  if (connections.length === 0) {
    return (
      <div style={{ padding: 60, textAlign: "center", color: "var(--ink-3)", fontSize: 13 }}>
        No network connections detected
      </div>
    );
  }

  return (
    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}>
      <thead>
        <tr style={{ borderBottom: "1px solid var(--line)", position: "sticky", top: 0, background: "var(--bg-0)" }}>
          <Th style={{ width: 30 }} />
          <Th>Remote Address</Th>
          <Th style={{ width: 80 }}>Protocol</Th>
          <Th style={{ width: 120 }}>State</Th>
        </tr>
      </thead>
      <tbody>
        {connections.map((n, i) => {
          const stateColor = n.state === "ESTABLISHED" ? "var(--green)"
            : n.state === "LISTEN" ? "var(--accent)"
            : n.state === "CLOSE_WAIT" ? "var(--amber)"
            : "var(--ink-3)";

          return (
            <tr
              key={i}
              style={{ borderBottom: "1px solid var(--line)" }}
              onMouseEnter={(e) => { e.currentTarget.style.background = "var(--bg-1)"; }}
              onMouseLeave={(e) => { e.currentTarget.style.background = ""; }}
            >
              <td style={{ padding: "8px 12px" }}>
                <Dot color={stateColor} size={6} />
              </td>
              <td style={{ padding: "8px 4px", fontFamily: "var(--font-mono)", color: "var(--ink-0)" }}>
                {n.connection}
              </td>
              <td style={{ padding: "8px 4px", fontFamily: "var(--font-mono)", color: "var(--ink-3)" }}>
                {n.protocol}
              </td>
              <td style={{ padding: "8px 4px" }}>
                <span style={{
                  fontSize: 11, fontFamily: "var(--font-mono)",
                  color: stateColor, fontWeight: 500,
                }}>
                  {n.state}
                </span>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

// ---------------------------------------------------------------------------
// File table
// ---------------------------------------------------------------------------

function FileTable({ files }: { files: ToolLiveActivity["open_files"] }) {
  if (files.length === 0) {
    return (
      <div style={{ padding: 60, textAlign: "center", color: "var(--ink-3)", fontSize: 13 }}>
        No open files detected
      </div>
    );
  }

  return (
    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}>
      <thead>
        <tr style={{ borderBottom: "1px solid var(--line)", position: "sticky", top: 0, background: "var(--bg-0)" }}>
          <Th style={{ width: 30 }} />
          <Th>Path</Th>
          <Th style={{ width: 80 }}>Type</Th>
        </tr>
      </thead>
      <tbody>
        {files.map((f, i) => {
          const icon = f.fd_type === "DIR" ? "folder" : "file";
          return (
            <tr
              key={i}
              style={{ borderBottom: "1px solid var(--line)" }}
              onMouseEnter={(e) => { e.currentTarget.style.background = "var(--bg-1)"; }}
              onMouseLeave={(e) => { e.currentTarget.style.background = ""; }}
            >
              <td style={{ padding: "8px 12px" }}>
                <Icon name={icon} size={13} color="var(--ink-3)" />
              </td>
              <td style={{
                padding: "8px 4px", fontFamily: "var(--font-mono)", color: "var(--ink-0)",
                overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 0,
              }}>
                {f.path}
              </td>
              <td style={{ padding: "8px 4px", fontFamily: "var(--font-mono)", color: "var(--ink-3)", fontSize: 11 }}>
                {f.fd_type}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

// ---------------------------------------------------------------------------
// Th helper
// ---------------------------------------------------------------------------

function Th({ children, style }: { children?: React.ReactNode; style?: React.CSSProperties }) {
  return (
    <th style={{
      textAlign: "left", padding: "8px 4px", fontSize: 11,
      fontWeight: 600, color: "var(--ink-3)", textTransform: "uppercase",
      letterSpacing: 0.5,
      ...style,
    }}>
      {children}
    </th>
  );
}
