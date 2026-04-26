import { useEffect, useCallback, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { useToolStore } from "../stores/toolStore";
import { useTauriEvent } from "../hooks/useTauriEvent";
import { useToastStore } from "../components/notifications/ToastContainer";
import { Icon, Badge, Btn, Dot, SectionTitle, ChessPiece, capabilityPiece } from "../components/design";
import type { NewToolInfo, ToolCardData, ServerCapabilities } from "../types";

const POLL_INTERVAL = 30_000;

/** Map ServerCapabilities to a string[] for capabilityPiece() */
function capsToStrings(caps: ServerCapabilities): string[] {
  const out: string[] = [];
  if (caps.network_access || caps.can_network) out.push("network");
  if (caps.execute_commands || caps.can_execute) out.push("shell");
  if (caps.read_files || caps.write_files || caps.can_read_files || caps.can_write_files) out.push("filesystem");
  if (caps.browser_access) out.push("api:github");
  if (out.length === 0) out.push("metadata");
  return out;
}

export function MyTools() {
  const navigate = useNavigate();
  const tools = useToolStore((s) => s.tools);
  const newTools = useToolStore((s) => s.newTools);
  const loading = useToolStore((s) => s.loading);
  const fetchTools = useToolStore((s) => s.fetchTools);
  const fetchNewTools = useToolStore((s) => s.fetchNewTools);

  useEffect(() => { fetchTools(); fetchNewTools(); }, [fetchTools, fetchNewTools]);
  useEffect(() => {
    const interval = setInterval(() => { fetchTools(); }, POLL_INTERVAL);
    return () => clearInterval(interval);
  }, [fetchTools]);

  const handleNewTool = useCallback(() => { fetchNewTools(); fetchTools(); }, [fetchNewTools, fetchTools]);
  useTauriEvent<NewToolInfo>("rookbot://new-tool-detected", handleNewTool);

  const unwrappedTools = useMemo(() => tools.filter((t) => !t.wrapped && !t.is_wrapped), [tools]);

  const addToast = useToastStore((s) => s.addToast);
  const handleScan = useCallback(async () => {
    try {
      await fetchTools();
      await fetchNewTools();
      const current = useToolStore.getState().tools;
      if (current.length === 0) {
        addToast({ title: "No MCP tools found. Install Claude Desktop, Cursor, VS Code, or Windsurf first.", severity: "info" });
      } else {
        addToast({ title: `Found ${current.length} tool${current.length !== 1 ? "s" : ""}.`, severity: "success" });
      }
    } catch {
      addToast({ title: "Tool scan failed. Check that the app has file access.", severity: "warning" });
    }
  }, [addToast, fetchTools, fetchNewTools]);

  const isEmpty = !loading && tools.length === 0;

  return (
    <div className="cd-scroll" style={{ padding: 24, maxWidth: 1080, margin: "0 auto", overflowY: "auto", height: "100%" }}>
      <SectionTitle sub="Each MCP server is wrapped at the eBPF layer.">My Tools</SectionTitle>

      {/* Unwrapped banner */}
      {unwrappedTools.length > 0 && (
        <div style={{
          padding: 12, marginBottom: 14, borderRadius: 10, display: "flex", alignItems: "center", gap: 12,
          background: "var(--accent-soft)", border: "1px solid var(--accent-line)",
        }}>
          <Icon name="shield" size={16} color="var(--accent)" />
          <div style={{ flex: 1, fontSize: 12.5 }}>
            <strong>{unwrappedTools.length} unwrapped server{unwrappedTools.length !== 1 ? "s" : ""}</strong>{" "}
            <span style={{ color: "var(--ink-2)" }}>running without protection</span>
          </div>
          <Btn kind="primary" size="sm">Wrap now</Btn>
        </div>
      )}

      {/* New tool banner */}
      {newTools.length > 0 && (
        <div style={{
          padding: 12, marginBottom: 14, borderRadius: 10, display: "flex", alignItems: "center", gap: 12,
          background: "var(--green-soft)", border: "1px solid color-mix(in oklch, var(--green) 30%, transparent)",
        }}>
          <Icon name="sparkles" size={16} color="var(--green)" />
          <div style={{ flex: 1, fontSize: 12.5, color: "var(--ink-1)" }}>
            <strong>{newTools.length} new tool{newTools.length !== 1 ? "s" : ""} detected</strong>
          </div>
          <Btn kind="accent" size="sm" onClick={() => navigate("/tools")}>View</Btn>
        </div>
      )}

      {/* Loading skeleton */}
      {loading && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12 }}>
          {[1, 2, 3, 4].map((i) => (
            <div key={i} style={{ padding: 16, background: "var(--bg-1)", border: "1px solid var(--line)", borderRadius: 12 }}>
              <div style={{ height: 40, width: 40, borderRadius: 9, background: "var(--bg-3)" }} className="cd-pulse" />
              <div style={{ height: 14, width: 120, borderRadius: 4, background: "var(--bg-3)", marginTop: 12 }} className="cd-pulse" />
              <div style={{ height: 10, width: 80, borderRadius: 4, background: "var(--bg-3)", marginTop: 8 }} className="cd-pulse" />
            </div>
          ))}
        </div>
      )}

      {/* Empty state */}
      {isEmpty && (
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "60px 0", textAlign: "center" }}>
          <Icon name="tools" size={40} color="var(--ink-3)" />
          <h2 style={{ fontSize: 15, fontWeight: 600, color: "var(--ink-0)", marginTop: 16, marginBottom: 4 }}>No tools found</h2>
          <p style={{ fontSize: 12.5, color: "var(--ink-2)", maxWidth: 340 }}>
            I don't see any AI tools installed. I support Claude Desktop, Cursor, VS Code, and Windsurf.
          </p>
          <Btn kind="primary" onClick={handleScan} style={{ marginTop: 16 }}>Scan for tools</Btn>
        </div>
      )}

      {/* Tool grid */}
      {!loading && tools.length > 0 && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12 }}>
          {tools.map((tool) => (
            <ToolTile key={`${tool.client_name}:${tool.server_name}`} tool={tool} onClick={() => navigate(`/tools/${encodeURIComponent(tool.server_name)}`)} />
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tool tile component (matches design handoff)
// ---------------------------------------------------------------------------

function ToolTile({ tool, onClick }: { tool: ToolCardData; onClick: () => void }) {
  const capStrings = capsToStrings(tool.capabilities);
  const piece = capabilityPiece(capStrings);
  const trustColor = tool.trust_level === "trusted" ? "var(--green)"
    : tool.trust_level === "untrusted" || tool.trust_level === "blocked" ? "var(--red)"
    : "var(--amber)";

  return (
    <button
      onClick={onClick}
      style={{
        textAlign: "left", padding: 16, cursor: "pointer",
        background: "var(--bg-1)", border: "1px solid var(--line)",
        borderRadius: "var(--radius-lg, 12px)",
      }}
      onMouseEnter={(e) => { (e.currentTarget as HTMLButtonElement).style.borderColor = "var(--line-strong)"; }}
      onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.borderColor = "var(--line)"; }}
    >
      {/* Header: chess piece + name + trust badge */}
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
        <div
          title={piece.reason}
          style={{
            width: 40, height: 40, borderRadius: 9,
            background: "var(--bg-2)", border: "1px solid var(--line)",
            display: "grid", placeItems: "center",
            color: trustColor, flexShrink: 0,
          }}
        >
          <ChessPiece kind={piece.kind} color="white" size={26} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 13.5, fontWeight: 600, color: "var(--ink-0)" }}>{tool.display_name || tool.server_name}</div>
          <div style={{ fontSize: 10.5, color: "var(--ink-3)", fontFamily: "var(--font-mono)" }}>{tool.client_name}</div>
        </div>
        <Badge color={trustColor}>{tool.trust_level}</Badge>
      </div>

      {/* Stats row */}
      <div style={{ display: "flex", alignItems: "center", gap: 12, fontSize: 11, fontFamily: "var(--font-mono)", color: "var(--ink-2)", marginBottom: 12 }}>
        <span><span style={{ color: "var(--ink-3)" }}>events </span>{tool.event_count}</span>
        <span>
          <span style={{ color: "var(--ink-3)" }}>anomaly </span>
          <span style={{ color: tool.anomaly_score > 0.6 ? "var(--red)" : tool.anomaly_score > 0.3 ? "var(--amber)" : "var(--green)" }}>
            {tool.anomaly_score.toFixed(2)}
          </span>
        </span>
        <span style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center", gap: 6 }}>
          <Dot color={(tool.wrapped || tool.is_wrapped) ? "var(--green)" : "var(--red)"} size={6} />
          {(tool.wrapped || tool.is_wrapped) ? "wrapped" : "exposed"}
        </span>
      </div>

      {/* Capability chips */}
      <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
        {capStrings.map((c) => (
          <span key={c} style={{
            fontFamily: "var(--font-mono)", fontSize: 10, padding: "2px 6px",
            background: "var(--bg-2)", color: "var(--ink-2)", borderRadius: 3,
          }}>
            {c}
          </span>
        ))}
      </div>
    </button>
  );
}
