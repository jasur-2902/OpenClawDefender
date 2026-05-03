import React, { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Icon, Dot } from "./design";

/* ── Types ──────────────────────────────────────────────────────── */

export interface ScanResult {
  toolsFound: number;
  serversFound: number;
  unwrappedCount: number;
  errors: { toolName: string; message: string }[];
}

export interface ScanChecklistProps {
  onComplete: (result: ScanResult) => void;
}

type CheckStatus = "waiting" | "checking" | "found" | "not_found" | "error";

interface ToolCheckState {
  name: string;
  configDir: string;
  status: CheckStatus;
  serverCount?: number;
  errorMessage?: string;
}

/* ── Backend response shape (from detect_mcp_clients) ─────────── */

interface McpClientResult {
  name: string;
  display_name: string;
  config_path: string;
  detected: boolean;
  servers_count: number;
}

/* ── Static tool metadata (display dirs shown during scan) ─────── */

const TOOL_DEFAULTS: { id: string; name: string; configDir: string }[] = [
  { id: "claude",      name: "Claude Desktop", configDir: "~/Library/Application Support/Claude/" },
  { id: "cursor",      name: "Cursor",         configDir: "~/.cursor/" },
  { id: "vscode",      name: "VS Code",        configDir: "~/.vscode/" },
  { id: "windsurf",    name: "Windsurf",       configDir: "~/.codeium/windsurf/" },
  { id: "claude_code", name: "Claude Code",    configDir: "~/.claude/" },
];

/* ── Helpers ────────────────────────────────────────────────────── */

/** Returns a promise that resolves after `ms` milliseconds. */
const delay = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** Extracts the directory portion of a config file path for display. */
function configDirFromPath(fullPath: string): string {
  const home = fullPath.replace(/^\/Users\/[^/]+/, "~");
  const lastSlash = home.lastIndexOf("/");
  return lastSlash > 0 ? home.slice(0, lastSlash + 1) : home;
}

/* ── Row sub-component (not exported) ──────────────────────────── */

interface ScanChecklistRowProps {
  name: string;
  configDir: string;
  status: CheckStatus;
  serverCount?: number;
  errorMessage?: string;
}

const ScanChecklistRow: React.FC<ScanChecklistRowProps> = ({
  name,
  configDir,
  status,
  serverCount,
  errorMessage,
}) => {
  const isActive = status !== "waiting";

  /* Left icon */
  let leftIcon: React.ReactNode;
  switch (status) {
    case "waiting":
      leftIcon = <Dot color="var(--ink-3)" size={8} />;
      break;
    case "checking":
      leftIcon = (
        <span className="cd-spin" style={{ display: "inline-flex", lineHeight: 0 }}>
          <Dot color="var(--accent)" size={8} pulse />
        </span>
      );
      break;
    case "found":
      leftIcon = <Icon name="check" color="var(--green)" size={14} />;
      break;
    case "not_found":
      leftIcon = <Icon name="x" color="var(--ink-3)" size={14} />;
      break;
    case "error":
      leftIcon = <Icon name="alert" color="var(--amber)" size={14} />;
      break;
  }

  /* Name color */
  const nameColor =
    status === "waiting" || status === "not_found"
      ? "var(--ink-3)"
      : status === "error"
        ? "var(--ink-2)"
        : "var(--ink-0)";

  /* Path color */
  const pathColor =
    status === "waiting" || status === "not_found"
      ? "var(--ink-3)"
      : "var(--ink-2)";

  /* Right side content */
  let rightContent: React.ReactNode = null;
  switch (status) {
    case "checking":
      rightContent = (
        <span style={{ fontSize: 11, color: "var(--ink-3)" }}>Checking...</span>
      );
      break;
    case "found":
      rightContent = (
        <span style={{ fontSize: 11, fontWeight: 600, color: "var(--green)" }}>
          {serverCount} {serverCount === 1 ? "server" : "servers"}
        </span>
      );
      break;
    case "not_found":
      rightContent = (
        <span style={{ fontSize: 11, color: "var(--ink-3)" }}>Not installed</span>
      );
      break;
    case "error":
      rightContent = (
        <span style={{ fontSize: 11, color: "var(--amber)" }}>
          {errorMessage || "Could not read config"}
        </span>
      );
      break;
  }

  return (
    <div
      role="listitem"
      style={{
        display: "flex",
        alignItems: "flex-start",
        gap: 10,
        padding: "8px 0",
        opacity: isActive ? 1 : 0.4,
        transition: "opacity 0.3s ease",
      }}
    >
      {/* Left icon — fixed width to align rows */}
      <div style={{ width: 16, minHeight: 16, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, marginTop: 1 }}>
        {leftIcon}
      </div>

      {/* Name + path */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 12.5, fontWeight: 600, color: nameColor, transition: "color 0.3s ease" }}>
          {name}
        </div>
        <div
          style={{
            fontSize: 11,
            fontFamily: "var(--font-mono)",
            color: pathColor,
            transition: "color 0.3s ease",
            marginTop: 1,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {configDir}
        </div>
      </div>

      {/* Right side */}
      {rightContent && (
        <div style={{ flexShrink: 0, display: "flex", alignItems: "center", marginTop: 2 }}>
          {rightContent}
        </div>
      )}
    </div>
  );
};

/* ── Main component ─────────────────────────────────────────────── */

export const ScanChecklist: React.FC<ScanChecklistProps> = ({ onComplete }) => {
  const [tools, setTools] = useState<ToolCheckState[]>(
    TOOL_DEFAULTS.map((t) => ({
      name: t.name,
      configDir: t.configDir,
      status: "waiting" as CheckStatus,
    })),
  );

  const calledComplete = useRef(false);

  useEffect(() => {
    let cancelled = false;

    async function runScan() {
      /* 1. Fire the single backend call immediately */
      const backendPromise = invoke<McpClientResult[]>("detect_mcp_clients");

      let backendResults: McpClientResult[] | null = null;
      let backendError: string | null = null;

      try {
        backendResults = await backendPromise;
      } catch (err: unknown) {
        backendError = err instanceof Error ? err.message : String(err);
      }

      if (cancelled) return;

      /* 2. Animate rows sequentially with staggered timing */
      const STAGGER_MS = 400;
      const MIN_CHECK_DISPLAY_MS = 300;
      const errors: { toolName: string; message: string }[] = [];
      let toolsFound = 0;
      let serversFound = 0;

      for (let i = 0; i < TOOL_DEFAULTS.length; i++) {
        if (cancelled) return;

        /* Transition row to "checking" */
        setTools((prev) =>
          prev.map((t, idx) => (idx === i ? { ...t, status: "checking" } : t)),
        );

        /* Wait the minimum display time */
        const checkStart = Date.now();
        await delay(MIN_CHECK_DISPLAY_MS);

        /* Resolve this row's result */
        if (backendError) {
          /* Entire backend call failed — mark all remaining as error */
          if (!cancelled) {
            setTools((prev) =>
              prev.map((t, idx) =>
                idx === i ? { ...t, status: "error", errorMessage: backendError! } : t,
              ),
            );
            errors.push({ toolName: TOOL_DEFAULTS[i].name, message: backendError });
          }
        } else if (backendResults) {
          const result = backendResults.find((r) => r.name === TOOL_DEFAULTS[i].id);
          if (!cancelled) {
            if (result?.detected) {
              const dir = configDirFromPath(result.config_path);
              setTools((prev) =>
                prev.map((t, idx) =>
                  idx === i
                    ? { ...t, status: "found", serverCount: result.servers_count, configDir: dir }
                    : t,
                ),
              );
              toolsFound++;
              serversFound += result.servers_count;
            } else {
              setTools((prev) =>
                prev.map((t, idx) =>
                  idx === i ? { ...t, status: "not_found" } : t,
                ),
              );
            }
          }
        }

        /* Stagger before next row (skip after the last one) */
        if (i < TOOL_DEFAULTS.length - 1) {
          const elapsed = Date.now() - checkStart;
          const remaining = STAGGER_MS - elapsed;
          if (remaining > 0) await delay(remaining);
        }
      }

      /* 3. Report completion */
      if (!cancelled && !calledComplete.current) {
        calledComplete.current = true;
        onComplete({
          toolsFound,
          serversFound,
          unwrappedCount: 0, // determined later by the parent
          errors,
        });
      }
    }

    runScan();

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div style={{ padding: "16px 0" }}>
      {/* Header */}
      <div style={{ marginBottom: 16 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: "var(--ink-0)" }}>
          Scanning your system...
        </div>
        <div style={{ fontSize: 12, color: "var(--ink-2)", marginTop: 2 }}>
          Looking for AI tools with MCP server configurations.
        </div>
      </div>

      {/* Checklist */}
      <div role="list" aria-live="polite">
        {tools.map((tool) => (
          <ScanChecklistRow
            key={tool.name}
            name={tool.name}
            configDir={tool.configDir}
            status={tool.status}
            serverCount={tool.serverCount}
            errorMessage={tool.errorMessage}
          />
        ))}
      </div>
    </div>
  );
};
