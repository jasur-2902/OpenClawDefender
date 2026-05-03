import React from "react";
import { Rook, Btn } from "./design";

export interface EmptyToolsStateProps {
  onScan: () => void;
  hasScanned: boolean;
}

const SUPPORTED_TOOLS = [
  { name: "Claude Desktop", desc: "Anthropic's desktop app" },
  { name: "Cursor", desc: "AI-first code editor" },
  { name: "VS Code", desc: "With MCP extension" },
  { name: "Windsurf", desc: "Codeium's AI IDE" },
  { name: "Claude Code", desc: "CLI for Claude" },
  { name: "Codex", desc: "OpenAI's AI coding app" },
];

export const EmptyToolsState: React.FC<EmptyToolsStateProps> = ({ onScan, hasScanned }) => {
  if (!hasScanned) {
    return (
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          padding: "60px 0",
          textAlign: "center",
        }}
      >
        <Rook size={40} color="var(--ink-3)" />
        <h2 style={{ fontSize: 15, fontWeight: 600, color: "var(--ink-0)", marginTop: 16, marginBottom: 4 }}>
          No tools found
        </h2>
        <p style={{ fontSize: 12.5, color: "var(--ink-2)", maxWidth: 340 }}>
          I don't see any AI tools installed. I support Claude Desktop, Cursor, VS Code, and Windsurf.
        </p>
        <Btn kind="primary" onClick={onScan} style={{ marginTop: 16 }}>
          Scan for tools
        </Btn>
      </div>
    );
  }

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        padding: "60px 0",
        textAlign: "center",
      }}
    >
      <Rook size={48} color="var(--ink-3)" />
      <h2 style={{ fontSize: 15, fontWeight: 600, color: "var(--ink-0)", marginTop: 16, marginBottom: 4 }}>
        No AI tools found on this Mac
      </h2>
      <p style={{ fontSize: 12.5, color: "var(--ink-2)", maxWidth: 400 }}>
        RookBot monitors MCP servers inside AI coding tools. Install one of the supported tools below, add an MCP server, then scan again.
      </p>

      <div
        style={{
          marginTop: 20,
          background: "var(--bg-1)",
          border: "1px solid var(--line)",
          borderRadius: 10,
          padding: 12,
          display: "flex",
          flexDirection: "column",
          gap: 8,
          width: "100%",
          maxWidth: 380,
          textAlign: "left",
        }}
      >
        {SUPPORTED_TOOLS.map((tool) => (
          <div key={tool.name} style={{ fontSize: 12.5, display: "flex", gap: 6, alignItems: "baseline" }}>
            <span style={{ fontWeight: 600, color: "var(--ink-1)" }}>{tool.name}</span>
            <span style={{ color: "var(--ink-3)" }}>&mdash;</span>
            <span style={{ color: "var(--ink-3)" }}>{tool.desc}</span>
          </div>
        ))}
      </div>

      <Btn kind="primary" onClick={onScan} style={{ marginTop: 20 }}>
        Scan again
      </Btn>
    </div>
  );
};
