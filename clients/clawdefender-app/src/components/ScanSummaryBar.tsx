import React, { useState } from "react";
import { Icon, Btn } from "./design";

interface ScanToolError {
  toolName: string;
  message: string;
}

export interface ScanSummaryBarProps {
  toolsFound: number;
  serversFound: number;
  unwrappedCount: number;
  errors: ScanToolError[];
  onWrapAll?: () => void;
  onViewErrors?: () => void;
}

export const ScanSummaryBar: React.FC<ScanSummaryBarProps> = ({
  toolsFound,
  serversFound,
  unwrappedCount,
  errors,
  onWrapAll,
}) => {
  const [showErrors, setShowErrors] = useState(false);

  // Not rendered if zero tools found and no errors (empty state handles this)
  if (toolsFound === 0 && errors.length === 0) return null;

  const hasErrors = errors.length > 0;

  if (hasErrors) {
    return (
      <div style={{ marginBottom: 14 }}>
        <div
          style={{
            padding: 12,
            borderRadius: 10,
            display: "flex",
            alignItems: "center",
            gap: 12,
            background: "oklch(from var(--amber) l c h / 0.08)",
            border: "1px solid color-mix(in oklch, var(--amber) 30%, transparent)",
          }}
        >
          <Icon name="alert" size={16} color="var(--amber)" />
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 12.5, fontWeight: 600, color: "var(--ink-0)" }}>
              Scan completed with errors
            </div>
            <div style={{ fontSize: 12.5, color: "var(--ink-2)" }}>
              Some config files could not be read
            </div>
          </div>
          <Btn kind="ghost" size="sm" onClick={() => setShowErrors((v) => !v)}>
            {showErrors ? "Hide" : "Details"}
          </Btn>
        </div>
        {showErrors && (
          <div
            style={{
              marginTop: 6,
              padding: 12,
              borderRadius: 8,
              background: "var(--bg-1)",
              border: "1px solid var(--line)",
              display: "flex",
              flexDirection: "column",
              gap: 6,
            }}
          >
            {errors.map((err, i) => (
              <div key={i} style={{ fontSize: 12, display: "flex", gap: 8 }}>
                <span style={{ fontWeight: 600, color: "var(--ink-1)" }}>{err.toolName}</span>
                <span style={{ color: "var(--ink-3)" }}>{err.message}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    );
  }

  return (
    <div
      style={{
        padding: 12,
        marginBottom: 14,
        borderRadius: 10,
        display: "flex",
        alignItems: "center",
        gap: 12,
        background: "var(--green-soft)",
        border: "1px solid color-mix(in oklch, var(--green) 30%, transparent)",
      }}
    >
      <Icon name="check" size={16} color="var(--green)" />
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: 12.5, fontWeight: 600, color: "var(--ink-0)" }}>
          Found {toolsFound} tool{toolsFound !== 1 ? "s" : ""} with {serversFound} MCP server{serversFound !== 1 ? "s" : ""}
        </div>
        {unwrappedCount > 0 && (
          <div style={{ fontSize: 12.5, color: "var(--ink-2)" }}>
            {unwrappedCount} server{unwrappedCount !== 1 ? "s" : ""} need wrapping
          </div>
        )}
      </div>
      {unwrappedCount > 0 && onWrapAll && (
        <Btn kind="primary" size="sm" onClick={onWrapAll}>Wrap all</Btn>
      )}
    </div>
  );
};
