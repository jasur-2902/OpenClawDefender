import React from "react";

export interface KVProps {
  k: string;
  v: React.ReactNode;
  mono?: boolean;
}

export const KV: React.FC<KVProps> = ({ k, v, mono = false }) => (
  <div
    style={{
      display: "flex",
      justifyContent: "space-between",
      alignItems: "baseline",
      padding: "8px 0",
      borderBottom: "1px solid var(--line-soft)",
      gap: 16,
    }}
  >
    <span style={{ color: "var(--ink-2)", fontSize: 12 }}>{k}</span>
    <span
      style={{
        fontFamily: mono ? "var(--font-mono)" : "var(--font-ui)",
        fontSize: 12,
        color: "var(--ink-0)",
        textAlign: "right",
      }}
    >
      {v}
    </span>
  </div>
);
