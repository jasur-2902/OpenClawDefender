import React from "react";

export interface CardProps {
  title?: string;
  action?: React.ReactNode;
  children: React.ReactNode;
  padded?: boolean;
  style?: React.CSSProperties;
}

export const Card: React.FC<CardProps> = ({
  title,
  action,
  children,
  padded = true,
  style,
}) => (
  <div
    style={{
      background: "var(--bg-1)",
      border: "1px solid var(--line)",
      borderRadius: 12,
      overflow: "hidden",
      boxShadow: "0 1px 2px oklch(0 0 0 / 0.04)",
      ...style,
    }}
  >
    {title && (
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "12px 16px",
          borderBottom: "1px solid var(--line-soft)",
        }}
      >
        <div style={{ fontSize: 13, fontWeight: 600, color: "var(--ink-0)" }}>{title}</div>
        {action}
      </div>
    )}
    <div style={{ padding: padded ? 16 : 0 }}>{children}</div>
  </div>
);
