import React from "react";

export interface BadgeProps {
  children: React.ReactNode;
  color?: string;
  soft?: string;
  mono?: boolean;
  style?: React.CSSProperties;
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  color = "var(--ink-2)",
  soft,
  mono = false,
  style,
}) => (
  <span
    style={{
      display: "inline-flex",
      alignItems: "center",
      gap: 5,
      fontFamily: mono ? "var(--font-mono)" : "var(--font-ui)",
      fontSize: 10.5,
      fontWeight: 600,
      letterSpacing: 0.4,
      textTransform: mono ? "none" : "uppercase",
      padding: "3px 7px",
      borderRadius: 4,
      color,
      background: soft || `color-mix(in oklch, ${color} 14%, transparent)`,
      border: `1px solid color-mix(in oklch, ${color} 28%, transparent)`,
      ...style,
    }}
  >
    {children}
  </span>
);
