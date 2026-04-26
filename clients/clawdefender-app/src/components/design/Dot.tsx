import React from "react";

export interface DotProps {
  color?: string;
  size?: number;
  pulse?: boolean;
  style?: React.CSSProperties;
}

export const Dot: React.FC<DotProps> = ({
  color = "var(--accent)",
  size = 8,
  pulse = false,
  style,
}) => (
  <span
    style={{
      display: "inline-block",
      width: size,
      height: size,
      borderRadius: 999,
      background: color,
      boxShadow: pulse ? `0 0 0 0 ${color}` : "none",
      position: "relative",
      ...style,
    }}
    className={pulse ? "cd-pulse-dot" : undefined}
  />
);
