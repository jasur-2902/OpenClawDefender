import React from "react";

export interface VerdictPillProps {
  verdict: string;
}

export const VerdictPill: React.FC<VerdictPillProps> = ({ verdict }) => {
  const isBlock = verdict === "BLOCK";
  return (
    <span
      style={{
        fontFamily: "var(--font-mono)",
        fontSize: 10.5,
        fontWeight: 700,
        letterSpacing: 0.6,
        padding: "3px 7px",
        borderRadius: 4,
        color: isBlock ? "var(--red)" : "var(--green)",
        background: isBlock ? "var(--red-soft)" : "var(--green-soft)",
        border: `1px solid color-mix(in oklch, ${isBlock ? "var(--red)" : "var(--green)"} 32%, transparent)`,
      }}
    >
      {verdict}
    </span>
  );
};
