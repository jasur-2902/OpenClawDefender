import React from "react";

export interface SectionTitleProps {
  children: React.ReactNode;
  sub?: React.ReactNode;
}

export const SectionTitle: React.FC<SectionTitleProps> = ({ children, sub }) => (
  <div style={{ marginBottom: 22 }}>
    <h1
      style={{
        margin: 0,
        fontSize: 26,
        fontWeight: 700,
        letterSpacing: -0.5,
        color: "var(--ink-0)",
      }}
    >
      {children}
    </h1>
    {sub && <div style={{ marginTop: 6, fontSize: 14, color: "var(--ink-2)" }}>{sub}</div>}
  </div>
);
