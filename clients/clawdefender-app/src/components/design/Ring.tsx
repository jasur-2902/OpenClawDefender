import React from "react";

export interface RingProps {
  value?: number;
  max?: number;
  size?: number;
  stroke?: number;
  color?: string;
  track?: string;
  label?: React.ReactNode;
  sub?: React.ReactNode;
}

export const Ring: React.FC<RingProps> = ({
  value = 0,
  max = 100,
  size = 96,
  stroke: sw = 7,
  color = "var(--accent)",
  track = "var(--bg-3)",
  label,
  sub,
}) => {
  const r = (size - sw) / 2;
  const c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(1, value / max));

  return (
    <div style={{ position: "relative", width: size, height: size }}>
      <svg width={size} height={size} style={{ transform: "rotate(-90deg)" }}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={track} strokeWidth={sw} />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={sw}
          strokeDasharray={c}
          strokeDashoffset={c * (1 - pct)}
          strokeLinecap="round"
          style={{ transition: "stroke-dashoffset 0.6s ease" }}
        />
      </svg>
      <div
        style={{
          position: "absolute",
          inset: 0,
          display: "grid",
          placeItems: "center",
          textAlign: "center",
        }}
      >
        <div>
          <div style={{ fontSize: 22, fontWeight: 600, fontFeatureSettings: '"tnum"' }}>
            {label ?? value}
          </div>
          {sub && (
            <div style={{ fontSize: 10, color: "var(--ink-2)", marginTop: 2 }}>{sub}</div>
          )}
        </div>
      </div>
    </div>
  );
};
