import React from "react";

export interface SparklineProps {
  data: number[];
  color?: string;
  width?: number;
  height?: number;
  fill?: boolean;
}

export const Sparkline: React.FC<SparklineProps> = ({
  data,
  color = "var(--accent)",
  width = 120,
  height = 32,
  fill = true,
}) => {
  const max = Math.max(...data, 1);
  const min = Math.min(...data, 0);
  const range = max - min || 1;
  const step = width / (data.length - 1);
  const pts = data.map((v, i) => [
    i * step,
    height - ((v - min) / range) * (height - 4) - 2,
  ]);
  const d = pts
    .map((p, i) => `${i ? "L" : "M"}${p[0].toFixed(1)} ${p[1].toFixed(1)}`)
    .join(" ");
  const fillD = fill ? `${d} L${width} ${height} L0 ${height} Z` : null;

  return (
    <svg width={width} height={height} style={{ display: "block" }}>
      {fillD && <path d={fillD} fill={color} opacity="0.12" />}
      <path
        d={d}
        fill="none"
        stroke={color}
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
};
