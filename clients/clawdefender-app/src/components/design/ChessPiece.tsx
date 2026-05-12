import React from "react";

export type PieceKind = "king" | "queen" | "rook" | "bishop" | "knight" | "pawn";

export interface ChessPieceProps {
  kind?: PieceKind;
  color?: "white" | "black";
  size?: number;
  style?: React.CSSProperties;
}

const paths: Record<PieceKind, React.ReactNode> = {
  rook: (
    <g>
      <path d="M9 36h27v-3H9zM12 33v-3h21v3zM11 14V8h4v3h4V8h7v3h4V8h4v6l-3 3v9H14l-3-3z" />
      <path d="M14 17h17v9H14z" opacity="0.92" />
    </g>
  ),
  king: (
    <g>
      <path d="M22.5 5v6M19.5 8h6" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" fill="none" />
      <path d="M22.5 14c-3 0-7 2-7 7 0 3 2 6 7 8 5-2 7-5 7-8 0-5-4-7-7-7z" />
      <path d="M11 36h23v-3H11zM13 33v-3h19v3zM14 30c-1-4 4-6 8.5-6s9.5 2 8.5 6" />
    </g>
  ),
  queen: (
    <g>
      <circle cx="9" cy="13" r="2" />
      <circle cx="22.5" cy="11" r="2" />
      <circle cx="36" cy="13" r="2" />
      <circle cx="15" cy="9" r="2" />
      <circle cx="30" cy="9" r="2" />
      <path d="M9 15l4 11h19l4-11-6 4-3.5-7-4 7-4-7-3.5 7z" />
      <path d="M11 28h23v3H11zM12 31h21v3H12zM10 34h25v3H10z" />
    </g>
  ),
  bishop: (
    <g>
      <path d="M22.5 5c-2 0-3.5 1.5-3.5 3.5 0 1 .5 1.8 1.2 2.3-3 1.5-5 5-5 9.2 0 4 2 7 7.3 8 5.3-1 7.3-4 7.3-8 0-4.2-2-7.7-5-9.2.7-.5 1.2-1.3 1.2-2.3 0-2-1.5-3.5-3.5-3.5z" />
      <path d="M20.5 13h4v3h-4z" fill="var(--bg-1)" opacity="0.9" />
      <path d="M14 30c1.5-3 5-3 8.5-3s7 0 8.5 3M11 36h23v-3H11zM13 33v-3h19v3z" />
    </g>
  ),
  knight: (
    <g>
      <path d="M 22 10 C 32.5 11 38.5 18 36 30 L 15 30 C 15 23 25 26 23 18" />
      <path d="M 24 18 C 24.38 20.91 18.45 25.37 16 27 C 13 29 13.18 31.34 11 31 C 9.958 30.06 12.41 27.96 11 28 C 10 28 11.19 29.23 10 30 C 9 30 5.997 29 6 26 C 6 24 12 14 12 14 C 12 14 13.89 12.1 14 10.5 C 13.27 9.506 13.5 8.5 13.5 7.5 C 14.5 6.5 16.5 10 16.5 10 L 18.5 10 C 18.5 10 19.28 8.008 21 7 C 22 7 22 10 22 10" />
      <circle cx="9" cy="25.5" r="0.7" fill="var(--bg-1)" />
      <circle cx="14.5" cy="15.5" r="1.2" fill="var(--bg-1)" />
      <path d="M11 36h23v-3H11zM13 33v-3h19v3z" />
    </g>
  ),
  pawn: (
    <g>
      <circle cx="22.5" cy="12" r="4.5" />
      <path d="M18 16c-1 2 0 4 2 5-3 1-5 4-5 8h15c0-4-2-7-5-8 2-1 3-3 2-5z" />
      <path d="M13 36h19v-3H13zM14 33v-3h17v3z" />
    </g>
  ),
};

export const ChessPiece: React.FC<ChessPieceProps> = ({
  kind = "rook",
  color = "white",
  size = 32,
  style,
}) => {
  const enemyFill = color === "black" ? "var(--ink-0)" : undefined;

  return (
    <svg
      viewBox="0 0 45 45"
      width={size}
      height={size}
      fill="currentColor"
      style={{ display: "block", color: enemyFill || "currentColor", ...style }}
    >
      <g>{paths[kind]}</g>
    </svg>
  );
};
