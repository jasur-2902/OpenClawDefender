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
      <path d="M22 8c4 0 9 3 10 9 .5 3-.5 6-1 8l-1 5H14l1-3c.5-2 0-3-1-4l-3 1c-2 .5-3-1-2-3 1-1.5 3-2 5-2.5l-1-3c-.5-2 .5-4 2-5l1 1c0-2 2-3 6-3.5z" />
      <circle cx="18" cy="14" r="1.2" fill="var(--bg-1)" />
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
