import React from "react";
import { ChessPiece } from "./ChessPiece";
import type { PieceKind } from "./ChessPiece";

export interface Cell {
  x: number;
  y: number;
  piece?: PieceKind;
  color?: "white" | "black";
  danger?: boolean;
  glow?: string;
  tint?: string;
  shadow?: boolean;
}

export interface MiniBoardProps {
  size?: number;
  cells?: Cell[];
  tileSize?: number;
  light?: string;
  dark?: string;
  style?: React.CSSProperties;
  onCellClick?: (cell: Cell) => void;
}

export const MiniBoard: React.FC<MiniBoardProps> = ({
  size = 5,
  cells = [],
  tileSize = 28,
  light = "var(--bg-2)",
  dark = "color-mix(in oklch, var(--ink-3) 10%, var(--bg-2))",
  style,
  onCellClick,
}) => {
  const cellMap = new Map(cells.map((c) => [`${c.x},${c.y}`, c]));

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: `repeat(${size}, ${tileSize}px)`,
        gridTemplateRows: `repeat(${size}, ${tileSize}px)`,
        borderRadius: 8,
        overflow: "hidden",
        border: "1px solid oklch(0 0 0 / 0.10)",
        boxShadow: "inset 0 0 0 1px oklch(1 0 0 / 0.20)",
        ...style,
      }}
    >
      {Array.from({ length: size * size }).map((_, i) => {
        const x = i % size;
        const y = Math.floor(i / size);
        const isLight = (x + y) % 2 === 0;
        const cell = cellMap.get(`${x},${y}`);

        return (
          <div
            key={i}
            onClick={() => cell && onCellClick?.(cell)}
            style={{
              background: isLight ? light : dark,
              position: "relative",
              display: "grid",
              placeItems: "center",
              cursor: onCellClick && cell ? "pointer" : "default",
            }}
          >
            {cell?.danger && (
              <div
                style={{
                  position: "absolute",
                  inset: 2,
                  borderRadius: 5,
                  background:
                    "radial-gradient(circle, color-mix(in oklch, var(--red) 28%, transparent), transparent 70%)",
                  animation: "cdPulse 1.8s ease-in-out infinite",
                }}
              />
            )}
            {cell?.glow && (
              <div
                style={{
                  position: "absolute",
                  inset: 2,
                  borderRadius: 5,
                  background: `radial-gradient(circle, color-mix(in oklch, ${cell.glow} 30%, transparent), transparent 70%)`,
                }}
              />
            )}
            {cell?.piece && (
              <ChessPiece
                kind={cell.piece}
                color={cell.color || "white"}
                size={tileSize - 6}
                style={{
                  color:
                    cell.color === "black"
                      ? cell.danger
                        ? "var(--red)"
                        : "var(--ink-0)"
                      : cell.tint || "var(--accent)",
                  filter: cell.shadow
                    ? "drop-shadow(0 1px 2px oklch(0 0 0 / 0.25))"
                    : "none",
                  position: "relative",
                  zIndex: 2,
                }}
              />
            )}
          </div>
        );
      })}
    </div>
  );
};
