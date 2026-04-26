import type { Cell } from "./MiniBoard";
import type { PieceKind } from "./ChessPiece";

export type Posture = "low" | "normal" | "elevated" | "high" | "critical";

export interface PosturePhrase {
  headline: string;
  chess: string;
  sub: string;
}

export interface CapabilityPieceResult {
  kind: PieceKind;
  reason: string;
}

/** Returns cells array for a 5x5 board based on posture level. */
export function postureBoard(posture: Posture): Cell[] {
  const base: Cell[] = [
    { x: 2, y: 2, piece: "king", color: "white", tint: "var(--ink-0)", shadow: true },
    { x: 1, y: 2, piece: "rook", color: "white", tint: "var(--accent)", shadow: true, glow: "var(--accent)" },
  ];

  switch (posture) {
    case "low":
    case "normal":
      return base;
    case "elevated":
      return [...base, { x: 4, y: 0, piece: "pawn", color: "black" }];
    case "high":
      return [...base, { x: 3, y: 2, piece: "knight", color: "black", danger: true }];
    case "critical":
      return [
        ...base,
        { x: 3, y: 2, piece: "queen", color: "black", danger: true },
        { x: 4, y: 4, piece: "bishop", color: "black", danger: true },
      ];
    default:
      return base;
  }
}

/** Returns headline, chess, and sub text for a given posture. */
export function posturePhrase(posture: Posture): PosturePhrase {
  const map: Record<Posture, PosturePhrase> = {
    low: { headline: "All quiet", chess: "No pieces in play", sub: "Nothing unusual happened today." },
    normal: { headline: "You're protected", chess: "Defenders in position", sub: "RookBot is watching your apps. Nothing unusual today." },
    elevated: { headline: "Something needs your attention", chess: "Pawn advanced", sub: "One alert is waiting for you to review." },
    high: { headline: "Active threat detected", chess: "Check", sub: "An AI tool tried to do something dangerous. We blocked it." },
    critical: { headline: "Confirmed attack in progress", chess: "Mate threatened", sub: "Your machine is being actively probed. Take action now." },
  };
  return map[posture];
}

/** Maps MCP capabilities to a chess piece archetype. */
export function capabilityPiece(caps: string[] = []): CapabilityPieceResult {
  if (caps.includes("network") || caps.includes("api:github"))
    return { kind: "bishop", reason: "Long range — network access" };
  if (caps.includes("shell"))
    return { kind: "knight", reason: "Unpredictable jumps — shell execution" };
  if (caps.includes("filesystem"))
    return { kind: "rook", reason: "Guards lanes — file access" };
  if (caps.includes("metadata") || caps.includes("git"))
    return { kind: "pawn", reason: "Limited scope — metadata only" };
  return { kind: "pawn", reason: "Standard piece" };
}
