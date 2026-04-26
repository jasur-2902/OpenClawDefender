// Chess primitives: pieces (SVG silhouettes), mini board, posture-driven scenes.
// All pieces drawn fresh — geometric, slightly modernized chess silhouettes.

const ChessPiece = ({ kind = "rook", color = "white", size = 32, style }) => {
  // viewBox 45x45 (FIDE convention). Drawn as flat silhouettes.
  const fill = color === "white" ? "currentColor" : "currentColor";
  const opacity = 1;

  const paths = {
    // ROOK — castle silhouette with crenellations
    rook: (
      <g>
        <path d="M9 36h27v-3H9zM12 33v-3h21v3zM11 14V8h4v3h4V8h7v3h4V8h4v6l-3 3v9H14l-3-3z"/>
        <path d="M14 17h17v9H14z" opacity="0.92"/>
      </g>
    ),
    // KING — cross on top, simple body
    king: (
      <g>
        <path d="M22.5 5v6M19.5 8h6" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" fill="none"/>
        <path d="M22.5 14c-3 0-7 2-7 7 0 3 2 6 7 8 5-2 7-5 7-8 0-5-4-7-7-7z"/>
        <path d="M11 36h23v-3H11zM13 33v-3h19v3zM14 30c-1-4 4-6 8.5-6s9.5 2 8.5 6"/>
      </g>
    ),
    // QUEEN — crown with points
    queen: (
      <g>
        <circle cx="9" cy="13" r="2"/>
        <circle cx="22.5" cy="11" r="2"/>
        <circle cx="36" cy="13" r="2"/>
        <circle cx="15" cy="9" r="2"/>
        <circle cx="30" cy="9" r="2"/>
        <path d="M9 15l4 11h19l4-11-6 4-3.5-7-4 7-4-7-3.5 7z"/>
        <path d="M11 28h23v3H11zM12 31h21v3H12zM10 34h25v3H10z"/>
      </g>
    ),
    // BISHOP — pointed mitre with slit
    bishop: (
      <g>
        <path d="M22.5 5c-2 0-3.5 1.5-3.5 3.5 0 1 .5 1.8 1.2 2.3-3 1.5-5 5-5 9.2 0 4 2 7 7.3 8 5.3-1 7.3-4 7.3-8 0-4.2-2-7.7-5-9.2.7-.5 1.2-1.3 1.2-2.3 0-2-1.5-3.5-3.5-3.5z"/>
        <path d="M20.5 13h4v3h-4z" fill="var(--bg-1)" opacity="0.9"/>
        <path d="M14 30c1.5-3 5-3 8.5-3s7 0 8.5 3M11 36h23v-3H11zM13 33v-3h19v3z"/>
      </g>
    ),
    // KNIGHT — horse head
    knight: (
      <g>
        <path d="M22 8c4 0 9 3 10 9 .5 3-.5 6-1 8l-1 5H14l1-3c.5-2 0-3-1-4l-3 1c-2 .5-3-1-2-3 1-1.5 3-2 5-2.5l-1-3c-.5-2 .5-4 2-5l1 1c0-2 2-3 6-3.5z"/>
        <circle cx="18" cy="14" r="1.2" fill="var(--bg-1)"/>
        <path d="M11 36h23v-3H11zM13 33v-3h19v3z"/>
      </g>
    ),
    // PAWN — round head, short body
    pawn: (
      <g>
        <circle cx="22.5" cy="12" r="4.5"/>
        <path d="M18 16c-1 2 0 4 2 5-3 1-5 4-5 8h15c0-4-2-7-5-8 2-1 3-3 2-5z"/>
        <path d="M13 36h19v-3H13zM14 33v-3h17v3z"/>
      </g>
    ),
  };

  const enemyFill = color === "black" ? "var(--ink-0)" : null;

  return (
    <svg viewBox="0 0 45 45" width={size} height={size} fill="currentColor" style={{ display: "block", color: enemyFill || "currentColor", ...style }}>
      <g style={{ opacity }}>{paths[kind]}</g>
    </svg>
  );
};

// Mini chessboard — N×N tiles. Cells: { x, y, piece, color, danger, glow }
const MiniBoard = ({ size = 5, cells = [], tileSize = 28, light = "var(--bg-2)", dark = "color-mix(in oklch, var(--ink-3) 10%, var(--bg-2))", style, onCellClick }) => {
  const cellMap = new Map(cells.map(c => [`${c.x},${c.y}`, c]));
  return (
    <div style={{
      display: "grid",
      gridTemplateColumns: `repeat(${size}, ${tileSize}px)`,
      gridTemplateRows: `repeat(${size}, ${tileSize}px)`,
      borderRadius: 8, overflow: "hidden",
      border: "1px solid oklch(0 0 0 / 0.10)",
      boxShadow: "inset 0 0 0 1px oklch(1 0 0 / 0.20)",
      ...style,
    }}>
      {Array.from({ length: size * size }).map((_, i) => {
        const x = i % size, y = Math.floor(i / size);
        const isLight = (x + y) % 2 === 0;
        const cell = cellMap.get(`${x},${y}`);
        return (
          <div key={i} onClick={() => cell && onCellClick?.(cell)} style={{
            background: isLight ? light : dark,
            position: "relative",
            display: "grid", placeItems: "center",
            cursor: cell?.onCellClick ? "pointer" : "default",
          }}>
            {cell?.danger && (
              <div style={{
                position: "absolute", inset: 2, borderRadius: 5,
                background: `radial-gradient(circle, color-mix(in oklch, var(--red) 28%, transparent), transparent 70%)`,
                animation: "cdPulse 1.8s ease-in-out infinite",
              }}/>
            )}
            {cell?.glow && (
              <div style={{
                position: "absolute", inset: 2, borderRadius: 5,
                background: `radial-gradient(circle, color-mix(in oklch, ${cell.glow} 30%, transparent), transparent 70%)`,
              }}/>
            )}
            {cell?.piece && (
              <ChessPiece
                kind={cell.piece}
                color={cell.color || "white"}
                size={tileSize - 6}
                style={{
                  color: cell.color === "black"
                    ? (cell.danger ? "var(--red)" : "var(--ink-0)")
                    : (cell.tint || "var(--accent)"),
                  filter: cell.shadow ? "drop-shadow(0 1px 2px oklch(0 0 0 / 0.25))" : "none",
                  position: "relative", zIndex: 2,
                }}
              />
            )}
          </div>
        );
      })}
    </div>
  );
};

// Posture-driven board scene. Returns cells for a 5x5 board (King center, Rook on file b).
const postureBoard = (posture) => {
  // Coordinates: 5x5 grid. (2,2)=King, (1,2)=Rook (defender).
  const base = [
    { x: 2, y: 2, piece: "king", color: "white", tint: "var(--ink-0)", shadow: true },
    { x: 1, y: 2, piece: "rook", color: "white", tint: "var(--accent)", shadow: true, glow: "var(--accent)" },
  ];
  switch (posture) {
    case "low":
    case "normal":
      return base; // no enemies
    case "elevated":
      return [
        ...base,
        { x: 4, y: 0, piece: "pawn", color: "black" }, // far corner
      ];
    case "high":
      return [
        ...base,
        { x: 3, y: 2, piece: "knight", color: "black", danger: true }, // adjacent attacker
      ];
    case "critical":
      return [
        ...base,
        { x: 3, y: 2, piece: "queen", color: "black", danger: true },
        { x: 4, y: 4, piece: "bishop", color: "black", danger: true },
      ];
    default:
      return base;
  }
};

// Chess-styled posture phrasing
const posturePhrase = (posture) => ({
  low: { headline: "All quiet", chess: "No pieces in play", sub: "Nothing unusual happened today." },
  normal: { headline: "You're protected", chess: "Defenders in position", sub: "ClawDefender is watching your apps. Nothing unusual today." },
  elevated: { headline: "Something needs your attention", chess: "Pawn advanced", sub: "One alert is waiting for you to review." },
  high: { headline: "Active threat detected", chess: "Check", sub: "An AI tool tried to do something dangerous. We blocked it." },
  critical: { headline: "Confirmed attack in progress", chess: "Mate threatened", sub: "Your machine is being actively probed. Take action now." },
}[posture]);

// Map MCP tool capability → chess piece archetype
const capabilityPiece = (caps = []) => {
  if (caps.includes("network") || caps.includes("api:github")) return { kind: "bishop", reason: "Long range — network access" };
  if (caps.includes("shell")) return { kind: "knight", reason: "Unpredictable jumps — shell execution" };
  if (caps.includes("filesystem")) return { kind: "rook", reason: "Guards lanes — file access" };
  if (caps.includes("metadata") || caps.includes("git")) return { kind: "pawn", reason: "Limited scope — metadata only" };
  return { kind: "pawn", reason: "Standard piece" };
};

Object.assign(window, { ChessPiece, MiniBoard, postureBoard, posturePhrase, capabilityPiece });
