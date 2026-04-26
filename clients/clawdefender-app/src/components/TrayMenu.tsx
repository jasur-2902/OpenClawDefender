import { useNavigate } from "react-router-dom";
import { Icon, Rook, Dot } from "./design";
import type { Posture } from "./design";

const POSTURE_COLOR: Record<Posture, string> = {
  low: "var(--green)",
  normal: "var(--green)",
  elevated: "var(--amber)",
  high: "var(--red)",
  critical: "var(--red)",
};

const POSTURE_LABEL: Record<Posture, string> = {
  low: "All quiet",
  normal: "Defenders in position",
  elevated: "Pawn advanced",
  high: "Check",
  critical: "Mate threatened",
};

const TRAY_NAV = [
  { path: "/", label: "Open RookBot", icon: "home" },
  { path: "/activity", label: "View activity", icon: "activity" },
  { path: "/alerts", label: "View alerts", icon: "alert" },
  { path: "/scan", label: "Run a scan", icon: "scan" },
  { path: "/ask", label: "Ask Rook", icon: "chat" },
] as const;

const POSTURE_LEVELS: Posture[] = ["low", "normal", "elevated", "high", "critical"];

interface TrayMenuProps {
  open: boolean;
  onClose: () => void;
  posture: Posture;
  setPosture: (p: Posture) => void;
}

export function TrayMenu({ open, onClose, posture, setPosture }: TrayMenuProps) {
  const navigate = useNavigate();

  if (!open) return null;

  const postureColor = POSTURE_COLOR[posture];
  const postureLabel = POSTURE_LABEL[posture];

  return (
    <>
      <div
        onClick={onClose}
        style={{ position: "absolute", inset: 0, zIndex: 50 }}
      />
      <div
        className="cd-slide-in"
        style={{
          position: "absolute",
          top: 44 + 8,
          right: 16,
          width: 300,
          background: "var(--bg-1)",
          border: "1px solid oklch(0 0 0 / 0.08)",
          borderRadius: 12,
          boxShadow: "var(--shadow-lg)",
          zIndex: 60,
          overflow: "hidden",
        }}
      >
        {/* Brand header */}
        <div
          style={{
            padding: "16px 16px 14px",
            display: "flex",
            alignItems: "center",
            gap: 12,
          }}
        >
          <div
            style={{
              width: 36,
              height: 36,
              borderRadius: 9,
              background: "var(--accent)",
              display: "grid",
              placeItems: "center",
            }}
          >
            <Rook size={18} color="white" />
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 13, fontWeight: 600 }}>RookBot</div>
            <div
              style={{
                fontSize: 12,
                color: postureColor,
                display: "flex",
                alignItems: "center",
                gap: 6,
                marginTop: 2,
              }}
            >
              <Dot color={postureColor} size={6} pulse />
              {postureLabel}
            </div>
          </div>
        </div>

        <div style={{ height: 1, background: "var(--line)" }} />

        {/* Quick nav */}
        <div style={{ padding: "6px 0" }}>
          {TRAY_NAV.map((it) => (
            <button
              key={it.path}
              onClick={() => {
                navigate(it.path);
                onClose();
              }}
              style={{
                width: "100%",
                padding: "8px 16px",
                display: "flex",
                alignItems: "center",
                gap: 10,
                fontSize: 13,
                color: "var(--ink-0)",
                background: "transparent",
                border: "none",
                cursor: "pointer",
              }}
              onMouseEnter={(e) =>
                (e.currentTarget.style.background = "var(--accent-soft)")
              }
              onMouseLeave={(e) =>
                (e.currentTarget.style.background = "transparent")
              }
            >
              <Icon name={it.icon} size={14} color="var(--ink-2)" />
              {it.label}
            </button>
          ))}
        </div>

        <div style={{ height: 1, background: "var(--line)" }} />

        {/* Pause options */}
        <div
          style={{
            padding: "10px 16px",
            display: "flex",
            alignItems: "center",
            gap: 10,
          }}
        >
          <span style={{ fontSize: 12, color: "var(--ink-2)", flex: 1 }}>
            Pause for...
          </span>
          {["1h", "8h"].map((p) => (
            <button
              key={p}
              style={{
                padding: "4px 10px",
                fontSize: 11.5,
                color: "var(--ink-1)",
                borderRadius: 6,
                background: "var(--bg-2)",
                border: "none",
                cursor: "pointer",
              }}
            >
              {p}
            </button>
          ))}
        </div>

        {/* Posture override (dev) */}
        <div
          style={{
            padding: "8px 12px",
            display: "flex",
            gap: 4,
            borderTop: "1px solid var(--line)",
            background: "var(--bg-2)",
          }}
        >
          {POSTURE_LEVELS.map((p) => (
            <button
              key={p}
              onClick={() => setPosture(p)}
              title={p}
              style={{
                flex: 1,
                padding: "4px 0",
                fontSize: 10,
                color: posture === p ? "var(--ink-0)" : "var(--ink-3)",
                borderRadius: 4,
                background: posture === p ? "white" : "transparent",
                border:
                  "1px solid " +
                  (posture === p ? "var(--line-strong)" : "transparent"),
                cursor: "pointer",
              }}
            >
              {p[0].toUpperCase()}
            </button>
          ))}
        </div>
      </div>
    </>
  );
}
