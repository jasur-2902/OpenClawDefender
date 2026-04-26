import { Rook } from "./design";
import type { Posture } from "./design";

const POSTURE_COLOR: Record<Posture, string> = {
  low: "var(--green)",
  normal: "var(--green)",
  elevated: "var(--amber)",
  high: "var(--red)",
  critical: "var(--red)",
};

const TITLE_MAP: Record<string, string> = {
  home: "",
  activity: "Activity",
  alerts: "Alerts",
  scan: "Scans",
  ask: "Ask Rook",
  tools: "Tools",
  transparency: "Activity log",
  settings: "Settings",
  event: "Event",
  alertDetail: "Alert",
  onboarding: "",
};

interface StatusHeaderProps {
  currentPage: string;
  posture: Posture;
  onTrayOpen: () => void;
}

export function StatusHeader({ currentPage, posture, onTrayOpen }: StatusHeaderProps) {
  const postureColor = POSTURE_COLOR[posture] || "var(--ink-2)";

  return (
    <header
      style={{
        height: 44,
        minHeight: 44,
        background: "var(--bg-0)",
        borderBottom: "1px solid var(--line)",
        display: "flex",
        alignItems: "center",
        padding: "0 20px",
        gap: 12,
      }}
    >
      <div
        style={{
          flex: 1,
          fontSize: 13.5,
          fontWeight: 600,
          color: "var(--ink-0)",
        }}
      >
        {TITLE_MAP[currentPage] || ""}
      </div>
      <button
        onClick={onTrayOpen}
        style={{
          width: 28,
          height: 28,
          borderRadius: 7,
          display: "grid",
          placeItems: "center",
          position: "relative",
          color: "var(--ink-1)",
          background: "transparent",
          border: "none",
          cursor: "pointer",
        }}
        onMouseEnter={(e) =>
          (e.currentTarget.style.background = "oklch(0 0 0 / 0.05)")
        }
        onMouseLeave={(e) =>
          (e.currentTarget.style.background = "transparent")
        }
        title="Status menu"
      >
        <Rook size={14} color="var(--ink-1)" />
        <span
          style={{
            position: "absolute",
            top: 4,
            right: 4,
            width: 6,
            height: 6,
            borderRadius: 999,
            background: postureColor,
            border: "1.5px solid var(--bg-0)",
          }}
        />
      </button>
    </header>
  );
}
