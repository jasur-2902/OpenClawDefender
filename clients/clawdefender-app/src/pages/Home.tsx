import { useEffect, useState, useMemo, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { useEventStore } from "../stores/eventStore";
import { useServerStore } from "../stores/serverStore";
import { useAlertStore } from "../stores/alertStore";
import {
  Icon,
  Dot,
  Btn,
  MiniBoard,
  postureBoard,
  posturePhrase,
} from "../components/design";
import type { Posture } from "../components/design";
import type { IntelligentAlert } from "../types";
import { AskRookDock } from "../components/AskRookDock";

function isToday(timestamp: string): boolean {
  const d = new Date(timestamp);
  const now = new Date();
  return (
    d.getFullYear() === now.getFullYear() &&
    d.getMonth() === now.getMonth() &&
    d.getDate() === now.getDate()
  );
}

const POSTURE_COLOR: Record<string, string> = {
  low: "var(--green)",
  normal: "var(--green)",
  elevated: "var(--amber)",
  high: "var(--red)",
  critical: "var(--red)",
};

/* ---------- small heading ---------- */
function SmallHeading({ children }: { children: React.ReactNode }) {
  return (
    <div
      style={{
        fontSize: 11,
        fontWeight: 600,
        color: "var(--ink-2)",
        textTransform: "uppercase",
        letterSpacing: 0.5,
        padding: "0 4px 8px",
      }}
    >
      {children}
    </div>
  );
}

/* ---------- settings-style list row ---------- */
function ListRow({
  icon,
  label,
  value,
  valueColor,
  borderBottom,
}: {
  icon: string;
  label: string;
  value: string | number;
  valueColor?: string;
  borderBottom?: boolean;
}) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 14,
        padding: "13px 16px",
        borderBottom: borderBottom ? "1px solid var(--line-soft)" : "none",
      }}
    >
      <div
        style={{
          width: 28,
          height: 28,
          borderRadius: 7,
          background: "var(--bg-2)",
          display: "grid",
          placeItems: "center",
          flexShrink: 0,
        }}
      >
        <Icon name={icon} size={15} color="var(--ink-2)" />
      </div>
      <span style={{ flex: 1, fontSize: 14, color: "var(--ink-0)" }}>
        {label}
      </span>
      <span
        style={{
          fontSize: 15,
          fontWeight: 600,
          color: valueColor || "var(--ink-1)",
          fontVariantNumeric: "tabular-nums",
        }}
      >
        {value}
      </span>
    </div>
  );
}

/* ---------- tool link row ---------- */
function ToolRow({
  label,
  desc,
  icon,
  color,
  borderBottom,
  onClick,
}: {
  label: string;
  desc: string;
  icon: string;
  color: string;
  borderBottom?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      style={{
        width: "100%",
        textAlign: "left",
        display: "flex",
        alignItems: "center",
        gap: 14,
        padding: "13px 16px",
        borderBottom: borderBottom ? "1px solid var(--line-soft)" : "none",
        cursor: "pointer",
        background: "transparent",
        border: "none",
      }}
      onMouseEnter={(e) =>
        (e.currentTarget.style.background = "var(--accent-soft)")
      }
      onMouseLeave={(e) =>
        (e.currentTarget.style.background = "transparent")
      }
    >
      <div
        style={{
          width: 30,
          height: 30,
          borderRadius: 8,
          background: `color-mix(in oklch, ${color} 14%, transparent)`,
          display: "grid",
          placeItems: "center",
          flexShrink: 0,
        }}
      >
        <Icon name={icon} size={15} color={color} />
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 14, color: "var(--ink-0)" }}>{label}</div>
        <div style={{ fontSize: 12.5, color: "var(--ink-2)", marginTop: 1 }}>
          {desc}
        </div>
      </div>
      <Icon name="chevron" size={13} color="var(--ink-3)" />
    </button>
  );
}

/* ========== main component ========== */

export function Home() {
  const navigate = useNavigate();
  const events = useEventStore((s) => s.events);
  const servers = useServerStore((s) => s.servers);
  const fetchServers = useServerStore((s) => s.fetchServers);
  const alerts = useAlertStore((s) => s.alerts);
  const fetchAlerts = useAlertStore((s) => s.fetchAlerts);

  const [posture, setPosture] = useState<Posture>("normal");

  // Fetch posture on mount + periodically
  useEffect(() => {
    async function loadPosture() {
      try {
        const info = await invoke<{ level_name: string }>(
          "get_threat_posture",
        );
        const level = info.level_name?.toLowerCase() as Posture;
        if (
          ["low", "normal", "elevated", "high", "critical"].includes(level)
        ) {
          setPosture(level);
        }
      } catch {
        /* ignore */
      }
    }
    loadPosture();
    const interval = setInterval(loadPosture, 30_000);
    return () => clearInterval(interval);
  }, []);

  // Fetch servers + alerts on mount
  useEffect(() => {
    fetchServers();
    fetchAlerts();
  }, [fetchServers, fetchAlerts]);

  // Derived
  const postureColor = POSTURE_COLOR[posture] || "var(--green)";
  const isOk = posture === "low" || posture === "normal";
  const phrase = posturePhrase(posture);
  const board = postureBoard(posture);

  const latestAlert: IntelligentAlert | undefined = alerts[0];

  const todayEvents = useMemo(
    () => events.filter((e) => isToday(e.timestamp)),
    [events],
  );
  const todayBlocked = useMemo(
    () =>
      todayEvents.filter(
        (e) => e.action_taken === "Blocked" || e.action_taken === "AutoBlocked",
      ).length,
    [todayEvents],
  );

  const wrappedCount = useMemo(
    () => servers.filter((s) => s.wrapped).length,
    [servers],
  );
  const unwrappedCount = useMemo(
    () => servers.filter((s) => !s.wrapped).length,
    [servers],
  );

  const goto = useCallback(
    (id: string) => {
      const routes: Record<string, string> = {
        scan: "/scan",
        ask: "/ask",
        activity: "/activity",
        tools: "/tools",
      };
      navigate(routes[id] || `/${id}`);
    },
    [navigate],
  );

  return (
    <div className="cd-scroll" style={{ overflowY: "auto", height: "100%" }}>
      <div
        style={{ maxWidth: 640, margin: "0 auto", padding: "44px 28px 24px" }}
      >
        {/* Hero: chessboard scene */}
        <div style={{ textAlign: "center", marginBottom: 36 }}>
          <div
            style={{
              display: "inline-flex",
              flexDirection: "column",
              alignItems: "center",
              gap: 16,
              padding: "20px 28px 22px",
              background: "var(--bg-1)",
              border: "1px solid var(--line)",
              borderRadius: 18,
              boxShadow:
                "0 1px 2px oklch(0 0 0 / 0.04), 0 8px 28px oklch(0 0 0 / 0.05)",
              marginBottom: 22,
            }}
          >
            <MiniBoard size={5} cells={board} tileSize={36} />
            <div
              style={{
                fontSize: 11,
                fontWeight: 600,
                color: postureColor,
                textTransform: "uppercase",
                letterSpacing: 0.6,
                display: "flex",
                alignItems: "center",
                gap: 6,
              }}
            >
              <Dot color={postureColor} size={6} pulse={!isOk} />
              {phrase.chess}
            </div>
          </div>
          <h1
            style={{
              margin: 0,
              fontSize: 30,
              fontWeight: 700,
              letterSpacing: -0.6,
              color: "var(--ink-0)",
            }}
          >
            {phrase.headline}
          </h1>
          <p
            style={{
              margin: "10px auto 0",
              fontSize: 16,
              color: "var(--ink-2)",
              lineHeight: 1.5,
              maxWidth: 440,
            }}
          >
            {phrase.sub}
          </p>
        </div>

        {/* Action row (posture OK) */}
        {isOk && (
          <div
            style={{
              display: "flex",
              justifyContent: "center",
              gap: 10,
              marginBottom: 36,
            }}
          >
            <Btn
              kind="primary"
              size="lg"
              icon="scan"
              onClick={() => goto("scan")}
            >
              Run a checkup
            </Btn>
            <Btn
              kind="soft"
              size="lg"
              icon="chat"
              onClick={() => goto("ask")}
            >
              Ask Rook
            </Btn>
          </div>
        )}

        {/* Alert card (posture not OK) */}
        {!isOk && latestAlert && (
          <button
            onClick={() => navigate(`/alerts/${latestAlert.id}`)}
            style={{
              width: "100%",
              textAlign: "left",
              padding: "18px 20px",
              background: "var(--bg-1)",
              border: `1px solid color-mix(in oklch, ${postureColor} 30%, var(--line))`,
              borderRadius: 14,
              marginBottom: 36,
              display: "flex",
              alignItems: "center",
              gap: 14,
              boxShadow: `0 4px 16px color-mix(in oklch, ${postureColor} 12%, transparent)`,
              cursor: "pointer",
            }}
          >
            <div
              style={{
                width: 36,
                height: 36,
                borderRadius: 10,
                background: `color-mix(in oklch, ${postureColor} 14%, transparent)`,
                display: "grid",
                placeItems: "center",
                flexShrink: 0,
              }}
            >
              <Icon name="alert" size={18} color={postureColor} />
            </div>
            <div style={{ flex: 1 }}>
              <div
                style={{ fontSize: 14.5, fontWeight: 600, marginBottom: 2 }}
              >
                {latestAlert.title}
              </div>
              <div
                style={{
                  fontSize: 13,
                  color: "var(--ink-2)",
                  lineHeight: 1.45,
                }}
              >
                {latestAlert.description}
              </div>
            </div>
            <Icon name="chevron" size={14} color="var(--ink-3)" />
          </button>
        )}

        {/* Today summary */}
        <div style={{ marginBottom: 14 }}>
          <SmallHeading>Today</SmallHeading>
          <div
            style={{
              background: "var(--bg-1)",
              border: "1px solid var(--line)",
              borderRadius: 12,
              overflow: "hidden",
              boxShadow: "0 1px 2px oklch(0 0 0 / 0.04)",
            }}
          >
            <ListRow
              icon="tools"
              label="Apps watched"
              value={String(servers.length)}
              borderBottom
            />
            <ListRow
              icon="shield"
              label="Things checked"
              value={todayEvents.length.toLocaleString()}
              borderBottom
            />
            <ListRow
              icon="lock"
              label="Things blocked"
              value={String(todayBlocked)}
              valueColor="var(--green)"
            />
          </div>
        </div>

        {/* Tools quick links */}
        <div>
          <SmallHeading>Tools</SmallHeading>
          <div
            style={{
              background: "var(--bg-1)",
              border: "1px solid var(--line)",
              borderRadius: 12,
              overflow: "hidden",
              boxShadow: "0 1px 2px oklch(0 0 0 / 0.04)",
            }}
          >
            <ToolRow
              label="Run a security scan"
              desc="Have Rook check your AI tools for risks"
              icon="scan"
              color="var(--accent)"
              borderBottom
              onClick={() => goto("scan")}
            />
            <ToolRow
              label="Ask Rook"
              desc="Ask anything in plain English"
              icon="chat"
              color="var(--violet)"
              borderBottom
              onClick={() => goto("ask")}
            />
            <ToolRow
              label="See what's happening"
              desc="Live feed of every action your AI tools take"
              icon="activity"
              color="var(--green)"
              borderBottom
              onClick={() => goto("activity")}
            />
            <ToolRow
              label="Manage your AI tools"
              desc={`${wrappedCount} wrapped, ${unwrappedCount} unwrapped`}
              icon="tools"
              color="var(--amber)"
              onClick={() => goto("tools")}
            />
          </div>
        </div>

        {/* Ask Rook Dock */}
        <AskRookDock />
      </div>
    </div>
  );
}
