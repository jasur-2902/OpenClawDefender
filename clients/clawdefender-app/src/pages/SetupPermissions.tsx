import { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { SectionTitle, Card, Btn, Icon, Dot } from "../components/design";
import type { SensorHealth } from "../types";

const StatusRow: React.FC<{ ok: boolean; label: string }> = ({ ok, label }) => (
  <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 0" }}>
    <Icon
      name={ok ? "check" : "alert"}
      size={16}
      color={ok ? "var(--green)" : "var(--red)"}
    />
    <span style={{ fontSize: 13, color: "var(--ink-1)" }}>{label}</span>
  </div>
);

export const SetupPermissions: React.FC = () => {
  const navigate = useNavigate();
  const [health, setHealth] = useState<SensorHealth | null>(null);
  const [wasGranted, setWasGranted] = useState(false);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchHealth = () => {
    invoke<SensorHealth>("get_sensor_health")
      .then((h) => {
        setHealth(h);
        if (h.fda_granted) setWasGranted(true);
      })
      .catch(() => {});
  };

  useEffect(() => {
    fetchHealth();
    timerRef.current = setInterval(fetchHealth, 5_000);
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, []);

  const openSettings = () => {
    invoke("open_system_settings_fda").catch(() => {});
  };

  return (
    <div
      className="cd-scroll"
      style={{
        padding: 24,
        maxWidth: 1080,
        margin: "0 auto",
        overflowY: "auto",
        height: "100%",
      }}
    >
      <SectionTitle
        sub="RookBot needs Full Disk Access to see which AI tool made each file and network change."
      >
        Enable Full Monitoring
      </SectionTitle>

      {/* Success banner */}
      {wasGranted && (
        <div
          style={{
            padding: "10px 16px",
            marginBottom: 16,
            borderRadius: 10,
            background: "var(--green-soft)",
            border: "1px solid color-mix(in oklch, var(--green) 30%, transparent)",
            fontSize: 13,
            color: "var(--ink-1)",
            display: "flex",
            alignItems: "center",
            gap: 8,
          }}
        >
          <Icon name="check" size={16} color="var(--green)" />
          <span style={{ flex: 1 }}>
            Full Disk Access granted! Monitoring is now active.
          </span>
          <Btn kind="primary" size="sm" onClick={() => navigate("/activity")}>
            Go to Activity
          </Btn>
        </div>
      )}

      {/* Status card */}
      <Card title="System Status" style={{ marginBottom: 16 }}>
        {health ? (
          <>
            <StatusRow ok={health.os_version_ok} label="macOS version OK" />
            <StatusRow ok={health.fda_granted} label="Full Disk Access" />
            <StatusRow ok={health.daemon_running} label="Daemon running" />
            <StatusRow ok={health.events_flowing} label="Events flowing" />
          </>
        ) : (
          <div style={{ fontSize: 13, color: "var(--ink-3)" }}>Checking...</div>
        )}
      </Card>

      {/* Step-by-step instructions */}
      <Card title="Setup Instructions" style={{ marginBottom: 16 }}>
        <ol
          style={{
            margin: 0,
            paddingLeft: 20,
            display: "flex",
            flexDirection: "column",
            gap: 10,
            fontSize: 13,
            color: "var(--ink-1)",
          }}
        >
          <li>
            Click <strong>Open System Settings</strong> below
          </li>
          <li>
            Find <strong>RookBot</strong> (or Terminal.app for development) in the list
          </li>
          <li>
            Toggle it <strong>on</strong> and enter your password
          </li>
          <li>Come back here — this page updates automatically</li>
        </ol>
      </Card>

      {/* Open System Settings button */}
      <div style={{ marginBottom: 24 }}>
        <Btn kind="primary" size="lg" onClick={openSettings}>
          Open System Settings
        </Btn>
      </div>

      {/* What this enables explainer */}
      <Card title="What this enables" style={{ marginBottom: 16 }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
              <Dot color="var(--red)" size={8} />
              <span style={{ fontSize: 13, fontWeight: 600, color: "var(--ink-0)" }}>
                Without Full Disk Access
              </span>
            </div>
            <div style={{ fontSize: 13, color: "var(--ink-2)", paddingLeft: 16 }}>
              File changes show as "Desktop", "Documents" — no tool attribution
            </div>
          </div>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
              <Dot color="var(--green)" size={8} />
              <span style={{ fontSize: 13, fontWeight: 600, color: "var(--ink-0)" }}>
                With Full Disk Access
              </span>
            </div>
            <div style={{ fontSize: 13, color: "var(--ink-2)", paddingLeft: 16 }}>
              Every file and network event is tagged with the exact AI tool
            </div>
          </div>
        </div>
      </Card>
    </div>
  );
};
