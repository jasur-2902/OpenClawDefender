import { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { Icon, Btn } from "./design";
import type { SensorHealth } from "../types";

export const PermissionBanner: React.FC = () => {
  const navigate = useNavigate();
  const [dismissed, setDismissed] = useState(false);
  const [fdaGranted, setFdaGranted] = useState<boolean | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchHealth = () => {
    invoke<SensorHealth>("get_sensor_health")
      .then((h) => setFdaGranted(h.fda_granted))
      .catch(() => {});
  };

  useEffect(() => {
    fetchHealth();
    timerRef.current = setInterval(fetchHealth, 30_000);
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, []);

  if (fdaGranted === null || fdaGranted || dismissed) return null;

  return (
    <div
      style={{
        padding: "10px 16px",
        marginBottom: 16,
        borderRadius: 10,
        background: "color-mix(in oklch, var(--amber) 8%, var(--bg-1))",
        border: "1px solid color-mix(in oklch, var(--amber) 20%, transparent)",
        fontSize: 13,
        color: "var(--ink-1)",
        display: "flex",
        alignItems: "center",
        gap: 8,
      }}
    >
      <Icon name="alert" size={16} color="var(--amber)" />
      <span style={{ flex: 1 }}>
        Full Disk Access required — RookBot can't see which app made each change
      </span>
      <Btn kind="primary" size="sm" onClick={() => navigate("/setup-permissions")}>
        Set up now
      </Btn>
      <Btn kind="ghost" size="sm" onClick={() => setDismissed(true)}>
        Dismiss
      </Btn>
    </div>
  );
};
