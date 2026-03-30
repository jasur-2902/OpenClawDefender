import { useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Link, useLocation } from "react-router-dom";
import type { AppSettings } from "../../types";
import { ToggleSwitch } from "./ToggleSwitch";

interface AdvancedSettingsProps {
  settings: AppSettings;
  onUpdateField: <K extends keyof AppSettings>(key: K, value: AppSettings[K]) => void;
}

const advancedSubRoutes = [
  { label: "Policy Editor", to: "/settings/policy" },
  { label: "System Health", to: "/settings/health" },
  { label: "Threat Intelligence", to: "/settings/threat-intel" },
];

export function AdvancedSettings({ settings, onUpdateField }: AdvancedSettingsProps) {
  const location = useLocation();
  const [exportStatus, setExportStatus] = useState<string | null>(null);

  const loadSettings = useCallback(async () => {
    try {
      const s = await invoke<AppSettings>("get_settings");
      // Update parent via individual field updates
      for (const [key, value] of Object.entries(s)) {
        onUpdateField(key as keyof AppSettings, value as AppSettings[keyof AppSettings]);
      }
    } catch {
      // Settings may not be available
    }
  }, [onUpdateField]);

  return (
    <div className="space-y-6">
      {/* Sub-route navigation */}
      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] overflow-hidden">
        <p className="px-4 pt-3 text-xs font-semibold text-[var(--color-text-muted)] uppercase tracking-wider">
          Advanced Sections
        </p>
        <div className="p-2">
          {advancedSubRoutes.map((route) => {
            const isActive = location.pathname === route.to;
            return (
              <Link
                key={route.to}
                to={route.to}
                className={`flex items-center justify-between px-3 py-2.5 rounded-md text-sm transition-colors ${
                  isActive
                    ? "bg-[var(--color-accent-subtle)] text-[var(--color-accent)]"
                    : "text-[var(--color-text-primary)] hover:bg-[var(--color-bg-tertiary)]"
                }`}
              >
                {route.label}
                <span className="text-[var(--color-text-muted)]">&rarr;</span>
              </Link>
            );
          })}
        </div>
      </div>

      {/* Sensor Configuration */}
      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4">
        <p className="text-sm font-medium mb-3">Sensor Configuration</p>
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm">Behavioral auto-block</p>
              <p className="text-xs text-[var(--color-text-secondary)]">
                Automatically block actions flagged as dangerous
              </p>
            </div>
            <ToggleSwitch
              checked={settings.behavioral_auto_block}
              onChange={(v) => onUpdateField("behavioral_auto_block", v)}
            />
          </div>

          {settings.behavioral_auto_block && (
            <div>
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs text-[var(--color-text-secondary)]">Auto-block threshold</p>
                <span className="text-xs text-[var(--color-text-secondary)]">{settings.behavioral_threshold}</span>
              </div>
              <input
                type="range"
                min={50}
                max={100}
                step={5}
                value={settings.behavioral_threshold}
                onChange={(e) => onUpdateField("behavioral_threshold", Number(e.target.value))}
                aria-label={`Auto-block threshold: ${settings.behavioral_threshold}`}
                className="w-full accent-[var(--color-accent)]"
              />
            </div>
          )}

          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm">Analysis frequency</p>
              <p className="text-xs text-[var(--color-text-secondary)]">When to run AI analysis on events</p>
            </div>
            <select
              value={settings.analysis_frequency}
              onChange={(e) => onUpdateField("analysis_frequency", e.target.value)}
              className="px-3 py-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-primary)] text-sm text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)]"
            >
              <option value="all">All prompted events</option>
              <option value="high_risk">High-risk events only</option>
              <option value="disabled">Disabled</option>
            </select>
          </div>

          <div>
            <div className="flex items-center justify-between mb-2">
              <div>
                <p className="text-sm">Prompt timeout</p>
                <p className="text-xs text-[var(--color-text-secondary)]">Auto-deny after this time</p>
              </div>
              <span className="text-sm text-[var(--color-text-secondary)]">{settings.prompt_timeout_seconds}s</span>
            </div>
            <input
              type="range"
              min={15}
              max={120}
              step={5}
              value={settings.prompt_timeout_seconds}
              onChange={(e) => onUpdateField("prompt_timeout_seconds", Number(e.target.value))}
              aria-label={`Prompt timeout: ${settings.prompt_timeout_seconds} seconds`}
              className="w-full accent-[var(--color-accent)]"
            />
            <div className="flex justify-between text-xs text-[var(--color-text-secondary)]">
              <span>15s</span>
              <span>120s</span>
            </div>
          </div>
        </div>
      </div>

      {/* Event Retention */}
      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium">Event Retention</p>
            <p className="text-xs text-[var(--color-text-secondary)]">Days to keep audit events</p>
          </div>
          <input
            type="number"
            min={1}
            max={365}
            value={settings.event_retention_days}
            onChange={(e) => onUpdateField("event_retention_days", Number(e.target.value))}
            aria-label="Event retention days"
            className="w-20 px-3 py-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-primary)] text-sm text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)] text-center"
          />
        </div>
      </div>

      {/* Network Protection -- Coming Soon */}
      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4">
        <div className="flex items-center gap-2 mb-2">
          <p className="text-sm font-medium">Network Protection</p>
          <span className="text-[10px] px-2 py-0.5 rounded-full bg-[var(--color-accent-subtle)] text-[var(--color-accent)] font-medium">
            Coming Soon
          </span>
        </div>
        <p className="text-xs text-[var(--color-text-secondary)]">
          Network-level protection requires the macOS Network Extension, which is under development.
          Your AI tools are still protected at the MCP protocol level.
        </p>
      </div>

      {/* Export / Import Config */}
      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4">
        <p className="text-sm font-medium mb-3">Export / Import Config</p>
        <div className="flex gap-2">
          <button
            onClick={async () => {
              try {
                const path = await invoke<string>("export_settings");
                setExportStatus(`Exported to ${path}`);
                setTimeout(() => setExportStatus(null), 4000);
              } catch (err) {
                setExportStatus(`Export failed: ${err}`);
                setTimeout(() => setExportStatus(null), 4000);
              }
            }}
            className="px-3 py-1.5 rounded-md text-xs border border-[var(--color-border)] hover:bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
          >
            Export Config
          </button>
          <button
            onClick={() => {
              const input = document.createElement("input");
              input.type = "file";
              input.accept = ".json";
              input.onchange = async (e) => {
                const file = (e.target as HTMLInputElement).files?.[0];
                if (file) {
                  try {
                    const content = await file.text();
                    await invoke("import_settings_from_content", { content });
                    setExportStatus("Settings imported successfully");
                    loadSettings();
                    setTimeout(() => setExportStatus(null), 4000);
                  } catch (err) {
                    setExportStatus(`Import failed: ${err}`);
                    setTimeout(() => setExportStatus(null), 4000);
                  }
                }
              };
              input.click();
            }}
            className="px-3 py-1.5 rounded-md text-xs border border-[var(--color-border)] hover:bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
          >
            Import Config
          </button>
          <button
            onClick={() => {
              if (window.confirm("Reset all settings to defaults? This cannot be undone.")) {
                const defaults: AppSettings = {
                  theme: "system",
                  notifications_enabled: true,
                  auto_start_daemon: true,
                  minimize_to_tray: true,
                  log_level: "info",
                  prompt_timeout_seconds: 30,
                  event_retention_days: 30,
                  behavioral_auto_block: false,
                  behavioral_threshold: 75,
                  analysis_frequency: "all",
                  security_level: "balanced",
                };
                for (const [key, value] of Object.entries(defaults)) {
                  onUpdateField(key as keyof AppSettings, value as AppSettings[keyof AppSettings]);
                }
                invoke("update_settings", { settings: defaults }).catch(() => {});
              }
            }}
            className="ml-auto px-3 py-1.5 rounded-md text-xs border border-[var(--color-danger)] text-[var(--color-danger)] hover:bg-[var(--color-danger)] hover:text-white"
          >
            Reset to Defaults
          </button>
        </div>
        {exportStatus && (
          <p className="text-xs text-[var(--color-text-secondary)] mt-2">{exportStatus}</p>
        )}
      </div>

      {/* Log Level & Debug */}
      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4">
        <p className="text-sm font-medium mb-3">Log Level & Debug</p>
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm">Log level</p>
            <p className="text-xs text-[var(--color-text-secondary)]">Verbosity of daemon logs</p>
          </div>
          <select
            value={settings.log_level}
            onChange={(e) => onUpdateField("log_level", e.target.value as AppSettings["log_level"])}
            className="px-3 py-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-primary)] text-sm text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)]"
          >
            <option value="trace">Trace</option>
            <option value="debug">Debug</option>
            <option value="info">Info</option>
            <option value="warn">Warn</option>
            <option value="error">Error</option>
          </select>
        </div>
      </div>
    </div>
  );
}
