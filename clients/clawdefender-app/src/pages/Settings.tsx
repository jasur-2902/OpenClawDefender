import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { AppSettings, NetworkExtensionStatus, NetworkSettings } from "../types";

const defaultSettings: AppSettings = {
  theme: "system",
  notifications_enabled: true,
  auto_start_daemon: true,
  minimize_to_tray: true,
  log_level: "info",
  prompt_timeout_seconds: 30,
  event_retention_days: 30,
};

const defaultNetworkSettings: NetworkSettings = {
  filter_enabled: false,
  dns_enabled: false,
  filter_all_processes: false,
  default_action: "prompt",
  prompt_timeout: 30,
  block_private_ranges: false,
  block_doh: true,
  log_dns: true,
};

export function Settings() {
  const [settings, setSettings] = useState<AppSettings>(defaultSettings);
  const [loading, setLoading] = useState(true);
  const [securityLevel, setSecurityLevel] = useState("balanced");
  const [netStatus, setNetStatus] = useState<NetworkExtensionStatus | null>(null);
  const [netSettings, setNetSettings] = useState<NetworkSettings>(defaultNetworkSettings);

  const loadSettings = useCallback(async () => {
    try {
      const s = await invoke<AppSettings>("get_settings");
      setSettings(s);
    } catch (_err) {
      // Use defaults
    } finally {
      setLoading(false);
    }
  }, []);

  const loadNetworkState = useCallback(async () => {
    try {
      const [status, ns] = await Promise.all([
        invoke<NetworkExtensionStatus>("get_network_extension_status"),
        invoke<NetworkSettings>("get_network_settings"),
      ]);
      setNetStatus(status);
      setNetSettings(ns);
    } catch (_err) {
      // Network extension may not be available
    }
  }, []);

  useEffect(() => {
    loadSettings();
    loadNetworkState();
  }, [loadSettings, loadNetworkState]);

  async function updateNetField<K extends keyof NetworkSettings>(key: K, value: NetworkSettings[K]) {
    const next = { ...netSettings, [key]: value };
    setNetSettings(next);
    try {
      await invoke("update_network_settings", { settings: next });
    } catch (_err) {
      // Tauri command may not be available yet
    }
  }

  async function updateField<K extends keyof AppSettings>(key: K, value: AppSettings[K]) {
    const next = { ...settings, [key]: value };
    setSettings(next);
    try {
      await invoke("update_settings", { settings: next });
    } catch (_err) {
      // Tauri command may not be available yet
    }
  }

  if (loading) {
    return (
      <div className="p-6">
        <p className="text-[var(--color-text-secondary)]">Loading settings...</p>
      </div>
    );
  }

  return (
    <div className="p-6 max-w-2xl">
      <h1 className="text-2xl font-bold mb-6">Settings</h1>

      {/* General */}
      <section className="mb-8">
        <h2 className="text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wider mb-3">
          General
        </h2>
        <div className="space-y-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4">
          {/* Theme */}
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">Theme</p>
              <p className="text-xs text-[var(--color-text-secondary)]">Choose appearance mode</p>
            </div>
            <select
              value={settings.theme}
              onChange={(e) => updateField("theme", e.target.value as AppSettings["theme"])}
              className="px-3 py-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-primary)] text-sm text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)]"
            >
              <option value="system">System</option>
              <option value="light">Light</option>
              <option value="dark">Dark</option>
            </select>
          </div>

          {/* Start at login */}
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">Start at Login</p>
              <p className="text-xs text-[var(--color-text-secondary)]">Auto-start daemon when you log in</p>
            </div>
            <ToggleSwitch
              checked={settings.auto_start_daemon}
              onChange={(v) => updateField("auto_start_daemon", v)}
            />
          </div>

          {/* Show in menu bar */}
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">Show in Menu Bar</p>
              <p className="text-xs text-[var(--color-text-secondary)]">Minimize to system tray</p>
            </div>
            <ToggleSwitch
              checked={settings.minimize_to_tray}
              onChange={(v) => updateField("minimize_to_tray", v)}
            />
          </div>
        </div>
      </section>

      {/* Protection */}
      <section className="mb-8">
        <h2 className="text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wider mb-3">
          Protection
        </h2>
        <div className="space-y-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4">
          {/* Security level */}
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">Security Level</p>
              <p className="text-xs text-[var(--color-text-secondary)]">Current protection template</p>
            </div>
            <select
              value={securityLevel}
              onChange={(e) => {
                setSecurityLevel(e.target.value);
                invoke("apply_template", { name: e.target.value }).catch(() => {});
              }}
              className="px-3 py-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-primary)] text-sm text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)]"
            >
              <option value="monitor-only">Monitor Only</option>
              <option value="balanced">Balanced</option>
              <option value="strict">Strict</option>
            </select>
          </div>

          {/* Auto-block */}
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">Notifications</p>
              <p className="text-xs text-[var(--color-text-secondary)]">Show alerts for blocked actions</p>
            </div>
            <ToggleSwitch
              checked={settings.notifications_enabled}
              onChange={(v) => updateField("notifications_enabled", v)}
            />
          </div>

          {/* Prompt timeout */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <div>
                <p className="text-sm font-medium">Prompt Timeout</p>
                <p className="text-xs text-[var(--color-text-secondary)]">Auto-deny after timeout</p>
              </div>
              <span className="text-sm text-[var(--color-text-secondary)]">{settings.prompt_timeout_seconds}s</span>
            </div>
            <input
              type="range"
              min={15}
              max={120}
              step={5}
              value={settings.prompt_timeout_seconds}
              onChange={(e) => updateField("prompt_timeout_seconds", Number(e.target.value))}
              className="w-full accent-[var(--color-accent)]"
            />
            <div className="flex justify-between text-xs text-[var(--color-text-secondary)]">
              <span>15s</span>
              <span>120s</span>
            </div>
          </div>
        </div>
      </section>

      {/* Network Protection */}
      <section className="mb-8">
        <h2 className="text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wider mb-3">
          Network Protection
        </h2>
        <div className="space-y-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4">
          {/* Status indicator */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span
                className={`inline-block w-2 h-2 rounded-full ${
                  netStatus?.filter_active ? "bg-[var(--color-success)]" : "bg-[var(--color-text-secondary)]"
                }`}
              />
              <p className="text-sm font-medium">
                {netStatus?.filter_active ? "Active" : "Inactive"}
              </p>
              {netStatus?.filter_active && (
                <span className="text-xs text-[var(--color-text-secondary)]">
                  ({netStatus.filtering_count} connections filtered)
                </span>
              )}
            </div>
            {netStatus?.mock_mode && (
              <span className="text-xs px-2 py-0.5 rounded-full bg-[var(--color-warning)]/15 text-[var(--color-warning)]">
                Mock Mode
              </span>
            )}
          </div>

          {/* Enable network filtering */}
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">Enable Network Filtering</p>
              <p className="text-xs text-[var(--color-text-secondary)]">Filter outbound connections from AI agents</p>
            </div>
            <ToggleSwitch
              checked={netSettings.filter_enabled}
              onChange={(v) => updateNetField("filter_enabled", v)}
            />
          </div>

          {/* Enable DNS filtering */}
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">Enable DNS Filtering</p>
              <p className="text-xs text-[var(--color-text-secondary)]">Monitor and filter DNS queries</p>
            </div>
            <ToggleSwitch
              checked={netSettings.dns_enabled}
              onChange={(v) => updateNetField("dns_enabled", v)}
            />
          </div>

          {/* Filter all processes */}
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">Filter All Processes</p>
              <p className="text-xs text-[var(--color-warning)]">Warning: may affect system performance</p>
            </div>
            <input
              type="checkbox"
              checked={netSettings.filter_all_processes}
              onChange={(e) => updateNetField("filter_all_processes", e.target.checked)}
              className="w-4 h-4 accent-[var(--color-accent)]"
            />
          </div>

          {/* Default action */}
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">Default Action</p>
              <p className="text-xs text-[var(--color-text-secondary)]">Action for unmatched connections</p>
            </div>
            <select
              value={netSettings.default_action}
              onChange={(e) => updateNetField("default_action", e.target.value as NetworkSettings["default_action"])}
              className="px-3 py-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-primary)] text-sm text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)]"
            >
              <option value="prompt">Prompt</option>
              <option value="block">Block</option>
              <option value="allow">Allow</option>
            </select>
          </div>

          {/* Prompt timeout */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <div>
                <p className="text-sm font-medium">Prompt Timeout</p>
                <p className="text-xs text-[var(--color-text-secondary)]">Auto-deny after timeout</p>
              </div>
              <span className="text-sm text-[var(--color-text-secondary)]">{netSettings.prompt_timeout}s</span>
            </div>
            <input
              type="range"
              min={5}
              max={60}
              step={5}
              value={netSettings.prompt_timeout}
              onChange={(e) => updateNetField("prompt_timeout", Number(e.target.value))}
              className="w-full accent-[var(--color-accent)]"
            />
            <div className="flex justify-between text-xs text-[var(--color-text-secondary)]">
              <span>5s</span>
              <span>60s</span>
            </div>
          </div>

          {/* Block private ranges */}
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">Block Private Ranges</p>
              <p className="text-xs text-[var(--color-text-secondary)]">Block connections to private/internal networks</p>
            </div>
            <input
              type="checkbox"
              checked={netSettings.block_private_ranges}
              onChange={(e) => updateNetField("block_private_ranges", e.target.checked)}
              className="w-4 h-4 accent-[var(--color-accent)]"
            />
          </div>

          {/* Block DoH */}
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">Block DNS-over-HTTPS</p>
              <p className="text-xs text-[var(--color-text-secondary)]">Prevent DNS bypass via encrypted DNS</p>
            </div>
            <input
              type="checkbox"
              checked={netSettings.block_doh}
              onChange={(e) => updateNetField("block_doh", e.target.checked)}
              className="w-4 h-4 accent-[var(--color-accent)]"
            />
          </div>

          {/* Log DNS */}
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">Log All DNS Queries</p>
              <p className="text-xs text-[var(--color-text-secondary)]">Record all DNS lookups for audit</p>
            </div>
            <input
              type="checkbox"
              checked={netSettings.log_dns}
              onChange={(e) => updateNetField("log_dns", e.target.checked)}
              className="w-4 h-4 accent-[var(--color-accent)]"
            />
          </div>
        </div>
      </section>

      {/* Advanced */}
      <section className="mb-8">
        <h2 className="text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wider mb-3">
          Advanced
        </h2>
        <div className="space-y-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4">
          {/* Log level */}
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">Log Level</p>
              <p className="text-xs text-[var(--color-text-secondary)]">Verbosity of daemon logs</p>
            </div>
            <select
              value={settings.log_level}
              onChange={(e) => updateField("log_level", e.target.value as AppSettings["log_level"])}
              className="px-3 py-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-primary)] text-sm text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)]"
            >
              <option value="trace">Trace</option>
              <option value="debug">Debug</option>
              <option value="info">Info</option>
              <option value="warn">Warn</option>
              <option value="error">Error</option>
            </select>
          </div>

          {/* Event retention */}
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
              onChange={(e) => updateField("event_retention_days", Number(e.target.value))}
              className="w-20 px-3 py-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-primary)] text-sm text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)] text-center"
            />
          </div>

          {/* Export / Import / Reset */}
          <div className="flex gap-2 pt-2 border-t border-[var(--color-border)]">
            <button className="px-3 py-1.5 rounded-md text-xs border border-[var(--color-border)] hover:bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]">
              Export Config
            </button>
            <button className="px-3 py-1.5 rounded-md text-xs border border-[var(--color-border)] hover:bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]">
              Import Config
            </button>
            <button
              onClick={() => {
                setSettings(defaultSettings);
                invoke("update_settings", { settings: defaultSettings }).catch(() => {});
              }}
              className="ml-auto px-3 py-1.5 rounded-md text-xs border border-[var(--color-danger)] text-[var(--color-danger)] hover:bg-[var(--color-danger)] hover:text-white"
            >
              Reset to Defaults
            </button>
          </div>
        </div>
      </section>
    </div>
  );
}

function ToggleSwitch({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      role="switch"
      aria-checked={checked}
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
        checked ? "bg-[var(--color-accent)]" : "bg-[var(--color-border)]"
      }`}
    >
      <span
        className={`inline-block h-4 w-4 rounded-full bg-white transition-transform ${
          checked ? "translate-x-6" : "translate-x-1"
        }`}
      />
    </button>
  );
}
