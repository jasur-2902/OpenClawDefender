import { useState, useEffect, useCallback, useRef } from "react";
import { useLocation } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { emit } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-shell";
import type { AppSettings, NetworkExtensionStatus, NetworkSettings } from "../types";

interface SlmStatus {
  loaded: boolean;
  model_name: string | null;
  model_size: string | null;
  backend: string | null;
}

interface CatalogModel {
  id: string;
  display_name: string;
  family: string;
  quantization: string;
  description: string;
  filename: string;
  size_bytes: number;
  download_url: string;
  sha256: string;
  min_ram_gb: number;
  ram_required_bytes: number;
  quality_rating: number;
  tokens_per_sec_apple: number;
  tokens_per_sec_intel: number;
  is_default: boolean;
  author: string;
  model_page_url: string;
}

interface SystemCapabilities {
  total_ram_bytes: number;
  total_ram_gb: number;
  arch: string;
  is_apple_silicon: boolean;
}

interface InstalledModelInfo {
  filename: string;
  size_bytes: number;
  catalog_id: string | null;
  display_name: string | null;
}

interface DownloadProgress {
  task_id: string;
  status: string | { failed: string };
  bytes_downloaded: number;
  bytes_total: number;
  speed_bytes_per_sec: number;
  eta_seconds: number;
  percent: number;
}

interface ActiveModelInfo {
  model_type: string;
  model_id: string | null;
  model_name: string;
  file_path: string | null;
  provider: string | null;
  size_bytes: number | null;
  using_gpu: boolean;
  total_inferences: number;
  avg_latency_ms: number;
}

interface CloudProvider {
  id: string;
  display_name: string;
  models: CloudModel[];
  api_endpoint: string;
}

interface CloudModel {
  id: string;
  display_name: string;
  cost_per_1k_input: number;
  cost_per_1k_output: number;
  recommended: boolean;
}

interface ConnectionTestResult {
  success: boolean;
  latency_ms: number;
  error?: string;
  model_name: string;
}

interface CloudUsageStats {
  provider: string;
  model: string;
  total_requests: number;
  tokens_in: number;
  tokens_out: number;
  estimated_cost_usd: number;
}

// --- Helper functions ---

/** Extract the status type string from DownloadStatus.
 *  Rust's serde serializes unit variants as strings ("downloading")
 *  but Failed(String) as an object: {"failed":"msg"}.  */
function getStatusType(status: string | { failed: string } | unknown): string {
  if (typeof status === "string") return status;
  if (typeof status === "object" && status !== null) {
    const keys = Object.keys(status);
    if (keys.length > 0) return keys[0];
  }
  return "unknown";
}

function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(0)} MB`;
  return `${(bytes / 1024).toFixed(0)} KB`;
}

function formatSpeed(bytesPerSec: number): string {
  return `${(bytesPerSec / (1024 * 1024)).toFixed(1)} MB/s`;
}

function QualityStars({ rating }: { rating: number }) {
  return (
    <span className="text-[var(--color-warning)]">
      {Array.from({ length: 5 }, (_, i) => (i < rating ? "\u2605" : "\u2606")).join("")}
    </span>
  );
}

const defaultSettings: AppSettings = {
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
  const location = useLocation();
  const [settings, setSettings] = useState<AppSettings>(defaultSettings);
  const [loading, setLoading] = useState(true);
  const [netStatus, setNetStatus] = useState<NetworkExtensionStatus | null>(null);
  const [netSettings, setNetSettings] = useState<NetworkSettings>(defaultNetworkSettings);
  const [saveStatus, setSaveStatus] = useState<"idle" | "saving" | "saved" | "error">("idle");
  const [exportStatus, setExportStatus] = useState<string | null>(null);
  const [slmStatus, setSlmStatus] = useState<SlmStatus | null>(null);

  // --- Model management state ---
  const [catalog, setCatalog] = useState<CatalogModel[]>([]);
  const [installedModels, setInstalledModels] = useState<InstalledModelInfo[]>([]);
  const [activeModel, setActiveModel] = useState<ActiveModelInfo | null>(null);
  const [systemCaps, setSystemCaps] = useState<SystemCapabilities | null>(null);
  const [downloads, setDownloads] = useState<Record<string, string>>({}); // modelId -> taskId
  const [downloadProgress, setDownloadProgress] = useState<Record<string, DownloadProgress>>({});
  const [downloadErrors, setDownloadErrors] = useState<Record<string, string>>({});
  const [activatingModel, setActivatingModel] = useState<string | null>(null);
  const [deletingModel, setDeletingModel] = useState<string | null>(null);
  const [customModelPath, setCustomModelPath] = useState("");
  const [customModelError, setCustomModelError] = useState<string | null>(null);
  const [customModelActivating, setCustomModelActivating] = useState(false);

  // Cloud API state
  const [cloudExpanded, setCloudExpanded] = useState(false);
  const [cloudProviders, setCloudProviders] = useState<CloudProvider[]>([]);
  const [selectedProvider, setSelectedProvider] = useState("");
  const [selectedCloudModel, setSelectedCloudModel] = useState("");
  const [apiKeyInput, setApiKeyInput] = useState("");
  const [showApiKey, setShowApiKey] = useState(false);
  const [hasApiKey, setHasApiKey] = useState(false);
  const [cloudTesting, setCloudTesting] = useState(false);
  const [cloudTestResult, setCloudTestResult] = useState<ConnectionTestResult | null>(null);
  const [cloudUsage, setCloudUsage] = useState<CloudUsageStats | null>(null);

  const downloadPollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const pollFailCountRef = useRef<Record<string, number>>({});

  const loadSlmStatus = useCallback(async () => {
    try {
      const s = await invoke<SlmStatus>("get_slm_status");
      setSlmStatus(s);
    } catch {
      setSlmStatus(null);
    }
  }, []);

  const loadModelData = useCallback(async () => {
    try {
      const [cat, installed, active, caps] = await Promise.all([
        invoke<CatalogModel[]>("get_model_catalog").catch(() => []),
        invoke<InstalledModelInfo[]>("get_installed_models").catch(() => []),
        invoke<ActiveModelInfo | null>("get_active_model").catch(() => null),
        invoke<SystemCapabilities>("get_system_capabilities").catch(() => null),
      ]);
      setCatalog(cat);
      setInstalledModels(installed);
      setActiveModel(active);
      setSystemCaps(caps);
    } catch {
      // Model data not available
    }
  }, []);

  const loadCloudProviders = useCallback(async () => {
    try {
      const providers = await invoke<CloudProvider[]>("get_cloud_providers");
      setCloudProviders(providers);
      if (providers.length > 0 && !selectedProvider) {
        setSelectedProvider(providers[0].id);
        if (providers[0].models.length > 0) {
          setSelectedCloudModel(providers[0].models[0].id);
        }
      }
    } catch {
      // Cloud providers not available
    }
  }, [selectedProvider]);

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
    loadSlmStatus();
    loadModelData();
    // Sync autostart state from the OS
    invoke<boolean>("is_autostart_enabled")
      .then((enabled) => {
        setSettings((s) => ({ ...s, auto_start_daemon: enabled }));
      })
      .catch(() => {});
  }, [loadSettings, loadNetworkState, loadSlmStatus, loadModelData]);

  // Scroll to a section if navigated with scrollTo state (e.g. from Dashboard)
  useEffect(() => {
    if (!loading && location.state && (location.state as { scrollTo?: string }).scrollTo) {
      const id = (location.state as { scrollTo: string }).scrollTo;
      const el = document.getElementById(id);
      if (el) {
        el.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    }
  }, [loading, location.state]);

  // Poll download progress when downloads are active
  useEffect(() => {
    const activeDownloadIds = Object.values(downloads);
    if (activeDownloadIds.length === 0) {
      if (downloadPollRef.current) {
        clearInterval(downloadPollRef.current);
        downloadPollRef.current = null;
      }
      return;
    }

    downloadPollRef.current = setInterval(async () => {
      const newProgress: Record<string, DownloadProgress> = {};
      const newErrors: Record<string, string> = {};
      let anyCompleted = false;
      for (const [modelId, taskId] of Object.entries(downloads)) {
        try {
          const prog = await invoke<DownloadProgress>("get_download_progress", { taskId });
          newProgress[modelId] = prog;
          pollFailCountRef.current[modelId] = 0; // reset on success
          const st = getStatusType(prog.status);
          if (st === "completed" || st === "failed" || st === "cancelled") {
            anyCompleted = true;
          }
        } catch (err) {
          const errMsg = err instanceof Error ? err.message : String(err);
          console.error("Progress fetch failed for task", taskId, errMsg);
          const count = (pollFailCountRef.current[modelId] || 0) + 1;
          pollFailCountRef.current[modelId] = count;
          // After 10 consecutive failures (5 seconds), surface error and stop
          if (count >= 10) {
            newErrors[modelId] = `Connection lost: ${errMsg}`;
            anyCompleted = true; // trigger cleanup
          }
        }
      }
      setDownloadProgress(newProgress);
      if (Object.keys(newErrors).length > 0) {
        setDownloadErrors((prev) => ({ ...prev, ...newErrors }));
      }

      if (anyCompleted) {
        // Capture error messages from failed downloads before cleanup
        for (const modelId of Object.keys(newProgress)) {
          const prog = newProgress[modelId];
          const st = prog ? getStatusType(prog.status) : null;
          if (st === "failed") {
            const failedMsg = typeof prog.status === "object" && prog.status !== null
              ? (prog.status as { failed: string }).failed
              : "Download failed";
            setDownloadErrors((prev) => ({ ...prev, [modelId]: failedMsg }));
          } else if (st === "cancelled") {
            setDownloadErrors((prev) => ({ ...prev, [modelId]: "Download cancelled" }));
          }
        }
        // Clean up completed/failed/cancelled downloads from active tracking
        setDownloads((prev) => {
          const next = { ...prev };
          for (const modelId of Object.keys(next)) {
            const prog = newProgress[modelId];
            const st = prog ? getStatusType(prog.status) : null;
            if (prog && (st === "completed" || st === "failed" || st === "cancelled")) {
              delete next[modelId];
            }
          }
          return next;
        });
        // Refresh installed models
        loadModelData();
      }
    }, 500);

    return () => {
      if (downloadPollRef.current) {
        clearInterval(downloadPollRef.current);
        downloadPollRef.current = null;
      }
    };
  }, [downloads, loadModelData]);

  // Check API key when provider changes
  useEffect(() => {
    if (selectedProvider) {
      invoke<boolean>("has_cloud_api_key", { provider: selectedProvider })
        .then(setHasApiKey)
        .catch(() => setHasApiKey(false));
    }
  }, [selectedProvider]);

  async function handleDownloadModel(modelId: string) {
    // Clear any previous error
    setDownloadErrors((prev) => {
      const next = { ...prev };
      delete next[modelId];
      return next;
    });
    try {
      const taskId = await invoke<string>("download_model", { modelId });
      setDownloads((prev) => ({ ...prev, [modelId]: taskId }));
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err);
      console.error("Download failed:", errMsg);
      setDownloadErrors((prev) => ({ ...prev, [modelId]: errMsg }));
    }
  }

  async function handleCancelDownload(modelId: string) {
    const taskId = downloads[modelId];
    if (taskId) {
      try {
        await invoke("cancel_download", { taskId });
      } catch (err) {
        console.error("Cancel download failed:", err);
      }
      setDownloads((prev) => {
        const next = { ...prev };
        delete next[modelId];
        return next;
      });
      setDownloadProgress((prev) => {
        const next = { ...prev };
        delete next[modelId];
        return next;
      });
    }
  }

  async function handleActivateModel(modelId: string) {
    setActivatingModel(modelId);
    try {
      const info = await invoke<ActiveModelInfo>("activate_model", { modelId });
      setActiveModel(info);
      await loadSlmStatus();
    } catch (err) {
      console.error("Activate failed:", err);
    } finally {
      setActivatingModel(null);
    }
  }

  async function handleDeactivateModel() {
    try {
      await invoke("deactivate_model");
      setActiveModel(null);
      await loadSlmStatus();
    } catch (err) {
      console.error("Deactivate failed:", err);
    }
  }

  async function handleDeleteModel(modelId: string) {
    setDeletingModel(modelId);
    try {
      await invoke("delete_model", { modelId });
      await loadModelData();
    } catch (err) {
      console.error("Delete failed:", err);
    } finally {
      setDeletingModel(null);
    }
  }

  async function handleActivateCustomModel() {
    if (!customModelPath.trim()) {
      setCustomModelError("Please enter a path to a .gguf model file");
      return;
    }
    if (!customModelPath.endsWith(".gguf")) {
      setCustomModelError("File must be a .gguf model file");
      return;
    }
    setCustomModelError(null);
    setCustomModelActivating(true);
    try {
      const info = await invoke<ActiveModelInfo>("activate_model", { modelId: customModelPath });
      setActiveModel(info);
      setCustomModelPath("");
      await loadSlmStatus();
    } catch (err) {
      setCustomModelError(`Failed to activate: ${err}`);
    } finally {
      setCustomModelActivating(false);
    }
  }

  async function handleSaveAndTestCloud() {
    if (!selectedProvider || !apiKeyInput.trim()) return;
    setCloudTesting(true);
    setCloudTestResult(null);
    try {
      await invoke("save_api_key", { provider: selectedProvider, key: apiKeyInput.trim() });
      setHasApiKey(true);
      const result = await invoke<ConnectionTestResult>("test_api_connection", {
        provider: selectedProvider,
        model: selectedCloudModel,
      });
      setCloudTestResult(result);
      if (result.success) {
        setApiKeyInput("");
      }
    } catch (err) {
      setCloudTestResult({ success: false, latency_ms: 0, error: String(err), model_name: "" });
    } finally {
      setCloudTesting(false);
    }
  }

  async function handleActivateCloud() {
    if (!selectedProvider || !selectedCloudModel) return;
    try {
      const info = await invoke<ActiveModelInfo>("activate_cloud_provider", {
        provider: selectedProvider,
        model: selectedCloudModel,
      });
      setActiveModel(info);
      // Load usage stats
      const usage = await invoke<CloudUsageStats>("get_cloud_usage").catch(() => null);
      setCloudUsage(usage);
    } catch (err) {
      console.error("Cloud activation failed:", err);
    }
  }

  async function handleClearApiKey() {
    if (!selectedProvider) return;
    try {
      await invoke("clear_api_key", { provider: selectedProvider });
      setHasApiKey(false);
      setApiKeyInput("");
      setCloudTestResult(null);
    } catch {
      // Clear may fail
    }
  }

  function getModelStatus(modelId: string): "active" | "downloaded" | "not_downloaded" | "downloading" {
    if (activeModel?.model_id === modelId) return "active";
    if (downloads[modelId]) return "downloading";
    if (installedModels.some((m) => m.catalog_id === modelId)) return "downloaded";
    return "not_downloaded";
  }

  const currentProvider = cloudProviders.find((p) => p.id === selectedProvider);
  const isCloudActive = activeModel?.model_type === "cloud";

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
    setSaveStatus("saving");
    try {
      await invoke("update_settings", { settings: next });
      setSaveStatus("saved");
      setTimeout(() => setSaveStatus("idle"), 2000);
    } catch (_err) {
      setSaveStatus("error");
      setTimeout(() => setSaveStatus("idle"), 3000);
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
      <div className="flex items-center gap-3 mb-6">
        <h1 className="text-2xl font-bold">Settings</h1>
        {saveStatus === "saving" && (
          <span className="text-xs text-[var(--color-text-secondary)]">Saving...</span>
        )}
        {saveStatus === "saved" && (
          <span className="text-xs text-[var(--color-success)]">Saved</span>
        )}
        {saveStatus === "error" && (
          <span className="text-xs text-[var(--color-danger)]">Save failed</span>
        )}
      </div>

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
              onChange={(e) => {
                const newTheme = e.target.value as AppSettings["theme"];
                updateField("theme", newTheme);
                emit("clawdefender://theme-changed", newTheme);
              }}
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
              onChange={async (v) => {
                try {
                  if (v) {
                    await invoke("enable_autostart");
                  } else {
                    await invoke("disable_autostart");
                  }
                  updateField("auto_start_daemon", v);
                } catch (_err) {
                  // Autostart toggle failed
                }
              }}
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
              value={settings.security_level}
              onChange={(e) => {
                const level = e.target.value;
                setSettings((s) => ({ ...s, security_level: level }));
                // Apply the template (maps monitor-only to permissive for backend)
                const templateName = level === "monitor-only" ? "permissive" : level;
                invoke("apply_template", { name: templateName }).then(() => {
                  // Reload settings to get the inferred security level
                  invoke<AppSettings>("get_settings").then((s) => setSettings(s)).catch(() => {});
                }).catch(() => {});
              }}
              className="px-3 py-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-primary)] text-sm text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)]"
            >
              <option value="monitor-only">Monitor Only</option>
              <option value="balanced">Balanced</option>
              <option value="strict">Strict</option>
              {settings.security_level === "custom" && (
                <option value="custom">Custom</option>
              )}
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

      {/* AI Model */}
      <section className="mb-8">
        <h2 className="text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wider mb-3">
          AI Model
        </h2>

        {/* Section 1: Active Model Status */}
        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4 mb-4">
          {activeModel ? (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="inline-block w-2 h-2 rounded-full bg-[var(--color-success)]" />
                  <p className="text-sm font-medium">{activeModel.model_name}</p>
                  <span className="text-xs px-2 py-0.5 rounded-full bg-[var(--color-success)]/15 text-[var(--color-success)]">
                    Active
                  </span>
                  {activeModel.using_gpu && (
                    <span className="text-xs px-2 py-0.5 rounded-full bg-[var(--color-accent)]/15 text-[var(--color-accent)]">
                      GPU
                    </span>
                  )}
                </div>
                <button
                  onClick={handleDeactivateModel}
                  className="px-3 py-1 rounded-md text-xs border border-[var(--color-border)] hover:bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
                >
                  Change Model
                </button>
              </div>
              <div className="grid grid-cols-3 gap-3 text-sm">
                <div>
                  <span className="text-[var(--color-text-secondary)] text-xs">Type</span>
                  <p className="text-[var(--color-text-primary)] text-xs font-medium capitalize">{activeModel.model_type}</p>
                </div>
                {activeModel.size_bytes != null && (
                  <div>
                    <span className="text-[var(--color-text-secondary)] text-xs">Size</span>
                    <p className="text-[var(--color-text-primary)] text-xs font-medium">{formatBytes(activeModel.size_bytes)}</p>
                  </div>
                )}
                {slmStatus?.backend && (
                  <div>
                    <span className="text-[var(--color-text-secondary)] text-xs">Backend</span>
                    <p className="text-[var(--color-text-primary)] text-xs font-medium">{slmStatus.backend}</p>
                  </div>
                )}
                {activeModel.total_inferences > 0 && (
                  <div>
                    <span className="text-[var(--color-text-secondary)] text-xs">Inferences</span>
                    <p className="text-[var(--color-text-primary)] text-xs font-medium">{activeModel.total_inferences.toLocaleString()}</p>
                  </div>
                )}
                {activeModel.avg_latency_ms > 0 && (
                  <div>
                    <span className="text-[var(--color-text-secondary)] text-xs">Avg Latency</span>
                    <p className="text-[var(--color-text-primary)] text-xs font-medium">{activeModel.avg_latency_ms.toFixed(0)}ms</p>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="text-center py-4">
              <p className="text-sm font-medium text-[var(--color-text-primary)] mb-1">No AI Model Active</p>
              <p className="text-xs text-[var(--color-text-secondary)] mb-3">
                Set up an AI model to enable intelligent security analysis
              </p>
              <span className="inline-block px-4 py-1.5 rounded-full bg-[var(--color-success)]/15 text-[var(--color-success)] text-xs font-medium">
                Choose a model below to get started
              </span>
            </div>
          )}
        </div>

        {/* Section 2: Local Models */}
        <div className="rounded-lg border border-[var(--color-success)]/30 bg-[var(--color-bg-secondary)] p-4 mb-4">
          <div className="flex items-center gap-2 mb-3">
            <h3 className="text-sm font-semibold text-[var(--color-text-primary)]">
              Local Models — Private, Fast, Free
            </h3>
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-[var(--color-success)]/15 text-[var(--color-success)] font-medium">
              Recommended
            </span>
          </div>
          <p className="text-xs text-[var(--color-text-secondary)] mb-3">
            Runs entirely on your machine. No data leaves your device.
          </p>

          {/* System info banner */}
          {systemCaps && (
            <div className="flex items-center gap-3 rounded-md bg-[var(--color-bg-tertiary)] border border-[var(--color-border)] px-3 py-2 mb-3">
              <span className="text-xs text-[var(--color-text-secondary)]">
                Your Mac: {systemCaps.is_apple_silicon ? "Apple Silicon" : systemCaps.arch} · {systemCaps.total_ram_gb} GB RAM
              </span>
            </div>
          )}

          <div className="space-y-3">
            {catalog.map((model) => {
              const status = getModelStatus(model.id);
              const progress = downloadProgress[model.id];
              const dlError = downloadErrors[model.id];
              const isActive = status === "active";
              const speedEstimate = systemCaps?.is_apple_silicon
                ? model.tokens_per_sec_apple
                : model.tokens_per_sec_intel;
              const ramGb = model.min_ram_gb;
              const isRecommended = model.is_default || (systemCaps && (
                (systemCaps.total_ram_gb < 8 && model.id.includes("1b")) ||
                (systemCaps.total_ram_gb >= 8 && systemCaps.total_ram_gb < 16 && model.id.includes("1.7b")) ||
                (systemCaps.total_ram_gb >= 16 && model.id.includes("4b"))
              ));

              return (
                <div
                  key={model.id}
                  className={`rounded-lg border p-3 ${
                    isActive
                      ? "border-[var(--color-success)] bg-[var(--color-success)]/5"
                      : isRecommended
                      ? "border-[var(--color-accent)]/50 bg-[var(--color-bg-tertiary)]"
                      : "border-[var(--color-border)] bg-[var(--color-bg-tertiary)]"
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-0.5">
                        <p className="text-sm font-semibold text-[var(--color-text-primary)]">{model.display_name}</p>
                        {isActive && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-[var(--color-success)]/15 text-[var(--color-success)] font-medium">
                            Active
                          </span>
                        )}
                        {status === "downloaded" && !isActive && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-[var(--color-accent)]/15 text-[var(--color-accent)] font-medium">
                            Downloaded
                          </span>
                        )}
                        {isRecommended && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-[var(--color-warning)]/15 text-[var(--color-warning)] font-medium">
                            Recommended for your Mac
                          </span>
                        )}
                      </div>
                      <p className="text-[11px] text-[var(--color-text-secondary)] mb-1.5">
                        {model.quantization} · by {model.author}
                      </p>
                      <p className="text-xs text-[var(--color-text-secondary)] mb-2">{model.description}</p>
                      <div className="flex flex-wrap items-center gap-3 text-xs text-[var(--color-text-secondary)]">
                        <span>{formatBytes(model.size_bytes)} download</span>
                        <span>~{ramGb} GB RAM</span>
                        <QualityStars rating={model.quality_rating} />
                        {speedEstimate > 0 && <span>~{speedEstimate} tok/s</span>}
                      </div>
                      {model.model_page_url && (
                        <button
                          onClick={() => open(model.model_page_url)}
                          className="mt-2 text-[11px] text-[var(--color-accent)] hover:underline"
                        >
                          View on HuggingFace
                        </button>
                      )}
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      {status === "not_downloaded" && (
                        <button
                          onClick={() => handleDownloadModel(model.id)}
                          className="px-3 py-1.5 rounded-md text-xs font-medium bg-[var(--color-success)] text-white hover:opacity-90"
                        >
                          Download
                        </button>
                      )}
                      {status === "downloading" && (
                        <button
                          onClick={() => handleCancelDownload(model.id)}
                          className="px-3 py-1.5 rounded-md text-xs border border-[var(--color-danger)] text-[var(--color-danger)] hover:bg-[var(--color-danger)] hover:text-white"
                        >
                          Cancel
                        </button>
                      )}
                      {status === "downloaded" && (
                        <>
                          <button
                            onClick={() => handleActivateModel(model.id)}
                            disabled={activatingModel === model.id}
                            className="px-3 py-1.5 rounded-md text-xs font-medium bg-[var(--color-accent)] text-white hover:opacity-90 disabled:opacity-50"
                          >
                            {activatingModel === model.id ? "Activating..." : "Activate"}
                          </button>
                          <button
                            onClick={() => handleDeleteModel(model.id)}
                            disabled={deletingModel === model.id}
                            className="px-2 py-1.5 rounded-md text-xs border border-[var(--color-danger)]/50 text-[var(--color-danger)] hover:bg-[var(--color-danger)] hover:text-white disabled:opacity-50"
                            title="Delete model"
                          >
                            {deletingModel === model.id ? "..." : "Delete"}
                          </button>
                        </>
                      )}
                      {isActive && (
                        <span className="text-xs text-[var(--color-success)] font-medium">In Use</span>
                      )}
                    </div>
                  </div>

                  {/* Download progress / error feedback */}
                  {status === "downloading" && (
                    <div className="mt-3 pt-3 border-t border-[var(--color-border)]">
                      {dlError && !progress ? (
                        <div className="flex items-center justify-between">
                          <p className="text-xs text-[var(--color-danger)] flex-1">{dlError}</p>
                          <button
                            onClick={() => { handleCancelDownload(model.id); handleDownloadModel(model.id); }}
                            className="ml-3 px-2 py-1 rounded text-[10px] font-medium bg-[var(--color-accent)] text-white hover:opacity-90 shrink-0"
                          >
                            Retry
                          </button>
                        </div>
                      ) : !progress ? (
                        <p className="text-xs text-[var(--color-text-secondary)] animate-pulse">
                          Connecting to server...
                        </p>
                      ) : (() => {
                        const st = getStatusType(progress.status);
                        const failedMsg = typeof progress.status === "object" && progress.status !== null
                          ? (progress.status as { failed: string }).failed
                          : null;
                        return st === "failed" ? (
                          <div className="flex items-center justify-between">
                            <p className="text-xs text-[var(--color-danger)] flex-1">
                              {failedMsg || "Download failed"}
                            </p>
                            <button
                              onClick={() => { handleCancelDownload(model.id); handleDownloadModel(model.id); }}
                              className="ml-3 px-2 py-1 rounded text-[10px] font-medium bg-[var(--color-accent)] text-white hover:opacity-90 shrink-0"
                            >
                              Retry
                            </button>
                          </div>
                        ) : (
                          <>
                            <div className="flex items-center justify-between text-xs text-[var(--color-text-secondary)] mb-1.5">
                              <span>
                                {formatBytes(progress.bytes_downloaded)} / {formatBytes(progress.bytes_total)}
                              </span>
                              <span>
                                {st === "pending" ? "Connecting..." : (
                                  <>
                                    {formatSpeed(progress.speed_bytes_per_sec)}
                                    {progress.eta_seconds > 0 && ` · ~${Math.ceil(progress.eta_seconds)}s remaining`}
                                  </>
                                )}
                              </span>
                            </div>
                            <div className="w-full h-2.5 rounded-full bg-[var(--color-bg-primary)] overflow-hidden">
                              <div
                                className={`h-full rounded-full transition-all duration-300 ${
                                  st === "verifying"
                                    ? "bg-[var(--color-warning)] animate-pulse"
                                    : "bg-gradient-to-r from-[var(--color-accent)] to-[var(--color-success)]"
                                }`}
                                style={{ width: `${Math.max(Math.min(progress.percent, 100), st === "downloading" ? 1 : 0)}%` }}
                              />
                            </div>
                            <p className="text-[10px] text-[var(--color-text-secondary)] mt-1 text-right">
                              {st === "verifying" ? "Verifying checksum..." : `${progress.percent.toFixed(1)}%`}
                            </p>
                          </>
                        );
                      })()}
                    </div>
                  )}
                  {/* Show download error with retry option */}
                  {status !== "downloading" && dlError && (
                    <div className="mt-3 pt-3 border-t border-[var(--color-danger)]/30">
                      <div className="flex items-center justify-between">
                        <p className="text-xs text-[var(--color-danger)] flex-1">{dlError}</p>
                        <div className="flex items-center gap-2 ml-3 shrink-0">
                          <button
                            onClick={() => handleDownloadModel(model.id)}
                            className="px-2 py-1 rounded text-[10px] font-medium bg-[var(--color-accent)] text-white hover:opacity-90"
                          >
                            Retry
                          </button>
                          <button
                            onClick={() => setDownloadErrors((prev) => { const next = { ...prev }; delete next[model.id]; return next; })}
                            className="px-2 py-1 rounded text-[10px] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
                          >
                            Dismiss
                          </button>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}

            {catalog.length === 0 && (
              <p className="text-xs text-[var(--color-text-secondary)] text-center py-4">
                No models available in catalog. Check your internet connection.
              </p>
            )}
          </div>
        </div>

        {/* Section 3: Custom Model */}
        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4 mb-4">
          <h3 className="text-sm font-semibold text-[var(--color-text-primary)] mb-1">Use Your Own Model</h3>
          <p className="text-xs text-[var(--color-text-secondary)] mb-3">
            Load a custom .gguf model file from your local filesystem
          </p>
          <div className="flex gap-2">
            <input
              type="text"
              value={customModelPath}
              onChange={(e) => {
                setCustomModelPath(e.target.value);
                setCustomModelError(null);
              }}
              placeholder="/path/to/model.gguf"
              className="flex-1 px-3 py-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-primary)] text-sm text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)] font-mono text-xs"
            />
            <button
              onClick={handleActivateCustomModel}
              disabled={customModelActivating}
              className="px-3 py-1.5 rounded-md text-xs font-medium bg-[var(--color-accent)] text-white hover:opacity-90 disabled:opacity-50"
            >
              {customModelActivating ? "Activating..." : "Activate"}
            </button>
          </div>
          {customModelError && (
            <p className="text-xs text-[var(--color-danger)] mt-2">{customModelError}</p>
          )}
        </div>

        {/* Section 4: Cloud API (collapsed) */}
        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] mb-4">
          <button
            onClick={() => {
              setCloudExpanded(!cloudExpanded);
              if (!cloudExpanded && cloudProviders.length === 0) {
                loadCloudProviders();
              }
            }}
            className="w-full flex items-center justify-between p-4 text-left"
          >
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold text-[var(--color-text-secondary)]">Advanced: Cloud API</h3>
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-[var(--color-warning)]/15 text-[var(--color-warning)] font-medium">
                Not Recommended
              </span>
            </div>
            <span className="text-[var(--color-text-secondary)] text-xs">{cloudExpanded ? "\u25B2" : "\u25BC"}</span>
          </button>

          {cloudExpanded && (
            <div className="px-4 pb-4 space-y-4">
              {/* Warning */}
              <div className="rounded-lg bg-[var(--color-warning)]/10 border border-[var(--color-warning)]/30 p-3">
                <p className="text-xs text-[var(--color-warning)] font-medium mb-1">Not Recommended</p>
                <p className="text-xs text-[var(--color-text-secondary)]">
                  Cloud API sends security event metadata to third-party servers, is slower than local models (500ms+ vs 50ms),
                  costs money per analysis ($5-20/month with typical usage), and requires internet connectivity. Local models
                  are private, fast, free, and work offline.
                </p>
              </div>

              {isCloudActive && (
                <div className="flex items-center justify-between rounded-lg bg-[var(--color-bg-tertiary)] p-3">
                  <div>
                    <p className="text-xs font-medium text-[var(--color-text-primary)]">Cloud model is active</p>
                    {cloudUsage && (
                      <p className="text-xs text-[var(--color-text-secondary)]">
                        This session: {cloudUsage.total_requests} analyses, ~${cloudUsage.estimated_cost_usd.toFixed(2)}
                      </p>
                    )}
                  </div>
                  <button
                    onClick={handleDeactivateModel}
                    className="px-3 py-1.5 rounded-md text-xs font-medium bg-[var(--color-success)] text-white hover:opacity-90"
                  >
                    Switch to Local Model
                  </button>
                </div>
              )}

              {/* Provider */}
              <div>
                <label className="text-xs text-[var(--color-text-secondary)] block mb-1">Provider</label>
                <select
                  value={selectedProvider}
                  onChange={(e) => {
                    setSelectedProvider(e.target.value);
                    setCloudTestResult(null);
                    const provider = cloudProviders.find((p) => p.id === e.target.value);
                    if (provider && provider.models.length > 0) {
                      setSelectedCloudModel(provider.models[0].id);
                    }
                  }}
                  className="w-full px-3 py-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-primary)] text-sm text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)]"
                >
                  {cloudProviders.map((p) => (
                    <option key={p.id} value={p.id}>{p.display_name}</option>
                  ))}
                </select>
              </div>

              {/* API Key */}
              <div>
                <label className="text-xs text-[var(--color-text-secondary)] block mb-1">
                  API Key {hasApiKey && <span className="text-[var(--color-success)]">(saved)</span>}
                </label>
                <div className="flex gap-2">
                  <div className="flex-1 relative">
                    <input
                      type={showApiKey ? "text" : "password"}
                      value={apiKeyInput}
                      onChange={(e) => setApiKeyInput(e.target.value)}
                      placeholder={hasApiKey ? "Key saved — enter new key to update" : "Enter API key"}
                      className="w-full px-3 py-1.5 pr-16 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-primary)] text-sm text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)] font-mono text-xs"
                    />
                    <button
                      onClick={() => setShowApiKey(!showApiKey)}
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-[10px] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
                    >
                      {showApiKey ? "Hide" : "Show"}
                    </button>
                  </div>
                  {hasApiKey && (
                    <button
                      onClick={handleClearApiKey}
                      className="px-2 py-1.5 rounded-md text-xs border border-[var(--color-danger)]/50 text-[var(--color-danger)] hover:bg-[var(--color-danger)] hover:text-white"
                    >
                      Clear
                    </button>
                  )}
                </div>
              </div>

              {/* Model selection */}
              <div>
                <label className="text-xs text-[var(--color-text-secondary)] block mb-1">Model</label>
                <select
                  value={selectedCloudModel}
                  onChange={(e) => {
                    setSelectedCloudModel(e.target.value);
                    setCloudTestResult(null);
                  }}
                  className="w-full px-3 py-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-primary)] text-sm text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)]"
                >
                  {currentProvider?.models.map((m) => (
                    <option key={m.id} value={m.id}>
                      {m.display_name}
                      {m.recommended ? " (Recommended)" : ""}
                      {` — $${m.cost_per_1k_input}/1k in, $${m.cost_per_1k_output}/1k out`}
                    </option>
                  ))}
                </select>
              </div>

              {/* Save & Test / Activate */}
              <div className="flex gap-2">
                <button
                  onClick={handleSaveAndTestCloud}
                  disabled={cloudTesting || (!apiKeyInput.trim() && !hasApiKey)}
                  className="px-3 py-1.5 rounded-md text-xs font-medium border border-[var(--color-accent)] text-[var(--color-accent)] hover:bg-[var(--color-accent)] hover:text-white disabled:opacity-50"
                >
                  {cloudTesting ? "Testing..." : "Save & Test"}
                </button>
                {hasApiKey && cloudTestResult?.success && !isCloudActive && (
                  <button
                    onClick={handleActivateCloud}
                    className="px-3 py-1.5 rounded-md text-xs font-medium bg-[var(--color-accent)] text-white hover:opacity-90"
                  >
                    Activate Cloud Model
                  </button>
                )}
              </div>

              {/* Test result */}
              {cloudTestResult && (
                <div
                  className={`rounded-lg p-3 text-xs ${
                    cloudTestResult.success
                      ? "bg-[var(--color-success)]/10 text-[var(--color-success)]"
                      : "bg-[var(--color-danger)]/10 text-[var(--color-danger)]"
                  }`}
                >
                  {cloudTestResult.success
                    ? `Connected — Latency: ${cloudTestResult.latency_ms}ms`
                    : `Failed: ${cloudTestResult.error}`}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Section 5: Model Settings */}
        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">Analysis Frequency</p>
              <p className="text-xs text-[var(--color-text-secondary)]">When to run AI analysis on events</p>
            </div>
            <select
              value={settings.analysis_frequency}
              onChange={(e) => updateField("analysis_frequency", e.target.value)}
              className="px-3 py-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-primary)] text-sm text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)]"
            >
              <option value="all">Analyze all prompted events</option>
              <option value="high_risk">Analyze high-risk events only</option>
              <option value="disabled">Disabled</option>
            </select>
          </div>
        </div>
      </section>

      {/* Network Protection */}
      <section id="network-protection" className="mb-8">
        <div className="flex items-center gap-2 mb-3">
          <h2 className="text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wider">
            Network Protection
          </h2>
          {(!netStatus || !netStatus.loaded) && (
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-[var(--color-danger)]/15 text-[var(--color-danger)] font-medium">
              Not Available
            </span>
          )}
        </div>
        {(!netStatus || !netStatus.loaded) && (
          <p className="text-xs text-[var(--color-text-secondary)] mb-3">
            Network Extension is not installed. This feature requires a macOS system extension.
          </p>
        )}
        <div className={`relative space-y-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4 ${!netStatus || !netStatus.loaded ? "select-none pointer-events-none opacity-40" : ""}`}>
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
          <div className="flex flex-col gap-2 pt-2 border-t border-[var(--color-border)]">
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
                    setSettings(defaultSettings);
                    invoke("update_settings", { settings: defaultSettings }).catch(() => {});
                  }
                }}
                className="ml-auto px-3 py-1.5 rounded-md text-xs border border-[var(--color-danger)] text-[var(--color-danger)] hover:bg-[var(--color-danger)] hover:text-white"
              >
                Reset to Defaults
              </button>
            </div>
            {exportStatus && (
              <p className="text-xs text-[var(--color-text-secondary)]">{exportStatus}</p>
            )}
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
