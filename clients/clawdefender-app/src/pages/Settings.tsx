import { useState, useEffect, useCallback, useRef } from "react";
import { useLocation } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { emit } from "@tauri-apps/api/event";
import { SectionTitle, Card, Badge, Btn, Icon, Dot } from "../components/design";
import type {
  AppSettings,
  NetworkExtensionStatus,
  NetworkSettings,
  AiStatus,
  FeatureRoutingEntry,
  FeatureRoutingResponse,
  FeatureBackendPreference,
} from "../types";

/* ---------- local types ---------- */

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

/* ---------- helpers ---------- */

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

/* ---------- small inline components ---------- */

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div style={{ fontSize: 10.5, color: "var(--ink-3)", textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 6 }}>
        {label}
      </div>
      {children}
    </div>
  );
}

function ToggleSwitch({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      role="switch"
      aria-checked={checked}
      onClick={() => onChange(!checked)}
      style={{
        position: "relative",
        display: "inline-flex",
        alignItems: "center",
        width: 44,
        height: 24,
        borderRadius: 12,
        background: checked ? "var(--accent)" : "var(--bg-3)",
        border: "1px solid " + (checked ? "var(--accent)" : "var(--line)"),
        cursor: "pointer",
        transition: "background 0.2s, border-color 0.2s",
        padding: 0,
      }}
    >
      <span
        style={{
          display: "inline-block",
          width: 16,
          height: 16,
          borderRadius: 8,
          background: "white",
          transition: "transform 0.2s",
          transform: checked ? "translateX(22px)" : "translateX(4px)",
        }}
      />
    </button>
  );
}

/* ============================================================
   SETTINGS PAGE
   ============================================================ */

export function Settings() {
  const location = useLocation();
  const [settings, setSettings] = useState<AppSettings>(defaultSettings);
  const [loading, setLoading] = useState(true);
  const [netStatus, setNetStatus] = useState<NetworkExtensionStatus | null>(null);
  const [netSettings, setNetSettings] = useState<NetworkSettings>(defaultNetworkSettings);
  const [saveStatus, setSaveStatus] = useState<"idle" | "saving" | "saved" | "error">("idle");
  const [exportStatus, setExportStatus] = useState<string | null>(null);
  const [, setSlmStatus] = useState<SlmStatus | null>(null);

  // Model management state
  const [catalog, setCatalog] = useState<CatalogModel[]>([]);
  const [installedModels, setInstalledModels] = useState<InstalledModelInfo[]>([]);
  const [activeModel, setActiveModel] = useState<ActiveModelInfo | null>(null);
  const [systemCaps, setSystemCaps] = useState<SystemCapabilities | null>(null);
  const [downloads, setDownloads] = useState<Record<string, string>>({});
  const [downloadProgress, setDownloadProgress] = useState<Record<string, DownloadProgress>>({});
  const [downloadErrors, setDownloadErrors] = useState<Record<string, string>>({});
  const [activatingModel, setActivatingModel] = useState<string | null>(null);
  const [deletingModel, setDeletingModel] = useState<string | null>(null);
  const [customModelPath, setCustomModelPath] = useState("");
  const [customModelError, setCustomModelError] = useState<string | null>(null);
  const [customModelActivating, setCustomModelActivating] = useState(false);

  // Dual AI status
  const [aiStatus, setAiStatus] = useState<AiStatus | null>(null);

  // Cloud API state
  const [cloudProviders, setCloudProviders] = useState<CloudProvider[]>([]);
  const [selectedProvider, setSelectedProvider] = useState("");
  const [selectedCloudModel, setSelectedCloudModel] = useState("");
  const [apiKeyInput, setApiKeyInput] = useState("");
  const [showApiKey, setShowApiKey] = useState(false);
  const [hasApiKey, setHasApiKey] = useState(false);
  const [cloudTesting, setCloudTesting] = useState(false);
  const [cloudTestResult, setCloudTestResult] = useState<ConnectionTestResult | null>(null);
  const [cloudUsage, setCloudUsage] = useState<CloudUsageStats | null>(null);
  const [cloudBudget, setCloudBudget] = useState(20);

  // Feature routing state
  const [featureRouting, setFeatureRouting] = useState<FeatureRoutingEntry[]>([]);
  const [featureRoutingHasOverrides, setFeatureRoutingHasOverrides] = useState(false);
  const [featureRoutingExpanded, setFeatureRoutingExpanded] = useState(false);

  const downloadPollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const pollFailCountRef = useRef<Record<string, number>>({});

  /* ---- loaders ---- */

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

  const loadAiStatus = useCallback(async () => {
    try {
      const s = await invoke<AiStatus>("get_ai_status");
      setAiStatus(s);
    } catch {
      // AI status not available
    }
  }, []);

  const loadFeatureRouting = useCallback(async () => {
    try {
      const r = await invoke<FeatureRoutingResponse>("get_feature_routing");
      setFeatureRouting(r.features);
      setFeatureRoutingHasOverrides(r.has_overrides);
    } catch {
      // Feature routing not available
    }
  }, []);

  const loadSettings = useCallback(async () => {
    try {
      const s = await invoke<AppSettings>("get_settings");
      setSettings(s);
    } catch {
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
    } catch {
      // Network extension may not be available
    }
  }, []);

  useEffect(() => {
    loadSettings();
    loadNetworkState();
    loadSlmStatus();
    loadModelData();
    loadAiStatus();
    loadCloudProviders();
    loadFeatureRouting();
    invoke<boolean>("is_autostart_enabled")
      .then((enabled) => setSettings((s) => ({ ...s, auto_start_daemon: enabled })))
      .catch(() => {});
  }, [loadSettings, loadNetworkState, loadSlmStatus, loadModelData, loadAiStatus, loadCloudProviders, loadFeatureRouting]);

  useEffect(() => {
    if (!loading && location.state && (location.state as { scrollTo?: string }).scrollTo) {
      const id = (location.state as { scrollTo: string }).scrollTo;
      const el = document.getElementById(id);
      if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [loading, location.state]);

  /* ---- download polling ---- */

  useEffect(() => {
    const activeDownloadIds = Object.values(downloads);
    if (activeDownloadIds.length === 0) {
      if (downloadPollRef.current) { clearInterval(downloadPollRef.current); downloadPollRef.current = null; }
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
          pollFailCountRef.current[modelId] = 0;
          const st = getStatusType(prog.status);
          if (st === "completed" || st === "failed" || st === "cancelled") anyCompleted = true;
        } catch (err) {
          const errMsg = err instanceof Error ? err.message : String(err);
          const count = (pollFailCountRef.current[modelId] || 0) + 1;
          pollFailCountRef.current[modelId] = count;
          if (count >= 10) { newErrors[modelId] = `Connection lost: ${errMsg}`; anyCompleted = true; }
        }
      }
      setDownloadProgress(newProgress);
      if (Object.keys(newErrors).length > 0) setDownloadErrors((prev) => ({ ...prev, ...newErrors }));
      if (anyCompleted) {
        for (const modelId of Object.keys(newProgress)) {
          const prog = newProgress[modelId];
          const st = prog ? getStatusType(prog.status) : null;
          if (st === "failed") {
            const failedMsg = typeof prog.status === "object" && prog.status !== null
              ? (prog.status as { failed: string }).failed : "Download failed";
            setDownloadErrors((prev) => ({ ...prev, [modelId]: failedMsg }));
          } else if (st === "cancelled") {
            setDownloadErrors((prev) => ({ ...prev, [modelId]: "Download cancelled" }));
          }
        }
        setDownloads((prev) => {
          const next = { ...prev };
          for (const modelId of Object.keys(next)) {
            const prog = newProgress[modelId];
            const st = prog ? getStatusType(prog.status) : null;
            if (prog && (st === "completed" || st === "failed" || st === "cancelled")) delete next[modelId];
          }
          return next;
        });
        loadModelData();
      }
    }, 500);
    return () => { if (downloadPollRef.current) { clearInterval(downloadPollRef.current); downloadPollRef.current = null; } };
  }, [downloads, loadModelData]);

  useEffect(() => {
    if (selectedProvider) {
      invoke<boolean>("has_cloud_api_key", { provider: selectedProvider }).then(setHasApiKey).catch(() => setHasApiKey(false));
    }
  }, [selectedProvider]);

  /* ---- actions ---- */

  async function handleDownloadModel(modelId: string) {
    setDownloadErrors((prev) => { const next = { ...prev }; delete next[modelId]; return next; });
    try {
      const taskId = await invoke<string>("download_model", { modelId });
      setDownloads((prev) => ({ ...prev, [modelId]: taskId }));
    } catch (err) {
      setDownloadErrors((prev) => ({ ...prev, [modelId]: err instanceof Error ? err.message : String(err) }));
    }
  }

  async function handleCancelDownload(modelId: string) {
    const taskId = downloads[modelId];
    if (taskId) {
      try { await invoke("cancel_download", { taskId }); } catch { /* noop */ }
      setDownloads((prev) => { const next = { ...prev }; delete next[modelId]; return next; });
      setDownloadProgress((prev) => { const next = { ...prev }; delete next[modelId]; return next; });
    }
  }

  async function handleActivateModel(modelId: string) {
    setActivatingModel(modelId);
    try {
      const info = await invoke<ActiveModelInfo>("activate_model", { modelId });
      setActiveModel(info);
      await Promise.all([loadSlmStatus(), loadAiStatus()]);
    } catch (err) { console.error("Activate failed:", err); }
    finally { setActivatingModel(null); }
  }

  async function handleDeactivateModel() {
    try { await invoke("deactivate_model"); setActiveModel(null); await Promise.all([loadSlmStatus(), loadAiStatus()]); }
    catch (err) { console.error("Deactivate failed:", err); }
  }

  async function handleDeleteModel(modelId: string) {
    setDeletingModel(modelId);
    try { await invoke("delete_model", { modelId }); await loadModelData(); }
    catch (err) { console.error("Delete failed:", err); }
    finally { setDeletingModel(null); }
  }

  async function handleActivateCustomModel() {
    if (!customModelPath.trim()) { setCustomModelError("Please enter a path to a .gguf model file"); return; }
    if (!customModelPath.endsWith(".gguf")) { setCustomModelError("File must be a .gguf model file"); return; }
    setCustomModelError(null);
    setCustomModelActivating(true);
    try {
      const info = await invoke<ActiveModelInfo>("activate_model", { modelId: customModelPath });
      setActiveModel(info);
      setCustomModelPath("");
      await Promise.all([loadSlmStatus(), loadAiStatus()]);
    } catch (err) { setCustomModelError(`Failed to activate: ${err}`); }
    finally { setCustomModelActivating(false); }
  }

  async function handleSaveAndTestCloud() {
    if (!selectedProvider || !apiKeyInput.trim()) return;
    setCloudTesting(true); setCloudTestResult(null);
    try {
      await invoke("save_api_key", { provider: selectedProvider, key: apiKeyInput.trim() });
      setHasApiKey(true);
      const result = await invoke<ConnectionTestResult>("test_api_connection", { provider: selectedProvider, model: selectedCloudModel });
      setCloudTestResult(result);
      if (result.success) setApiKeyInput("");
    } catch (err) {
      setCloudTestResult({ success: false, latency_ms: 0, error: String(err), model_name: "" });
    } finally { setCloudTesting(false); }
  }

  async function handleActivateCloud() {
    if (!selectedProvider || !selectedCloudModel) return;
    try {
      const info = await invoke<ActiveModelInfo>("activate_cloud_provider", { provider: selectedProvider, model: selectedCloudModel });
      setActiveModel(info);
      await loadAiStatus();
      setCloudUsage(await invoke<CloudUsageStats>("get_cloud_usage").catch(() => null));
    } catch (err) { console.error("Cloud activation failed:", err); }
  }

  async function handleClearApiKey() {
    if (!selectedProvider) return;
    try { await invoke("clear_api_key", { provider: selectedProvider }); setHasApiKey(false); setApiKeyInput(""); setCloudTestResult(null); } catch { /* noop */ }
  }

  async function handleDeactivateCloud() {
    try { await invoke("deactivate_cloud_provider"); await loadAiStatus(); setCloudUsage(await invoke<CloudUsageStats>("get_cloud_usage").catch(() => null)); }
    catch (err) { console.error("Cloud deactivation failed:", err); }
  }

  async function handleFeatureRoutingChange(feature: string, pref: FeatureBackendPreference) {
    const overrides: Record<string, string> = {};
    for (const entry of featureRouting) {
      if (entry.feature === feature) overrides[entry.feature] = pref;
      else if (entry.current_preference !== "auto") overrides[entry.feature] = entry.current_preference;
    }
    if (pref === "auto") delete overrides[feature];
    try { await invoke("update_feature_routing", { overrides }); await loadFeatureRouting(); }
    catch (err) { console.error("Failed to update feature routing:", err); }
  }

  async function handleResetFeatureRouting() {
    try { await invoke("reset_feature_routing"); await loadFeatureRouting(); }
    catch (err) { console.error("Failed to reset feature routing:", err); }
  }

  function getModelStatus(modelId: string): "active" | "downloaded" | "not_downloaded" | "downloading" {
    if (activeModel?.model_id === modelId) return "active";
    if (downloads[modelId]) return "downloading";
    if (installedModels.some((m) => m.catalog_id === modelId)) return "downloaded";
    return "not_downloaded";
  }

  const currentProvider = cloudProviders.find((p) => p.id === selectedProvider);

  async function updateNetField<K extends keyof NetworkSettings>(key: K, value: NetworkSettings[K]) {
    const next = { ...netSettings, [key]: value };
    setNetSettings(next);
    try { await invoke("update_network_settings", { settings: next }); } catch { /* noop */ }
  }

  async function updateField<K extends keyof AppSettings>(key: K, value: AppSettings[K]) {
    const next = { ...settings, [key]: value };
    setSettings(next);
    setSaveStatus("saving");
    try { await invoke("update_settings", { settings: next }); setSaveStatus("saved"); setTimeout(() => setSaveStatus("idle"), 2000); }
    catch { setSaveStatus("error"); setTimeout(() => setSaveStatus("idle"), 3000); }
  }

  if (loading) {
    return <div style={{ padding: 24 }}><p style={{ color: "var(--ink-2)", fontSize: 13 }}>Loading settings...</p></div>;
  }

  const localModelName = activeModel?.model_name ?? aiStatus?.local?.model_name ?? "None";
  const localTokS =
    activeModel?.avg_latency_ms && activeModel.avg_latency_ms > 0
      ? Math.round(1000 / activeModel.avg_latency_ms)
      : aiStatus?.local?.avg_latency_ms && aiStatus.local.avg_latency_ms > 0
        ? Math.round(1000 / aiStatus.local.avg_latency_ms)
        : null;

  /* ================================================================
     RENDER
     ================================================================ */

  return (
    <div className="cd-scroll" style={{ padding: 24, maxWidth: 1080, margin: "0 auto", overflowY: "auto", height: "100%" }}>
      <SectionTitle sub="Local SLM handles 95% of triage on-device. Cloud is opt-in for deep investigations.">
        AI Analysis
      </SectionTitle>

      {saveStatus !== "idle" && (
        <div style={{ marginBottom: 10, fontSize: 11, fontFamily: "var(--font-mono)" }}>
          {saveStatus === "saving" && <span style={{ color: "var(--ink-2)" }}>Saving...</span>}
          {saveStatus === "saved" && <span style={{ color: "var(--green)" }}>Saved</span>}
          {saveStatus === "error" && <span style={{ color: "var(--red)" }}>Save failed</span>}
        </div>
      )}

      {/* ===== Two-column: Local + Cloud ===== */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
        {/* LOCAL MODEL */}
        <Card
          title="Local model"
          action={
            aiStatus?.local?.active
              ? <Badge color="var(--green)" mono><Dot color="var(--green)" size={5} pulse style={{ marginRight: 4 }} />active</Badge>
              : <Badge color="var(--ink-2)" mono>offline</Badge>
          }
        >
          {aiStatus?.local?.active ? (
            <div style={{ padding: 12, background: "var(--bg-2)", borderRadius: 8, marginBottom: 14, display: "flex", alignItems: "center", gap: 10 }}>
              <Icon name="cpu" size={16} color="var(--accent)" />
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 13, fontWeight: 600 }}>{localModelName}</div>
                <div style={{ fontSize: 10.5, color: "var(--ink-3)", fontFamily: "var(--font-mono)", marginTop: 2 }}>
                  {localTokS ? `${localTokS} tok/s` : ""}{activeModel?.using_gpu ? " \u00B7 GPU" : ""}{activeModel?.total_inferences ? ` \u00B7 ${activeModel.total_inferences} inf` : ""}
                </div>
              </div>
              <Btn size="sm" kind="ghost" onClick={handleDeactivateModel}>Deactivate</Btn>
            </div>
          ) : (
            <div style={{ padding: 12, background: "var(--bg-2)", borderRadius: 8, marginBottom: 14, fontSize: 12, color: "var(--ink-2)" }}>
              No model loaded. Download one for real-time AI monitoring.
            </div>
          )}

          <div style={{ display: "grid", gap: 6 }}>
            {catalog.map((m) => {
              const status = getModelStatus(m.id);
              const progress = downloadProgress[m.id];
              const dlError = downloadErrors[m.id];
              const isRecommended = m.is_default || (systemCaps && (
                (systemCaps.total_ram_gb < 8 && m.id.includes("1b")) ||
                (systemCaps.total_ram_gb >= 8 && systemCaps.total_ram_gb < 16 && m.id.includes("1.7b")) ||
                (systemCaps.total_ram_gb >= 16 && m.id.includes("4b"))
              ));
              return (
                <div key={m.id}>
                  <div style={{
                    padding: "9px 10px", borderRadius: 8,
                    background: status === "active" ? "var(--accent-soft)" : "transparent",
                    border: "1px solid " + (status === "active" ? "var(--accent-line)" : "var(--line-soft)"),
                    display: "flex", alignItems: "center", gap: 10,
                  }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: 12, fontWeight: 500, display: "flex", alignItems: "center", gap: 6 }}>
                        {m.display_name}
                        {isRecommended && <Badge color="var(--accent)">recommended</Badge>}
                      </div>
                      <div style={{ fontSize: 10, fontFamily: "var(--font-mono)", color: "var(--ink-3)", marginTop: 2 }}>
                        {formatBytes(m.size_bytes)} \u00B7 {m.min_ram_gb} GB RAM
                      </div>
                    </div>
                    {status === "active" ? <Badge color="var(--accent)">active</Badge> :
                     status === "downloaded" ? (
                       <div style={{ display: "flex", gap: 4 }}>
                         <Btn size="sm" kind="soft" disabled={activatingModel === m.id} onClick={() => handleActivateModel(m.id)}>
                           {activatingModel === m.id ? "..." : "Activate"}
                         </Btn>
                         <Btn size="sm" kind="ghost" disabled={deletingModel === m.id} onClick={() => handleDeleteModel(m.id)}>
                           {deletingModel === m.id ? "..." : "Del"}
                         </Btn>
                       </div>
                     ) : status === "downloading" ? (
                       <Btn size="sm" kind="ghost" onClick={() => handleCancelDownload(m.id)}>Cancel</Btn>
                     ) : (
                       <Btn size="sm" kind="ghost" icon="download" onClick={() => handleDownloadModel(m.id)}>Get</Btn>
                     )}
                  </div>
                  {status === "downloading" && progress && (
                    <div style={{ padding: "6px 10px" }}>
                      <div style={{ width: "100%", height: 3, borderRadius: 2, background: "var(--bg-3)", overflow: "hidden" }}>
                        <div style={{ width: `${Math.min(progress.percent, 100)}%`, height: "100%", borderRadius: 2, background: "var(--accent)", transition: "width 0.3s" }} />
                      </div>
                      <div style={{ fontSize: 10, fontFamily: "var(--font-mono)", color: "var(--ink-3)", marginTop: 3, display: "flex", justifyContent: "space-between" }}>
                        <span>{formatBytes(progress.bytes_downloaded)} / {formatBytes(progress.bytes_total)}</span>
                        <span>{progress.speed_bytes_per_sec > 0 && formatSpeed(progress.speed_bytes_per_sec)}{progress.eta_seconds > 0 && ` \u00B7 ~${Math.ceil(progress.eta_seconds)}s`}</span>
                      </div>
                    </div>
                  )}
                  {dlError && (
                    <div style={{ padding: "4px 10px", fontSize: 10.5, color: "var(--red)" }}>
                      {dlError}{" "}
                      <button onClick={() => { handleCancelDownload(m.id); handleDownloadModel(m.id); }} style={{ background: "none", border: "none", color: "var(--accent)", cursor: "pointer", fontSize: 10.5, textDecoration: "underline", padding: 0 }}>Retry</button>
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Custom model */}
          <div style={{ marginTop: 12, paddingTop: 12, borderTop: "1px solid var(--line-soft)" }}>
            <div style={{ fontSize: 11, color: "var(--ink-2)", marginBottom: 6 }}>Or load a custom .gguf model:</div>
            <div style={{ display: "flex", gap: 6 }}>
              <input type="text" value={customModelPath} onChange={(e) => { setCustomModelPath(e.target.value); setCustomModelError(null); }} placeholder="/path/to/model.gguf"
                style={{ flex: 1, background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: 6, padding: "6px 8px", fontSize: 11, fontFamily: "var(--font-mono)", color: "var(--ink-0)", outline: "none" }} />
              <Btn size="sm" kind="soft" disabled={customModelActivating} onClick={handleActivateCustomModel}>{customModelActivating ? "..." : "Activate"}</Btn>
            </div>
            {customModelError && <div style={{ fontSize: 10.5, color: "var(--red)", marginTop: 4 }}>{customModelError}</div>}
          </div>
        </Card>

        {/* CLOUD REASONING */}
        <Card
          title="Cloud reasoning"
          action={
            aiStatus?.cloud?.active
              ? <Badge color="var(--violet)" mono><Dot color="var(--green)" size={5} pulse style={{ marginRight: 4 }} />connected</Badge>
              : <Badge color="var(--ink-2)" mono>offline</Badge>
          }
        >
          <div style={{ display: "grid", gap: 12 }}>
            {cloudProviders.length > 1 && (
              <Field label="Provider">
                <select value={selectedProvider} onChange={(e) => {
                  setSelectedProvider(e.target.value); setCloudTestResult(null);
                  const provider = cloudProviders.find((p) => p.id === e.target.value);
                  if (provider && provider.models.length > 0) setSelectedCloudModel(provider.models[0].id);
                }} style={{ width: "100%", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: 6, padding: "8px 10px", fontSize: 12, color: "var(--ink-0)", outline: "none" }}>
                  {cloudProviders.map((p) => <option key={p.id} value={p.id}>{p.display_name}</option>)}
                </select>
              </Field>
            )}

            <Field label="Model">
              <select value={selectedCloudModel} onChange={(e) => { setSelectedCloudModel(e.target.value); setCloudTestResult(null); }}
                style={{ width: "100%", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: 6, padding: "8px 10px", fontSize: 12, color: "var(--ink-0)", outline: "none" }}>
                {currentProvider?.models.map((cm) => (
                  <option key={cm.id} value={cm.id}>{cm.display_name}{cm.recommended ? " (Recommended)" : ""}</option>
                )) ?? <option>No providers available</option>}
              </select>
            </Field>

            <Field label="Monthly budget">
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <input type="range" min="5" max="100" value={cloudBudget} onChange={(e) => setCloudBudget(Number(e.target.value))} style={{ flex: 1, accentColor: "var(--accent)" }} />
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--ink-1)", width: 50 }}>${cloudBudget}</span>
              </div>
              {cloudUsage && (
                <div style={{ fontSize: 10.5, color: "var(--ink-3)", marginTop: 4, fontFamily: "var(--font-mono)" }}>
                  used: ${cloudUsage.estimated_cost_usd.toFixed(2)} \u00B7 {cloudUsage.total_requests} requests
                </div>
              )}
            </Field>

            <Field label={`API key${hasApiKey ? " (saved)" : ""}`}>
              <div style={{ display: "flex", gap: 6 }}>
                <div style={{ flex: 1, position: "relative" }}>
                  <input type={showApiKey ? "text" : "password"} value={apiKeyInput} onChange={(e) => setApiKeyInput(e.target.value)}
                    placeholder={hasApiKey ? "Enter new key to update" : "sk-ant-..."}
                    style={{ width: "100%", boxSizing: "border-box", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: 6, padding: "8px 10px", paddingRight: 50, fontSize: 12, fontFamily: "var(--font-mono)", color: "var(--ink-0)", outline: "none" }} />
                  <button onClick={() => setShowApiKey(!showApiKey)} style={{ position: "absolute", right: 8, top: "50%", transform: "translateY(-50%)", background: "none", border: "none", fontSize: 10, color: "var(--ink-3)", cursor: "pointer", padding: 0 }}>
                    {showApiKey ? "Hide" : "Show"}
                  </button>
                </div>
                {hasApiKey && <Btn size="sm" kind="ghost" onClick={handleClearApiKey}>Clear</Btn>}
              </div>
            </Field>

            <div style={{ display: "flex", gap: 8 }}>
              <Btn size="sm" kind="soft" disabled={cloudTesting || (!apiKeyInput.trim() && !hasApiKey)} onClick={handleSaveAndTestCloud}>
                {cloudTesting ? "Testing..." : "Save & Test"}
              </Btn>
              {hasApiKey && cloudTestResult?.success && !aiStatus?.cloud?.active && (
                <Btn size="sm" kind="primary" onClick={handleActivateCloud}>Activate</Btn>
              )}
              {aiStatus?.cloud?.active && <Btn size="sm" kind="ghost" onClick={handleDeactivateCloud}>Disconnect</Btn>}
            </div>

            {cloudTestResult && (
              <div style={{
                padding: "8px 10px", borderRadius: 8, fontSize: 11.5,
                background: cloudTestResult.success ? "color-mix(in oklch, var(--green) 10%, transparent)" : "color-mix(in oklch, var(--red) 10%, transparent)",
                color: cloudTestResult.success ? "var(--green)" : "var(--red)",
              }}>
                {cloudTestResult.success ? `Connected \u2014 ${cloudTestResult.latency_ms}ms` : `Failed: ${cloudTestResult.error}`}
              </div>
            )}
          </div>
        </Card>
      </div>

      {/* How they work together */}
      <Card title="How they work together" style={{ marginTop: 14 }}>
        <div style={{ fontSize: 12.5, color: "var(--ink-1)", lineHeight: 1.65 }}>
          Every event flows first into <span className="mono" style={{ color: "var(--accent)" }}>{localModelName}</span> for triage.
          Anything <span style={{ color: "var(--red)" }}>suspicious</span> auto-escalates to <span className="mono" style={{ color: "var(--violet)" }}>{currentProvider?.display_name ?? "Cloud"}</span> with correlated context.
          You always see which brain answered.
        </div>
      </Card>

      {/* Feature Routing (collapsible) */}
      <div style={{ marginTop: 14, background: "var(--bg-1)", border: "1px solid var(--line)", borderRadius: 12, overflow: "hidden" }}>
        <button onClick={() => setFeatureRoutingExpanded(!featureRoutingExpanded)}
          style={{ width: "100%", display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 16px", background: "none", border: "none", cursor: "pointer", textAlign: "left" }}>
          <div>
            <div style={{ fontSize: 13, fontWeight: 600, color: "var(--ink-0)" }}>Feature Routing</div>
            <div style={{ fontSize: 11, color: "var(--ink-2)", marginTop: 2 }}>Customize which AI backend handles each feature</div>
          </div>
          <Icon name="chevron" size={14} color="var(--ink-2)" />
        </button>
        {featureRoutingExpanded && (
          <div style={{ padding: "0 16px 16px" }}>
            {featureRoutingHasOverrides && (
              <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 8 }}>
                <Btn size="sm" kind="ghost" onClick={handleResetFeatureRouting}>Reset to Defaults</Btn>
              </div>
            )}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 70px 1fr", gap: 8, padding: "0 8px 6px", borderBottom: "1px solid var(--line-soft)" }}>
              <span style={{ fontSize: 10, fontWeight: 600, color: "var(--ink-3)", textTransform: "uppercase", letterSpacing: 0.5 }}>Feature</span>
              <span style={{ fontSize: 10, fontWeight: 600, color: "var(--ink-3)", textTransform: "uppercase", letterSpacing: 0.5, textAlign: "center" }}>Default</span>
              <span style={{ fontSize: 10, fontWeight: 600, color: "var(--ink-3)", textTransform: "uppercase", letterSpacing: 0.5, textAlign: "center" }}>Setting</span>
            </div>
            {featureRouting.map((entry) => (
              <div key={entry.feature} style={{ display: "grid", gridTemplateColumns: "1fr 70px 1fr", gap: 8, alignItems: "center", padding: "8px 8px" }}>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 500, color: "var(--ink-0)" }}>{entry.display_name}</div>
                  <div style={{ fontSize: 10, color: "var(--ink-3)" }}>{entry.description}</div>
                </div>
                <span style={{ fontSize: 10.5, textAlign: "center", textTransform: "capitalize", color: entry.default_backend === "cloud" ? "var(--accent)" : "var(--green)" }}>
                  {entry.default_backend}
                </span>
                <div style={{ display: "flex", borderRadius: 6, border: "1px solid var(--line)", overflow: "hidden" }}>
                  {(["auto", "local", "cloud"] as const).map((opt) => (
                    <button key={opt} onClick={() => handleFeatureRoutingChange(entry.feature, opt)}
                      style={{ flex: 1, padding: "5px 0", fontSize: 10, fontWeight: 500, textTransform: "capitalize",
                        background: entry.current_preference === opt ? "var(--accent)" : "transparent",
                        color: entry.current_preference === opt ? "white" : "var(--ink-2)",
                        border: "none", cursor: "pointer", transition: "background 0.15s, color 0.15s" }}>
                      {opt}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ===== General Settings ===== */}
      <div style={{ marginTop: 32 }}>
        <SectionTitle sub="App preferences and general configuration.">General</SectionTitle>
      </div>
      <Card style={{ marginBottom: 14 }}>
        <div style={{ display: "grid", gap: 16 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div><div style={{ fontSize: 13, fontWeight: 500 }}>Theme</div><div style={{ fontSize: 11, color: "var(--ink-3)" }}>Choose appearance mode</div></div>
            <select value={settings.theme} onChange={(e) => { const t = e.target.value as AppSettings["theme"]; updateField("theme", t); emit("rookbot://theme-changed", t); }}
              style={{ background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: 6, padding: "6px 10px", fontSize: 12, color: "var(--ink-0)", outline: "none" }}>
              <option value="system">System</option><option value="light">Light</option><option value="dark">Dark</option>
            </select>
          </div>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div><div style={{ fontSize: 13, fontWeight: 500 }}>Start at Login</div><div style={{ fontSize: 11, color: "var(--ink-3)" }}>Auto-start daemon when you log in</div></div>
            <ToggleSwitch checked={settings.auto_start_daemon} onChange={async (v) => { try { if (v) await invoke("enable_autostart"); else await invoke("disable_autostart"); updateField("auto_start_daemon", v); } catch { /* noop */ } }} />
          </div>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div><div style={{ fontSize: 13, fontWeight: 500 }}>Show in Menu Bar</div><div style={{ fontSize: 11, color: "var(--ink-3)" }}>Minimize to system tray</div></div>
            <ToggleSwitch checked={settings.minimize_to_tray} onChange={(v) => updateField("minimize_to_tray", v)} />
          </div>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div><div style={{ fontSize: 13, fontWeight: 500 }}>Notifications</div><div style={{ fontSize: 11, color: "var(--ink-3)" }}>Show alerts for blocked actions</div></div>
            <ToggleSwitch checked={settings.notifications_enabled} onChange={(v) => updateField("notifications_enabled", v)} />
          </div>
        </div>
      </Card>

      {/* Protection */}
      <Card style={{ marginBottom: 14 }}>
        <div style={{ display: "grid", gap: 16 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div><div style={{ fontSize: 13, fontWeight: 500 }}>Security Level</div><div style={{ fontSize: 11, color: "var(--ink-3)" }}>Current protection template</div></div>
            <select value={settings.security_level} onChange={(e) => {
              const level = e.target.value;
              setSettings((s) => ({ ...s, security_level: level }));
              const templateName = level === "monitor-only" ? "permissive" : level;
              invoke("apply_template", { name: templateName }).then(() => { invoke<AppSettings>("get_settings").then((s) => setSettings(s)).catch(() => {}); }).catch(() => {});
            }} style={{ background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: 6, padding: "6px 10px", fontSize: 12, color: "var(--ink-0)", outline: "none" }}>
              <option value="monitor-only">Monitor Only</option><option value="balanced">Balanced</option><option value="strict">Strict</option>
              {settings.security_level === "custom" && <option value="custom">Custom</option>}
            </select>
          </div>
          <div>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
              <div><div style={{ fontSize: 13, fontWeight: 500 }}>Prompt Timeout</div><div style={{ fontSize: 11, color: "var(--ink-3)" }}>Auto-deny after timeout</div></div>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--ink-2)" }}>{settings.prompt_timeout_seconds}s</span>
            </div>
            <input type="range" min={15} max={120} step={5} value={settings.prompt_timeout_seconds} onChange={(e) => updateField("prompt_timeout_seconds", Number(e.target.value))} style={{ width: "100%", accentColor: "var(--accent)" }} />
          </div>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div><div style={{ fontSize: 13, fontWeight: 500 }}>Analysis Frequency</div><div style={{ fontSize: 11, color: "var(--ink-3)" }}>When to run AI analysis</div></div>
            <select value={settings.analysis_frequency} onChange={(e) => updateField("analysis_frequency", e.target.value)}
              style={{ background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: 6, padding: "6px 10px", fontSize: 12, color: "var(--ink-0)", outline: "none" }}>
              <option value="all">All prompted events</option><option value="high_risk">High-risk only</option><option value="disabled">Disabled</option>
            </select>
          </div>
        </div>
      </Card>

      {/* Network Protection */}
      <div id="network-protection" style={{ marginTop: 32 }}>
        <SectionTitle sub="Monitor and filter outbound connections from AI agents.">Network Protection</SectionTitle>
      </div>
      {(!netStatus || !netStatus.loaded) && (
        <div style={{ padding: "10px 14px", background: "color-mix(in oklch, var(--red) 8%, transparent)", borderRadius: 8, fontSize: 11.5, color: "var(--red)", marginBottom: 10 }}>
          Network Extension is not installed. This feature requires a macOS system extension.
        </div>
      )}
      <Card style={{ marginBottom: 14, opacity: !netStatus || !netStatus.loaded ? 0.4 : 1, pointerEvents: !netStatus || !netStatus.loaded ? "none" : "auto" }}>
        <div style={{ display: "grid", gap: 16 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div><div style={{ fontSize: 13, fontWeight: 500 }}>Enable Network Filtering</div><div style={{ fontSize: 11, color: "var(--ink-3)" }}>Filter outbound connections from AI agents</div></div>
            <ToggleSwitch checked={netSettings.filter_enabled} onChange={(v) => updateNetField("filter_enabled", v)} />
          </div>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div><div style={{ fontSize: 13, fontWeight: 500 }}>Enable DNS Filtering</div><div style={{ fontSize: 11, color: "var(--ink-3)" }}>Monitor and filter DNS queries</div></div>
            <ToggleSwitch checked={netSettings.dns_enabled} onChange={(v) => updateNetField("dns_enabled", v)} />
          </div>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div><div style={{ fontSize: 13, fontWeight: 500 }}>Default Action</div><div style={{ fontSize: 11, color: "var(--ink-3)" }}>Action for unmatched connections</div></div>
            <select value={netSettings.default_action} onChange={(e) => updateNetField("default_action", e.target.value as NetworkSettings["default_action"])}
              style={{ background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: 6, padding: "6px 10px", fontSize: 12, color: "var(--ink-0)", outline: "none" }}>
              <option value="prompt">Prompt</option><option value="block">Block</option><option value="allow">Allow</option>
            </select>
          </div>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div><div style={{ fontSize: 13, fontWeight: 500 }}>Block DNS-over-HTTPS</div><div style={{ fontSize: 11, color: "var(--ink-3)" }}>Prevent DNS bypass via encrypted DNS</div></div>
            <input type="checkbox" checked={netSettings.block_doh} onChange={(e) => updateNetField("block_doh", e.target.checked)} style={{ width: 16, height: 16, accentColor: "var(--accent)" }} />
          </div>
        </div>
      </Card>

      {/* Advanced */}
      <div style={{ marginTop: 32 }}>
        <SectionTitle sub="Log level, data retention, import/export.">Advanced</SectionTitle>
      </div>
      <Card style={{ marginBottom: 14 }}>
        <div style={{ display: "grid", gap: 16 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div><div style={{ fontSize: 13, fontWeight: 500 }}>Log Level</div><div style={{ fontSize: 11, color: "var(--ink-3)" }}>Verbosity of daemon logs</div></div>
            <select value={settings.log_level} onChange={(e) => updateField("log_level", e.target.value as AppSettings["log_level"])}
              style={{ background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: 6, padding: "6px 10px", fontSize: 12, color: "var(--ink-0)", outline: "none" }}>
              <option value="trace">Trace</option><option value="debug">Debug</option><option value="info">Info</option><option value="warn">Warn</option><option value="error">Error</option>
            </select>
          </div>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div><div style={{ fontSize: 13, fontWeight: 500 }}>Event Retention</div><div style={{ fontSize: 11, color: "var(--ink-3)" }}>Days to keep audit events</div></div>
            <input type="number" min={1} max={365} value={settings.event_retention_days} onChange={(e) => updateField("event_retention_days", Number(e.target.value))}
              style={{ width: 70, background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: 6, padding: "6px 10px", fontSize: 12, color: "var(--ink-0)", outline: "none", textAlign: "center" }} />
          </div>
          <div style={{ paddingTop: 12, borderTop: "1px solid var(--line-soft)", display: "flex", gap: 8, flexWrap: "wrap" }}>
            <Btn size="sm" kind="soft" onClick={async () => {
              try { const path = await invoke<string>("export_settings"); setExportStatus(`Exported to ${path}`); setTimeout(() => setExportStatus(null), 4000); }
              catch (err) { setExportStatus(`Export failed: ${err}`); setTimeout(() => setExportStatus(null), 4000); }
            }}>Export Config</Btn>
            <Btn size="sm" kind="soft" onClick={() => {
              const input = document.createElement("input"); input.type = "file"; input.accept = ".json";
              input.onchange = async (e) => { const file = (e.target as HTMLInputElement).files?.[0]; if (file) { try { const content = await file.text(); await invoke("import_settings_from_content", { content }); setExportStatus("Settings imported"); loadSettings(); setTimeout(() => setExportStatus(null), 4000); } catch (err) { setExportStatus(`Import failed: ${err}`); setTimeout(() => setExportStatus(null), 4000); } } };
              input.click();
            }}>Import Config</Btn>
            <span style={{ flex: 1 }} />
            <Btn size="sm" kind="danger" onClick={() => { if (window.confirm("Reset all settings to defaults?")) { setSettings(defaultSettings); invoke("update_settings", { settings: defaultSettings }).catch(() => {}); } }}>Reset to Defaults</Btn>
          </div>
          {exportStatus && <div style={{ fontSize: 11, color: "var(--ink-2)" }}>{exportStatus}</div>}
        </div>
      </Card>
    </div>
  );
}
