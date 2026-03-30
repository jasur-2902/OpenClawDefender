import { useState, useEffect, useCallback, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-shell";


// --- Types ---

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

// --- Helpers ---

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
    <span className="text-[var(--color-warning)]" aria-label={`Quality: ${rating} out of 5`}>
      {Array.from({ length: 5 }, (_, i) => (i < rating ? "\u2605" : "\u2606")).join("")}
    </span>
  );
}

function CompatibilityBadge({ model, systemCaps }: { model: CatalogModel; systemCaps: SystemCapabilities | null }) {
  if (!systemCaps) return null;
  const hasEnoughRam = systemCaps.total_ram_gb >= model.min_ram_gb;
  if (hasEnoughRam) {
    return (
      <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-[var(--color-safe-subtle)] text-[var(--color-safe)] font-medium">
        Works on your system
      </span>
    );
  }
  return (
    <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-[var(--color-warning-subtle)] text-[var(--color-warning)] font-medium">
      May be slow
    </span>
  );
}

function humanizeDownloadError(rawError: string, _modelId: string): string {
  const lower = rawError.toLowerCase();
  if (lower.includes("no space") || lower.includes("disk full") || lower.includes("enospc")) {
    return "Not enough disk space. Free up some storage and try again.";
  }
  if (lower.includes("network") || lower.includes("connection") || lower.includes("timeout") || lower.includes("dns")) {
    return "Could not reach the download server. Check your internet connection and try again.";
  }
  if (lower.includes("checksum") || lower.includes("hash") || lower.includes("integrity") || lower.includes("corrupt")) {
    return "The downloaded file did not pass verification. This can happen with unstable connections. Try again.";
  }
  if (lower.includes("permission") || lower.includes("access denied")) {
    return "I do not have permission to write to the model directory. Check your folder permissions.";
  }
  if (lower.includes("partial") || lower.includes("incomplete") || lower.includes("resume")) {
    return "The download did not finish. You can try again and it will resume from where it stopped.";
  }
  // Default: calm, non-technical message
  return "The download did not complete. Try again in a moment.";
}

// --- Components ---

interface ModelManagerProps {
  onModelChanged?: () => void;
}

export function ModelManager({ onModelChanged }: ModelManagerProps) {
  const [catalog, setCatalog] = useState<CatalogModel[]>([]);
  const [installedModels, setInstalledModels] = useState<InstalledModelInfo[]>([]);
  const [activeModel, setActiveModel] = useState<ActiveModelInfo | null>(null);
  const [systemCaps, setSystemCaps] = useState<SystemCapabilities | null>(null);
  const [downloads, setDownloads] = useState<Record<string, string>>({});
  const [downloadProgress, setDownloadProgress] = useState<Record<string, DownloadProgress>>({});
  const [downloadErrors, setDownloadErrors] = useState<Record<string, string>>({});
  const [activatingModel, setActivatingModel] = useState<string | null>(null);
  const [deletingModel, setDeletingModel] = useState<string | null>(null);
  const [deactivateConfirm, setDeactivateConfirm] = useState(false);

  // Cloud state
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

  useEffect(() => {
    loadModelData();
  }, [loadModelData]);

  // Download progress polling
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
          pollFailCountRef.current[modelId] = 0;
          const st = getStatusType(prog.status);
          if (st === "completed" || st === "failed" || st === "cancelled") {
            anyCompleted = true;
          }
        } catch (err) {
          const errMsg = err instanceof Error ? err.message : String(err);
          const count = (pollFailCountRef.current[modelId] || 0) + 1;
          pollFailCountRef.current[modelId] = count;
          if (count >= 10) {
            newErrors[modelId] = `Connection lost: ${errMsg}`;
            anyCompleted = true;
          }
        }
      }
      setDownloadProgress(newProgress);
      if (Object.keys(newErrors).length > 0) {
        setDownloadErrors((prev) => ({ ...prev, ...newErrors }));
      }

      if (anyCompleted) {
        for (const modelId of Object.keys(newProgress)) {
          const prog = newProgress[modelId];
          const st = prog ? getStatusType(prog.status) : null;
          if (st === "failed") {
            const failedMsg =
              typeof prog.status === "object" && prog.status !== null
                ? (prog.status as { failed: string }).failed
                : "Download failed";
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
            if (prog && (st === "completed" || st === "failed" || st === "cancelled")) {
              delete next[modelId];
            }
          }
          return next;
        });
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
    setDownloadErrors((prev) => {
      const next = { ...prev };
      delete next[modelId];
      return next;
    });
    try {
      const taskId = await invoke<string>("download_model", { modelId });
      setDownloads((prev) => ({ ...prev, [modelId]: taskId }));
    } catch (err) {
      const rawMsg = err instanceof Error ? err.message : String(err);
      const friendlyMsg = humanizeDownloadError(rawMsg, modelId);
      setDownloadErrors((prev) => ({ ...prev, [modelId]: friendlyMsg }));
    }
  }

  async function handleCancelDownload(modelId: string) {
    const taskId = downloads[modelId];
    if (taskId) {
      try {
        await invoke("cancel_download", { taskId });
      } catch {
        // Cancel may fail
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
      onModelChanged?.();
    } catch (err) {
      const rawMsg = err instanceof Error ? err.message : String(err);
      setDownloadErrors((prev) => ({
        ...prev,
        [modelId]: humanizeDownloadError(rawMsg, modelId),
      }));
    } finally {
      setActivatingModel(null);
    }
  }

  async function handleDeactivateModel() {
    try {
      await invoke("deactivate_model");
      setActiveModel(null);
      setDeactivateConfirm(false);
      onModelChanged?.();
    } catch {
      // Deactivate may fail
    }
  }

  async function handleDeleteModel(modelId: string) {
    setDeletingModel(modelId);
    try {
      await invoke("delete_model", { modelId });
      await loadModelData();
    } catch {
      // Delete may fail
    } finally {
      setDeletingModel(null);
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
      if (result.success) setApiKeyInput("");
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
      const usage = await invoke<CloudUsageStats>("get_cloud_usage").catch(() => null);
      setCloudUsage(usage);
      onModelChanged?.();
    } catch {
      // Cloud activation failed
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

  return (
    <div className="space-y-4">
      {/* System info */}
      {systemCaps && (
        <div className="flex items-center gap-3 rounded-lg bg-[var(--color-bg-tertiary)] border border-[var(--color-border)] px-3 py-2">
          <span className="text-xs text-[var(--color-text-secondary)]">
            Your Mac: {systemCaps.is_apple_silicon ? "Apple Silicon" : systemCaps.arch} · {systemCaps.total_ram_gb} GB RAM
          </span>
        </div>
      )}

      {/* Active model highlight */}
      {activeModel && activeModel.model_type !== "cloud" && (
        <div className="rounded-lg border border-[var(--color-safe)] bg-[var(--color-safe-light)] p-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="inline-block w-2 h-2 rounded-full bg-[var(--color-safe)]" aria-hidden="true" />
              <span className="text-sm font-medium">{activeModel.model_name}</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-[var(--color-safe-subtle)] text-[var(--color-safe)] font-medium">
                Active
              </span>
              {activeModel.using_gpu && (
                <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-[var(--color-accent-subtle)] text-[var(--color-accent)]">
                  GPU
                </span>
              )}
            </div>
            {!deactivateConfirm ? (
              <button
                onClick={() => setDeactivateConfirm(true)}
                className="text-xs text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
              >
                Deactivate
              </button>
            ) : (
              <div className="flex items-center gap-2">
                <span className="text-xs text-[var(--color-text-secondary)]">Deactivate?</span>
                <button
                  onClick={handleDeactivateModel}
                  className="px-2 py-1 rounded text-xs bg-[var(--color-danger)] text-white hover:opacity-90"
                >
                  Yes
                </button>
                <button
                  onClick={() => setDeactivateConfirm(false)}
                  className="px-2 py-1 rounded text-xs border border-[var(--color-border)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
                >
                  No
                </button>
              </div>
            )}
          </div>
          <p className="text-xs text-[var(--color-text-secondary)] mt-1">
            {activeModel.total_inferences} analyses performed
          </p>
        </div>
      )}

      {/* Installed + catalog models */}
      <div className="space-y-2">
        <p className="text-xs font-semibold text-[var(--color-text-muted)] uppercase tracking-wider">
          {installedModels.length > 0 ? "Available Models" : "Model Catalog"}
        </p>
        {catalog.map((model) => {
          const status = getModelStatus(model.id);
          const progress = downloadProgress[model.id];
          const dlError = downloadErrors[model.id];
          const isActive = status === "active";
          const speedEstimate = systemCaps?.is_apple_silicon
            ? model.tokens_per_sec_apple
            : model.tokens_per_sec_intel;
          const isRecommended =
            model.is_default ||
            (systemCaps &&
              ((systemCaps.total_ram_gb < 8 && model.id.includes("1b")) ||
                (systemCaps.total_ram_gb >= 8 && systemCaps.total_ram_gb < 16 && model.id.includes("1.7b")) ||
                (systemCaps.total_ram_gb >= 16 && model.id.includes("4b"))));

          return (
            <div
              key={model.id}
              className={`rounded-lg border p-3 ${
                isActive
                  ? "border-[var(--color-safe)] bg-[var(--color-safe-light)]"
                  : isRecommended
                  ? "border-[var(--color-accent)]/50 bg-[var(--color-bg-tertiary)]"
                  : "border-[var(--color-border)] bg-[var(--color-bg-tertiary)]"
              }`}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                    <p className="text-sm font-semibold">{model.display_name}</p>
                    {isActive && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-[var(--color-safe-subtle)] text-[var(--color-safe)] font-medium">
                        Active
                      </span>
                    )}
                    {status === "downloaded" && !isActive && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-[var(--color-accent-subtle)] text-[var(--color-accent)] font-medium">
                        Downloaded
                      </span>
                    )}
                    {isRecommended && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-[var(--color-warning-subtle)] text-[var(--color-warning)] font-medium">
                        Recommended
                      </span>
                    )}
                    <CompatibilityBadge model={model} systemCaps={systemCaps} />
                  </div>
                  <p className="text-xs text-[var(--color-text-secondary)] mb-1">{model.description}</p>
                  <div className="flex flex-wrap items-center gap-3 text-xs text-[var(--color-text-secondary)]">
                    <span>{formatBytes(model.size_bytes)}</span>
                    <span>~{model.min_ram_gb} GB RAM</span>
                    <QualityStars rating={model.quality_rating} />
                    {speedEstimate > 0 && <span>~{speedEstimate} tok/s</span>}
                  </div>
                  {model.model_page_url && (
                    <button
                      onClick={() => open(model.model_page_url)}
                      className="mt-1 text-[11px] text-[var(--color-accent)] hover:underline"
                    >
                      View on HuggingFace
                    </button>
                  )}
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  {status === "not_downloaded" && (
                    <button
                      onClick={() => handleDownloadModel(model.id)}
                      className="px-3 py-1.5 rounded-md text-xs font-medium bg-[var(--color-safe)] text-white hover:opacity-90"
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
                      >
                        {deletingModel === model.id ? "..." : "Delete"}
                      </button>
                    </>
                  )}
                  {isActive && (
                    <span className="text-xs text-[var(--color-safe)] font-medium">In Use</span>
                  )}
                </div>
              </div>

              {/* Download progress */}
              {status === "downloading" && (
                <DownloadProgressBar
                  progress={progress}
                  error={dlError}
                  onRetry={() => {
                    handleCancelDownload(model.id);
                    handleDownloadModel(model.id);
                  }}
                />
              )}

              {/* Post-download error */}
              {status !== "downloading" && dlError && (
                <div className="mt-3 pt-3 border-t border-[var(--color-danger)]/30">
                  <div className="flex items-center justify-between">
                    <p className="text-xs text-[var(--color-danger)] flex-1">{dlError}</p>
                    <div className="flex items-center gap-2 ml-3 shrink-0">
                      <button
                        onClick={() => handleDownloadModel(model.id)}
                        className="px-2 py-1 rounded text-[10px] font-medium bg-[var(--color-accent)] text-white hover:opacity-90"
                      >
                        Try again
                      </button>
                      <button
                        onClick={() =>
                          setDownloadErrors((prev) => {
                            const next = { ...prev };
                            delete next[model.id];
                            return next;
                          })
                        }
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
            I could not load the model catalog. Check your internet connection and try again.
          </p>
        )}
      </div>

      {/* Cloud analysis section */}
      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-tertiary)]">
        <button
          onClick={() => {
            setCloudExpanded(!cloudExpanded);
            if (!cloudExpanded && cloudProviders.length === 0) loadCloudProviders();
          }}
          aria-expanded={cloudExpanded}
          className="w-full flex items-center justify-between p-3 text-left focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-[var(--color-accent)] rounded-lg"
        >
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-[var(--color-text-secondary)]">Cloud Analysis</span>
            {isCloudActive && (
              <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-[var(--color-safe-subtle)] text-[var(--color-safe)] font-medium">
                Active
              </span>
            )}
          </div>
          <span className="text-[var(--color-text-secondary)] text-xs">{cloudExpanded ? "\u25B2" : "\u25BC"}</span>
        </button>

        {cloudExpanded && (
          <div className="px-3 pb-3 space-y-3">
            <div className="rounded-lg bg-[var(--color-warning-subtle)] border border-[var(--color-warning)]/30 p-2">
              <p className="text-xs text-[var(--color-text-secondary)]">
                Cloud analysis sends metadata to third-party servers and costs money. Local models are private, fast, and free.
              </p>
            </div>

            {isCloudActive && (
              <div className="flex items-center justify-between rounded-lg bg-[var(--color-bg-secondary)] p-2">
                <div>
                  <p className="text-xs font-medium">Cloud model is active</p>
                  {cloudUsage && (
                    <p className="text-xs text-[var(--color-text-secondary)]">
                      {cloudUsage.total_requests} analyses, ~${cloudUsage.estimated_cost_usd.toFixed(2)}
                    </p>
                  )}
                </div>
                <button
                  onClick={handleDeactivateModel}
                  className="px-3 py-1 rounded-md text-xs font-medium bg-[var(--color-safe)] text-white hover:opacity-90"
                >
                  Switch to Local
                </button>
              </div>
            )}

            {/* Provider */}
            <div>
              <label htmlFor="cloud-provider" className="text-xs text-[var(--color-text-secondary)] block mb-1">
                Provider
              </label>
              <select
                id="cloud-provider"
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
                  <option key={p.id} value={p.id}>
                    {p.display_name}
                  </option>
                ))}
              </select>
            </div>

            {/* API Key */}
            <div>
              <label htmlFor="cloud-api-key" className="text-xs text-[var(--color-text-secondary)] block mb-1">
                API Key {hasApiKey && <span className="text-[var(--color-safe)]">(saved)</span>}
              </label>
              <div className="flex gap-2">
                <div className="flex-1 relative">
                  <input
                    id="cloud-api-key"
                    type={showApiKey ? "text" : "password"}
                    value={apiKeyInput}
                    onChange={(e) => setApiKeyInput(e.target.value)}
                    placeholder={hasApiKey ? "Key saved -- enter new key to update" : "Enter API key"}
                    className="w-full px-3 py-1.5 pr-16 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-primary)] text-sm text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)] font-mono text-xs"
                  />
                  <button
                    onClick={() => setShowApiKey(!showApiKey)}
                    aria-label={showApiKey ? "Hide API key" : "Show API key"}
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
              <label htmlFor="cloud-model" className="text-xs text-[var(--color-text-secondary)] block mb-1">
                Model
              </label>
              <select
                id="cloud-model"
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
                  </option>
                ))}
              </select>
            </div>

            {/* Save & Test */}
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

            {cloudTestResult && (
              <div
                role="status"
                aria-live="polite"
                className={`rounded-lg p-2 text-xs ${
                  cloudTestResult.success
                    ? "bg-[var(--color-safe-light)] text-[var(--color-safe)]"
                    : "bg-[var(--color-danger-light)] text-[var(--color-danger)]"
                }`}
              >
                {cloudTestResult.success
                  ? `Connected -- Latency: ${cloudTestResult.latency_ms}ms`
                  : `Failed: ${cloudTestResult.error}`}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function DownloadProgressBar({
  progress,
  error,
  onRetry,
}: {
  progress: DownloadProgress | undefined;
  error: string | undefined;
  onRetry: () => void;
}) {
  if (error && !progress) {
    return (
      <div className="mt-3 pt-3 border-t border-[var(--color-border)]">
        <div className="flex items-center justify-between">
          <p className="text-xs text-[var(--color-danger)] flex-1">{error}</p>
          <button
            onClick={onRetry}
            className="ml-3 px-2 py-1 rounded text-[10px] font-medium bg-[var(--color-accent)] text-white hover:opacity-90 shrink-0"
          >
            Try again
          </button>
        </div>
      </div>
    );
  }

  if (!progress) {
    return (
      <div className="mt-3 pt-3 border-t border-[var(--color-border)]">
        <p className="text-xs text-[var(--color-text-secondary)] animate-pulse">Connecting to server...</p>
      </div>
    );
  }

  const st = getStatusType(progress.status);
  const failedMsg =
    typeof progress.status === "object" && progress.status !== null
      ? (progress.status as { failed: string }).failed
      : null;

  if (st === "failed") {
    const friendlyFail = failedMsg
      ? humanizeDownloadError(failedMsg, "")
      : "The download did not complete. Try again in a moment.";
    return (
      <div className="mt-3 pt-3 border-t border-[var(--color-border)]">
        <div className="flex items-center justify-between">
          <p className="text-xs text-[var(--color-danger)] flex-1">{friendlyFail}</p>
          <button
            onClick={onRetry}
            className="ml-3 px-2 py-1 rounded text-[10px] font-medium bg-[var(--color-accent)] text-white hover:opacity-90 shrink-0"
          >
            Try again
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="mt-3 pt-3 border-t border-[var(--color-border)]">
      <div className="flex items-center justify-between text-xs text-[var(--color-text-secondary)] mb-1.5">
        <span>
          {formatBytes(progress.bytes_downloaded)} / {formatBytes(progress.bytes_total)}
        </span>
        <span>
          {st === "pending"
            ? "Connecting..."
            : `${formatSpeed(progress.speed_bytes_per_sec)}${
                progress.eta_seconds > 0 ? ` -- ~${Math.ceil(progress.eta_seconds)}s remaining` : ""
              }`}
        </span>
      </div>
      <div
        className="w-full h-2.5 rounded-full bg-[var(--color-bg-primary)] overflow-hidden"
        role="progressbar"
        aria-valuenow={Math.round(progress.percent)}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label="Download progress"
      >
        <div
          className={`h-full rounded-full transition-all duration-300 ${
            st === "verifying"
              ? "bg-[var(--color-warning)] animate-pulse"
              : "bg-gradient-to-r from-[var(--color-accent)] to-[var(--color-safe)]"
          }`}
          style={{ width: `${Math.max(Math.min(progress.percent, 100), st === "downloading" ? 1 : 0)}%` }}
        />
      </div>
      <p className="text-[10px] text-[var(--color-text-secondary)] mt-1 text-right">
        {st === "verifying" ? "Verifying checksum..." : `${progress.percent.toFixed(1)}%`}
      </p>
    </div>
  );
}
