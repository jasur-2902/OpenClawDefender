import { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { Rook, Btn, Icon } from "../components/design";
import type { McpClient, McpServer, SensorHealth } from "../types";

/* ---------- local types ---------- */

interface DetectedServer {
  client: McpClient;
  server: McpServer;
  checked: boolean;
}

interface CatalogModel {
  id: string;
  display_name: string;
  family: string;
  quantization: string;
  filename: string;
  size_bytes: number;
  download_url: string;
  sha256: string;
  min_ram_gb: number;
  tokens_per_sec_apple: number;
  tokens_per_sec_intel: number;
  quality_rating: number;
  description: string;
  is_default: boolean;
}

interface DownloadProgress {
  status: string | { failed: string };
  bytes_downloaded: number;
  bytes_total: number;
  speed_bytes_per_sec: number;
  eta_seconds: number;
  percent: number;
}

interface InstalledModelInfo {
  id: string;
  display_name: string;
  filename: string;
  size_bytes: number;
}

interface SystemCapabilities {
  total_ram_bytes: number;
  total_ram_gb: number;
  arch: string;
  is_apple_silicon: boolean;
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
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

/* ---------- step definitions ---------- */

const STEPS = [
  { t: "Welcome to RookBot", d: "An AI-powered firewall that watches what your AI tools do \u2014 at the kernel level." },
  { t: "Grant kernel access", d: "RookBot attaches eBPF probes to monitor process, network, and DNS activity." },
  { t: "Pick a local model", d: "Runs on your machine. Triages events in ~400 ms each. We recommend Qwen3 1.7B." },
  { t: "Connect a cloud brain", d: "Optional. Used for escalations. Capped at $20/month by default." },
  { t: "Wrap your AI tools", d: "We found MCP servers. Wrap them to start monitoring tool calls." },
] as const;

/* ---------- small helpers ---------- */

function StatusRow({ label, ok }: { label: string; ok: boolean }) {
  return (
    <div style={{
      padding: "8px 14px",
      background: "var(--bg-2)",
      borderRadius: 8,
      display: "flex",
      alignItems: "center",
      gap: 10,
    }}>
      <Icon
        name={ok ? "check" : "alert"}
        size={14}
        color={ok ? "var(--green)" : "var(--red)"}
      />
      <span style={{ fontSize: 12.5, color: "var(--ink-1)", flex: 1 }}>{label}</span>
      <span style={{ fontSize: 11, color: ok ? "var(--green)" : "var(--ink-3)" }}>
        {ok ? "Ready" : "Required"}
      </span>
    </div>
  );
}

/* ============================================================
   ONBOARDING PAGE
   ============================================================ */

export function Onboarding() {
  const navigate = useNavigate();
  const [step, setStep] = useState(0);

  // Step 1 (Kernel access / FDA) state
  const [sensorHealth, setSensorHealth] = useState<SensorHealth | null>(null);

  // Step 2 (Pick model) state
  const [capabilities, setCapabilities] = useState<SystemCapabilities | null>(null);
  const [catalog, setCatalog] = useState<CatalogModel[]>([]);
  const [installedModels, setInstalledModels] = useState<InstalledModelInfo[]>([]);
  const [downloadingModelId, setDownloadingModelId] = useState<string | null>(null);
  const [, setDownloadTaskId] = useState<string | null>(null);
  const [downloadProgress, setDownloadProgress] = useState<DownloadProgress | null>(null);
  const [downloadDone, setDownloadDone] = useState(false);
  const [modelError, setModelError] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Step 3 (Cloud) state
  const [apiKeyInput, setApiKeyInput] = useState("");
  const [cloudTesting, setCloudTesting] = useState(false);
  const [cloudConnected, setCloudConnected] = useState(false);

  // Step 4 (Wrap servers) state
  const [servers, setServers] = useState<DetectedServer[]>([]);
  const [serversLoading, setServersLoading] = useState(true);

  // Poll sensor health when on step 1
  useEffect(() => {
    if (step !== 1) return;
    const poll = async () => {
      try {
        const h = await invoke<SensorHealth>("get_sensor_health");
        setSensorHealth(h);
      } catch { /* ignore */ }
    };
    poll();
    const interval = setInterval(poll, 5000);
    return () => clearInterval(interval);
  }, [step]);

  // Load model data when reaching step 2
  useEffect(() => {
    if (step === 2) {
      (async () => {
        try {
          const [caps, models, installed] = await Promise.all([
            invoke<SystemCapabilities>("get_system_capabilities").catch(() => null),
            invoke<CatalogModel[]>("get_model_catalog").catch(() => []),
            invoke<InstalledModelInfo[]>("get_installed_models").catch(() => []),
          ]);
          setCapabilities(caps);
          setCatalog(models);
          setInstalledModels(installed);
        } catch {
          // Model data not available
        }
      })();
    }
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [step]);

  // Load servers when reaching step 4
  useEffect(() => {
    if (step === 4) {
      setServersLoading(true);
      (async () => {
        try {
          const clients = await invoke<McpClient[]>("detect_mcp_clients");
          const detected: DetectedServer[] = [];
          for (const client of clients) {
            if (!client.detected) continue;
            const serverList = await invoke<McpServer[]>("list_mcp_servers", { client: client.name });
            for (const server of serverList) {
              detected.push({ client, server, checked: true });
            }
          }
          setServers(detected);
        } catch {
          // Detection failed
        } finally {
          setServersLoading(false);
        }
      })();
    }
  }, [step]);

  const recommended = catalog.find((m) => {
    if (!capabilities) return m.is_default;
    if (m.is_default && m.min_ram_gb <= capabilities.total_ram_gb) return true;
    return false;
  }) ?? catalog[0];

  const startDownload = async (model: CatalogModel) => {
    try {
      setDownloadingModelId(model.id);
      setDownloadProgress(null);
      setDownloadDone(false);
      setModelError(null);
      const taskId = await invoke<string>("download_model", { modelId: model.id });
      setDownloadTaskId(taskId);
      let pollFailCount = 0;
      pollRef.current = setInterval(async () => {
        try {
          const prog = await invoke<DownloadProgress>("get_download_progress", { taskId });
          setDownloadProgress(prog);
          const st = getStatusType(prog.status);
          if (st === "completed" || st === "done") {
            if (pollRef.current) clearInterval(pollRef.current);
            setDownloadDone(true);
            try { await invoke("activate_model", { modelId: model.id }); } catch { /* noop */ }
          } else if (st === "failed") {
            const msg = typeof prog.status === "object" && prog.status !== null ? (prog.status as { failed: string }).failed : "Download failed";
            if (pollRef.current) clearInterval(pollRef.current);
            setModelError(msg);
            setDownloadingModelId(null);
          }
        } catch {
          pollFailCount++;
          if (pollFailCount >= 10) {
            if (pollRef.current) clearInterval(pollRef.current);
            setModelError("Connection lost");
            setDownloadingModelId(null);
          }
        }
      }, 500);
    } catch (e) {
      setModelError(String(e));
      setDownloadingModelId(null);
    }
  };

  const handleFinish = async () => {
    // Wrap checked servers
    for (const s of servers) {
      if (s.checked && !s.server.wrapped) {
        try { await invoke("wrap_server", { client: s.client.name, server: s.server.name }); } catch { /* noop */ }
      }
    }
    try { await invoke("complete_onboarding"); } catch { /* noop */ }
    navigate("/");
  };

  const s = STEPS[step];

  return (
    <div style={{ display: "grid", placeItems: "center", height: "100%", padding: 32 }}>
      <div
        style={{
          width: "100%",
          maxWidth: 560,
          background: "var(--bg-1)",
          border: "1px solid var(--line)",
          borderRadius: "var(--radius-xl, 16px)",
          overflow: "hidden",
          boxShadow: "var(--shadow-lg, 0 8px 30px oklch(0 0 0 / 0.08))",
        }}
      >
        {/* Progress bar */}
        <div
          style={{
            padding: "16px 24px",
            display: "flex",
            alignItems: "center",
            gap: 8,
            borderBottom: "1px solid var(--line-soft)",
          }}
        >
          {STEPS.map((_, i) => (
            <div
              key={i}
              style={{
                flex: 1,
                height: 3,
                borderRadius: 2,
                background: i <= step ? "var(--accent)" : "var(--bg-3)",
                transition: "background 0.3s",
              }}
            />
          ))}
          <span
            style={{
              fontSize: 10.5,
              fontFamily: "var(--font-mono)",
              color: "var(--ink-3)",
              marginLeft: 8,
            }}
          >
            {step + 1} / {STEPS.length}
          </span>
        </div>

        {/* Content */}
        <div style={{ padding: "32px 28px", textAlign: "center" }}>
          {/* Rook icon */}
          <div
            style={{
              width: 56,
              height: 56,
              borderRadius: 14,
              background: "var(--accent-soft)",
              border: "1px solid var(--accent-line)",
              display: "grid",
              placeItems: "center",
              margin: "0 auto 18px",
            }}
          >
            <Rook size={28} color="var(--accent)" />
          </div>

          <h1 style={{ margin: 0, fontSize: 22, fontWeight: 600, letterSpacing: -0.3 }}>{s.t}</h1>
          <p style={{ margin: "10px auto 0", fontSize: 13.5, color: "var(--ink-2)", lineHeight: 1.6, maxWidth: 420 }}>
            {s.d}
          </p>

          {/* Step 1: Grant kernel access */}
          {step === 1 && (
            <div style={{ marginTop: 22, textAlign: "left" }}>
              {/* Status checklist */}
              <div style={{ display: "grid", gap: 8, marginBottom: 16 }}>
                <StatusRow
                  label="macOS version"
                  ok={sensorHealth?.os_version_ok ?? false}
                />
                <StatusRow
                  label="Full Disk Access"
                  ok={sensorHealth?.fda_granted ?? false}
                />
                <StatusRow
                  label="Daemon running"
                  ok={sensorHealth?.daemon_running ?? false}
                />
              </div>

              {/* Open System Settings button */}
              <div style={{ textAlign: "center", marginBottom: 12 }}>
                <Btn kind="primary" onClick={() => invoke("open_system_settings_fda")}>
                  Open System Settings
                </Btn>
              </div>

              {/* Skip note */}
              <div style={{ fontSize: 11, color: "var(--ink-3)", textAlign: "center" }}>
                You can set this up later in Settings
              </div>
            </div>
          )}

          {/* Step 2: Pick a local model */}
          {step === 2 && (
            <div style={{ marginTop: 22, textAlign: "left" }}>
              {capabilities && (
                <div style={{ fontSize: 11, color: "var(--ink-3)", fontFamily: "var(--font-mono)", marginBottom: 12, textAlign: "center" }}>
                  {capabilities.is_apple_silicon ? "Apple Silicon" : capabilities.arch} \u00B7 {capabilities.total_ram_gb} GB RAM
                </div>
              )}

              {downloadDone && (
                <div style={{ padding: "10px 14px", background: "color-mix(in oklch, var(--green) 10%, transparent)", borderRadius: 8, fontSize: 12, color: "var(--green)", textAlign: "center", marginBottom: 12 }}>
                  Model installed and activated
                </div>
              )}

              {modelError && (
                <div style={{ padding: "10px 14px", background: "color-mix(in oklch, var(--red) 10%, transparent)", borderRadius: 8, fontSize: 12, color: "var(--red)", textAlign: "center", marginBottom: 12 }}>
                  {modelError}
                </div>
              )}

              {downloadingModelId && downloadProgress && !downloadDone && (
                <div style={{ marginBottom: 12 }}>
                  <div style={{ width: "100%", height: 4, borderRadius: 2, background: "var(--bg-3)", overflow: "hidden" }}>
                    <div style={{ width: `${Math.min(downloadProgress.percent, 100)}%`, height: "100%", borderRadius: 2, background: "var(--accent)", transition: "width 0.3s" }} />
                  </div>
                  <div style={{ fontSize: 10.5, color: "var(--ink-3)", fontFamily: "var(--font-mono)", marginTop: 4, textAlign: "center" }}>
                    {formatBytes(downloadProgress.bytes_downloaded)} / {formatBytes(downloadProgress.bytes_total)}
                    {downloadProgress.speed_bytes_per_sec > 0 && ` \u00B7 ${formatBytes(downloadProgress.speed_bytes_per_sec)}/s`}
                  </div>
                </div>
              )}

              {!downloadingModelId && !downloadDone && catalog.length > 0 && (
                <div style={{ display: "grid", gap: 8 }}>
                  {catalog.slice(0, 4).map((m) => {
                    const installed = installedModels.some((im) => im.id === m.id);
                    const isRec = recommended?.id === m.id;
                    return (
                      <div key={m.id} style={{
                        padding: "10px 14px", background: "var(--bg-2)", borderRadius: 8,
                        border: isRec ? "1px solid var(--accent-line)" : "1px solid var(--line-soft)",
                        display: "flex", alignItems: "center", gap: 10,
                      }}>
                        <Icon name="cpu" size={14} color="var(--ink-1)" />
                        <div style={{ flex: 1 }}>
                          <div style={{ fontSize: 12.5 }}>{m.display_name}</div>
                          <div style={{ fontSize: 10.5, color: "var(--ink-3)", fontFamily: "var(--font-mono)" }}>
                            {formatBytes(m.size_bytes)}{isRec ? " \u00B7 recommended" : ""}
                          </div>
                        </div>
                        {installed ? (
                          <span style={{ fontSize: 11, color: "var(--green)" }}>Installed</span>
                        ) : (
                          <Btn size="sm" kind={isRec ? "primary" : "soft"} onClick={() => startDownload(m)}>
                            {isRec ? "Download" : "Get"}
                          </Btn>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* Step 3: Connect cloud brain */}
          {step === 3 && (
            <div style={{ marginTop: 22, textAlign: "left" }}>
              {cloudConnected ? (
                <div style={{ padding: "10px 14px", background: "color-mix(in oklch, var(--green) 10%, transparent)", borderRadius: 8, fontSize: 12, color: "var(--green)", textAlign: "center" }}>
                  Cloud brain connected
                </div>
              ) : (
                <div style={{ display: "grid", gap: 10 }}>
                  <div>
                    <div style={{ fontSize: 10.5, color: "var(--ink-3)", textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 4 }}>API Key</div>
                    <input
                      type="password"
                      value={apiKeyInput}
                      onChange={(e) => setApiKeyInput(e.target.value)}
                      placeholder="sk-ant-..."
                      style={{ width: "100%", boxSizing: "border-box", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: 6, padding: "8px 10px", fontSize: 12, fontFamily: "var(--font-mono)", color: "var(--ink-0)", outline: "none" }}
                    />
                  </div>
                  <Btn
                    size="sm"
                    kind="primary"
                    disabled={cloudTesting || !apiKeyInput.trim()}
                    onClick={async () => {
                      setCloudTesting(true);
                      try {
                        await invoke("save_api_key", { provider: "anthropic", key: apiKeyInput.trim() });
                        await invoke("test_api_connection", { provider: "anthropic", model: "claude-sonnet-4-5-20250929" });
                        setCloudConnected(true);
                      } catch {
                        // Test failed, but not fatal
                      } finally {
                        setCloudTesting(false);
                      }
                    }}
                  >
                    {cloudTesting ? "Testing..." : "Save & Test"}
                  </Btn>
                  <div style={{ fontSize: 11, color: "var(--ink-3)", textAlign: "center" }}>
                    You can skip this and set it up later in Settings.
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Step 4: Wrap MCP servers */}
          {step === 4 && (
            <div style={{ marginTop: 22, textAlign: "left", display: "grid", gap: 8 }}>
              {serversLoading ? (
                <div style={{ textAlign: "center", fontSize: 12, color: "var(--ink-2)", padding: 16 }}>
                  Scanning for MCP servers...
                </div>
              ) : servers.length === 0 ? (
                <div style={{ textAlign: "center", fontSize: 12, color: "var(--ink-2)", padding: 16 }}>
                  No MCP servers found. You can add them later.
                </div>
              ) : (
                servers.map((s, i) => (
                  <div
                    key={`${s.client.name}-${s.server.name}`}
                    style={{
                      padding: "10px 14px",
                      background: "var(--bg-2)",
                      borderRadius: 8,
                      display: "flex",
                      alignItems: "center",
                      gap: 10,
                    }}
                  >
                    <Icon name="tools" size={14} color="var(--ink-1)" />
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: 12.5 }}>{s.server.name}</div>
                      <div style={{ fontSize: 10.5, color: "var(--ink-3)", fontFamily: "var(--font-mono)" }}>
                        {s.client.display_name}
                      </div>
                    </div>
                    <input
                      type="checkbox"
                      checked={s.checked}
                      onChange={() => {
                        setServers((prev) => prev.map((sv, j) => j === i ? { ...sv, checked: !sv.checked } : sv));
                      }}
                      style={{ accentColor: "var(--accent)" }}
                    />
                  </div>
                ))
              )}
            </div>
          )}
        </div>

        {/* Footer navigation */}
        <div
          style={{
            padding: "16px 24px",
            borderTop: "1px solid var(--line-soft)",
            display: "flex",
            gap: 8,
          }}
        >
          {step > 0 && (
            <Btn kind="ghost" onClick={() => setStep(step - 1)}>
              Back
            </Btn>
          )}
          <span style={{ flex: 1 }} />
          {step < STEPS.length - 1 ? (
            <Btn kind="primary" onClick={() => setStep(step + 1)}>
              Continue
            </Btn>
          ) : (
            <Btn kind="primary" icon="check" onClick={handleFinish}>
              Start protecting
            </Btn>
          )}
        </div>
      </div>
    </div>
  );
}
