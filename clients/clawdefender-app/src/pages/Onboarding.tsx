import { useState, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import type { McpClient, McpServer } from "../types";

type Step = 1 | 2 | 3 | 4;

interface DetectedServer {
  client: McpClient;
  server: McpServer;
  checked: boolean;
}

type WrapStatus = "pending" | "wrapping" | "done" | "error";

interface WrapResult {
  serverName: string;
  status: WrapStatus;
}

const SECURITY_LEVELS = [
  {
    id: "permissive",
    name: "Monitor Only",
    icon: "\u25CB",
    description:
      "Log all activity without blocking. Good for observing what your AI agents do before enforcing rules.",
  },
  {
    id: "balanced",
    name: "Balanced",
    icon: "\u25C9",
    description:
      "Block high-risk actions and prompt for sensitive operations. Recommended for most users.",
    recommended: true,
  },
  {
    id: "strict",
    name: "Strict",
    icon: "\u25C8",
    description:
      "Prompt for all actions and deny anything not explicitly allowed. Best for high-security environments.",
  },
] as const;

function StepIndicator({ current }: { current: Step }) {
  return (
    <div className="flex items-center justify-center gap-2 mb-10">
      {([1, 2, 3, 4] as const).map((s) => (
        <div key={s} className="flex items-center gap-2">
          <div
            className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium transition-colors ${
              s === current
                ? "bg-[var(--color-accent)] text-white"
                : s < current
                  ? "bg-[var(--color-success)] text-white"
                  : "bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)]"
            }`}
          >
            {s < current ? "\u2713" : s}
          </div>
          {s < 4 && (
            <div
              className={`w-12 h-0.5 transition-colors ${
                s < current
                  ? "bg-[var(--color-success)]"
                  : "bg-[var(--color-bg-tertiary)]"
              }`}
            />
          )}
        </div>
      ))}
    </div>
  );
}

function WelcomeStep({ onNext }: { onNext: () => void }) {
  return (
    <div className="text-center">
      <div className="text-6xl mb-6 text-[var(--color-accent)]">{"\u25C8"}</div>
      <h1 className="text-3xl font-bold mb-3 text-[var(--color-text-primary)]">
        Welcome to ClawDefender
      </h1>
      <p className="text-lg text-[var(--color-text-secondary)] mb-6">
        Your AI agents are about to get a lot safer.
      </p>
      <p className="text-[var(--color-text-secondary)] mb-10 max-w-md mx-auto leading-relaxed">
        ClawDefender sits between your AI tools and the MCP servers they use,
        monitoring every action, enforcing security policies, and alerting you
        when something looks wrong -- all without slowing anything down.
      </p>
      <button
        onClick={onNext}
        className="px-8 py-3 rounded-lg bg-[var(--color-accent)] hover:bg-[var(--color-accent-hover)] text-white font-medium text-lg transition-colors"
      >
        Get Started
      </button>
    </div>
  );
}

function DetectStep({
  onNext,
  setWrappedServers,
}: {
  onNext: () => void;
  setWrappedServers: (servers: string[]) => void;
}) {
  const [loading, setLoading] = useState(true);
  const [servers, setServers] = useState<DetectedServer[]>([]);
  const [wrapResults, setWrapResults] = useState<WrapResult[]>([]);
  const [wrapping, setWrapping] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function detect() {
      try {
        const clients = await invoke<McpClient[]>("detect_mcp_clients");
        const detected: DetectedServer[] = [];
        for (const client of clients) {
          if (!client.detected) continue;
          const serverList = await invoke<McpServer[]>("list_mcp_servers", {
            client: client.name,
          });
          for (const server of serverList) {
            detected.push({ client, server, checked: !server.wrapped });
          }
        }
        setServers(detected);
      } catch (e) {
        setError(String(e));
      } finally {
        setLoading(false);
      }
    }
    detect();
  }, []);

  const toggleServer = useCallback(
    (index: number) => {
      if (wrapping) return;
      setServers((prev) =>
        prev.map((s, i) => (i === index ? { ...s, checked: !s.checked } : s))
      );
    },
    [wrapping]
  );

  const handleProtect = async () => {
    const toWrap = servers.filter((s) => s.checked && !s.server.wrapped);
    if (toWrap.length === 0) {
      setWrappedServers(
        servers.filter((s) => s.checked).map((s) => s.server.name)
      );
      onNext();
      return;
    }

    setWrapping(true);
    setWrapResults(
      toWrap.map((s) => ({ serverName: s.server.name, status: "pending" }))
    );

    const names: string[] = [];
    for (let i = 0; i < toWrap.length; i++) {
      const s = toWrap[i];
      setWrapResults((prev) =>
        prev.map((r, j) => (j === i ? { ...r, status: "wrapping" } : r))
      );
      try {
        await invoke("wrap_server", {
          client: s.client.name,
          server: s.server.name,
        });
        setWrapResults((prev) =>
          prev.map((r, j) => (j === i ? { ...r, status: "done" } : r))
        );
        names.push(s.server.name);
      } catch {
        setWrapResults((prev) =>
          prev.map((r, j) => (j === i ? { ...r, status: "error" } : r))
        );
      }
    }

    // Also include already-wrapped servers that were checked
    const alreadyWrapped = servers
      .filter((s) => s.checked && s.server.wrapped)
      .map((s) => s.server.name);
    setWrappedServers([...names, ...alreadyWrapped]);

    // Brief pause to show final state
    await new Promise((r) => setTimeout(r, 600));
    setWrapping(false);
    onNext();
  };

  if (loading) {
    return (
      <div className="text-center">
        <div className="text-4xl mb-4 animate-pulse text-[var(--color-accent)]">
          {"\u25CE"}
        </div>
        <p className="text-[var(--color-text-secondary)]">
          Scanning for MCP clients...
        </p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-center">
        <p className="text-[var(--color-danger)] mb-4">
          Failed to detect MCP clients: {error}
        </p>
        <button
          onClick={onNext}
          className="px-6 py-2 rounded-lg bg-[var(--color-bg-tertiary)] hover:bg-[var(--color-border)] text-[var(--color-text-primary)] transition-colors"
        >
          Skip
        </button>
      </div>
    );
  }

  if (servers.length === 0) {
    return (
      <div className="text-center">
        <div className="text-4xl mb-4 text-[var(--color-text-secondary)]">
          {"\u2205"}
        </div>
        <h2 className="text-xl font-semibold mb-2 text-[var(--color-text-primary)]">
          No MCP Clients Detected
        </h2>
        <p className="text-[var(--color-text-secondary)] mb-6 max-w-md mx-auto">
          ClawDefender did not find any MCP clients on your system. You can add
          servers manually later from the Dashboard.
        </p>
        <button
          onClick={onNext}
          className="px-8 py-3 rounded-lg bg-[var(--color-accent)] hover:bg-[var(--color-accent-hover)] text-white font-medium transition-colors"
        >
          Continue
        </button>
      </div>
    );
  }

  return (
    <div>
      <h2 className="text-xl font-semibold mb-2 text-center text-[var(--color-text-primary)]">
        Detect &amp; Protect
      </h2>
      <p className="text-[var(--color-text-secondary)] text-center mb-6">
        We found the following MCP servers. Select which ones to protect.
      </p>

      <div className="space-y-2 mb-8 max-h-64 overflow-y-auto">
        {servers.map((s, i) => (
          <label
            key={`${s.client.name}-${s.server.name}`}
            className="flex items-center gap-3 p-3 rounded-lg bg-[var(--color-bg-tertiary)] hover:bg-[var(--color-border)] transition-colors cursor-pointer"
          >
            <input
              type="checkbox"
              checked={s.checked}
              onChange={() => toggleServer(i)}
              disabled={wrapping || s.server.wrapped}
              className="w-4 h-4 accent-[var(--color-accent)]"
            />
            <div className="flex-1 min-w-0">
              <div className="text-sm font-medium text-[var(--color-text-primary)] truncate">
                {s.server.name}
              </div>
              <div className="text-xs text-[var(--color-text-secondary)] truncate">
                via {s.client.display_name}
              </div>
            </div>
            {s.server.wrapped && (
              <span className="text-xs text-[var(--color-success)]">
                Already protected
              </span>
            )}
          </label>
        ))}
      </div>

      {wrapResults.length > 0 && (
        <div className="space-y-1 mb-6">
          {wrapResults.map((r) => (
            <div
              key={r.serverName}
              className="flex items-center gap-2 text-sm px-3 py-1"
            >
              <span>
                {r.status === "pending" && (
                  <span className="text-[var(--color-text-secondary)]">
                    {"\u25CB"}
                  </span>
                )}
                {r.status === "wrapping" && (
                  <span className="text-[var(--color-accent)] animate-pulse">
                    {"\u25CF"}
                  </span>
                )}
                {r.status === "done" && (
                  <span className="text-[var(--color-success)]">{"\u2713"}</span>
                )}
                {r.status === "error" && (
                  <span className="text-[var(--color-danger)]">{"\u2717"}</span>
                )}
              </span>
              <span className="text-[var(--color-text-secondary)]">
                {r.serverName}
              </span>
            </div>
          ))}
        </div>
      )}

      <div className="flex justify-center">
        <button
          onClick={handleProtect}
          disabled={wrapping || servers.every((s) => !s.checked)}
          className="px-8 py-3 rounded-lg bg-[var(--color-accent)] hover:bg-[var(--color-accent-hover)] text-white font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {wrapping ? "Protecting..." : "Protect These"}
        </button>
      </div>
    </div>
  );
}

function SecurityLevelStep({
  onNext,
  selectedLevel,
  setSelectedLevel,
}: {
  onNext: () => void;
  selectedLevel: string;
  setSelectedLevel: (level: string) => void;
}) {
  const [applying, setApplying] = useState(false);

  const handleContinue = async () => {
    setApplying(true);
    try {
      await invoke("apply_template", { name: selectedLevel });
    } catch {
      // Template apply failure is non-fatal during onboarding
    }
    setApplying(false);
    onNext();
  };

  return (
    <div>
      <h2 className="text-xl font-semibold mb-2 text-center text-[var(--color-text-primary)]">
        Choose Security Level
      </h2>
      <p className="text-[var(--color-text-secondary)] text-center mb-8">
        You can change this anytime from Settings.
      </p>

      <div className="space-y-3 mb-8">
        {SECURITY_LEVELS.map((level) => (
          <button
            key={level.id}
            onClick={() => setSelectedLevel(level.id)}
            className={`w-full text-left p-4 rounded-lg border transition-colors ${
              selectedLevel === level.id
                ? "border-[var(--color-accent)] bg-[var(--color-accent)]/10"
                : "border-[var(--color-border)] bg-[var(--color-bg-tertiary)] hover:border-[var(--color-text-secondary)]"
            }`}
          >
            <div className="flex items-center gap-3">
              <span className="text-2xl">{level.icon}</span>
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <span className="font-medium text-[var(--color-text-primary)]">
                    {level.name}
                  </span>
                  {"recommended" in level && level.recommended && (
                    <span className="text-xs px-2 py-0.5 rounded-full bg-[var(--color-accent)] text-white">
                      Recommended
                    </span>
                  )}
                </div>
                <p className="text-sm text-[var(--color-text-secondary)] mt-1">
                  {level.description}
                </p>
              </div>
              <div
                className={`w-5 h-5 rounded-full border-2 flex items-center justify-center ${
                  selectedLevel === level.id
                    ? "border-[var(--color-accent)]"
                    : "border-[var(--color-border)]"
                }`}
              >
                {selectedLevel === level.id && (
                  <div className="w-2.5 h-2.5 rounded-full bg-[var(--color-accent)]" />
                )}
              </div>
            </div>
          </button>
        ))}
      </div>

      <div className="flex justify-center">
        <button
          onClick={handleContinue}
          disabled={applying}
          className="px-8 py-3 rounded-lg bg-[var(--color-accent)] hover:bg-[var(--color-accent-hover)] text-white font-medium transition-colors disabled:opacity-50"
        >
          {applying ? "Applying..." : "Continue"}
        </button>
      </div>
    </div>
  );
}

function CompleteStep({
  wrappedServers,
  onFinish,
}: {
  wrappedServers: string[];
  onFinish: () => void;
}) {
  const [startAtLogin, setStartAtLogin] = useState(true);
  const [showInMenuBar, setShowInMenuBar] = useState(true);

  const handleFinish = async () => {
    try {
      await invoke("complete_onboarding");
    } catch {
      // Non-fatal
    }
    onFinish();
  };

  return (
    <div className="text-center">
      <div className="text-5xl mb-4 text-[var(--color-success)]">{"\u2713"}</div>
      <h2 className="text-2xl font-bold mb-2 text-[var(--color-text-primary)]">
        You're All Set!
      </h2>
      <p className="text-[var(--color-text-secondary)] mb-6">
        ClawDefender is now protecting your MCP servers.
      </p>

      {wrappedServers.length > 0 && (
        <div className="mb-6 p-4 rounded-lg bg-[var(--color-bg-tertiary)] text-left max-w-sm mx-auto">
          <p className="text-sm font-medium text-[var(--color-text-primary)] mb-2">
            Protected servers:
          </p>
          <ul className="space-y-1">
            {wrappedServers.map((name) => (
              <li
                key={name}
                className="text-sm text-[var(--color-text-secondary)] flex items-center gap-2"
              >
                <span className="text-[var(--color-success)]">{"\u2713"}</span>
                {name}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="mb-4 p-4 rounded-lg bg-[var(--color-warning)]/10 border border-[var(--color-warning)]/30 max-w-sm mx-auto">
        <p className="text-sm text-[var(--color-warning)]">
          Remember to restart your AI applications for the protection to take
          effect.
        </p>
      </div>

      <div className="mb-8 p-4 rounded-lg bg-[var(--color-accent)]/10 border border-[var(--color-accent)]/30 max-w-sm mx-auto">
        <p className="text-sm text-[var(--color-accent)]">
          For maximum protection, enable Network Protection in Settings to block
          suspicious network connections from AI agents.
        </p>
      </div>

      <div className="space-y-3 mb-8 max-w-xs mx-auto text-left">
        <label className="flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={startAtLogin}
            onChange={(e) => setStartAtLogin(e.target.checked)}
            className="w-4 h-4 accent-[var(--color-accent)]"
          />
          <span className="text-sm text-[var(--color-text-secondary)]">
            Start at login
          </span>
        </label>
        <label className="flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={showInMenuBar}
            onChange={(e) => setShowInMenuBar(e.target.checked)}
            className="w-4 h-4 accent-[var(--color-accent)]"
          />
          <span className="text-sm text-[var(--color-text-secondary)]">
            Show in menu bar
          </span>
        </label>
      </div>

      <button
        onClick={handleFinish}
        className="px-8 py-3 rounded-lg bg-[var(--color-accent)] hover:bg-[var(--color-accent-hover)] text-white font-medium text-lg transition-colors"
      >
        Open Dashboard
      </button>
    </div>
  );
}

export function Onboarding() {
  const navigate = useNavigate();
  const [step, setStep] = useState<Step>(1);
  const [wrappedServers, setWrappedServers] = useState<string[]>([]);
  const [selectedLevel, setSelectedLevel] = useState("balanced");

  const nextStep = () => setStep((s) => Math.min(s + 1, 4) as Step);

  return (
    <div className="flex items-center justify-center min-h-screen bg-[var(--color-bg-primary)] p-6">
      <div className="w-full max-w-[600px]">
        <StepIndicator current={step} />

        {step === 1 && <WelcomeStep onNext={nextStep} />}

        {step === 2 && (
          <DetectStep
            onNext={nextStep}
            setWrappedServers={setWrappedServers}
          />
        )}

        {step === 3 && (
          <SecurityLevelStep
            onNext={nextStep}
            selectedLevel={selectedLevel}
            setSelectedLevel={setSelectedLevel}
          />
        )}

        {step === 4 && (
          <CompleteStep
            wrappedServers={wrappedServers}
            onFinish={() => navigate("/")}
          />
        )}
      </div>
    </div>
  );
}
