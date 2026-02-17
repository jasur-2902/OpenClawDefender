import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { PendingPrompt } from "../types";
import { useEventStore } from "../stores/eventStore";

type Decision = "deny" | "allow_once" | "allow_session" | "allow_always";

interface PromptWindowProps {
  prompt: PendingPrompt;
  queueCount: number;
}

export function PromptWindow({ prompt, queueCount }: PromptWindowProps) {
  const removePrompt = useEventStore((s) => s.removePrompt);
  const [remaining, setRemaining] = useState(prompt.timeout_seconds);
  const [responding, setResponding] = useState(false);

  const isHighRisk =
    prompt.risk_level === "high" || prompt.risk_level === "critical";

  const respond = useCallback(
    async (decision: Decision) => {
      if (responding) return;
      setResponding(true);
      try {
        await invoke("respond_to_prompt", {
          promptId: prompt.id,
          decision,
        });
      } catch {
        // Daemon may not be connected; still remove from UI
      }
      removePrompt(prompt.id);
    },
    [prompt.id, removePrompt, responding]
  );

  // Countdown timer
  useEffect(() => {
    const start = Date.now();
    const interval = setInterval(() => {
      const elapsed = Math.floor((Date.now() - start) / 1000);
      const left = prompt.timeout_seconds - elapsed;
      if (left <= 0) {
        clearInterval(interval);
        respond("deny");
      } else {
        setRemaining(left);
      }
    }, 250);
    return () => clearInterval(interval);
  }, [prompt.timeout_seconds, respond]);

  // Keyboard shortcuts
  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;
      switch (e.key.toLowerCase()) {
        case "d":
          respond("deny");
          break;
        case "a":
          respond("allow_once");
          break;
        case "s":
          respond("allow_session");
          break;
        case "p":
          respond("allow_always");
          break;
      }
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [respond]);

  const timerPercent = (remaining / prompt.timeout_seconds) * 100;
  const timerColor =
    remaining <= 5
      ? "var(--color-danger)"
      : remaining <= 10
        ? "var(--color-warning)"
        : "var(--color-accent)";

  const riskColors: Record<string, string> = {
    low: "var(--color-success)",
    medium: "var(--color-warning)",
    high: "var(--color-danger)",
    critical: "var(--color-danger)",
  };

  return (
    <div role="alertdialog" aria-labelledby="prompt-title" aria-describedby="prompt-details" className="flex flex-col w-full max-w-md mx-auto bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-lg shadow-2xl overflow-hidden">
      {/* Timer bar */}
      <div className="h-1 bg-[var(--color-bg-tertiary)]">
        <div
          className="h-full transition-all duration-250 ease-linear"
          style={{
            width: `${timerPercent}%`,
            backgroundColor: timerColor,
          }}
        />
      </div>

      {/* High risk warning banner */}
      {isHighRisk && (
        <div className="px-4 py-2 bg-[var(--color-danger)] text-white text-sm font-semibold text-center">
          ClawDefender recommends DENYING this request
        </div>
      )}

      {/* Header */}
      <div className="px-4 pt-4 pb-2 flex items-center justify-between">
        <span id="prompt-title" className="text-sm font-semibold text-[var(--color-text-primary)]">
          Approval Required
        </span>
        <span className="text-xs font-mono text-[var(--color-text-secondary)]" aria-live="polite" aria-label={`${remaining} seconds remaining`}>
          {remaining}s
        </span>
      </div>

      {/* Details */}
      <div id="prompt-details" className="px-4 pb-3 space-y-2">
        <div className="flex items-center gap-2">
          <span
            aria-hidden="true"
            className="inline-block w-2 h-2 rounded-full"
            style={{ backgroundColor: riskColors[prompt.risk_level] }}
          />
          <span className="text-xs font-semibold uppercase" aria-label={`Risk level: ${prompt.risk_level}`} style={{ color: riskColors[prompt.risk_level] }}>
            {prompt.risk_level} risk
          </span>
        </div>

        <div className="space-y-1.5 text-sm">
          <Row label="Server" value={prompt.server_name} />
          <Row label="Tool" value={prompt.tool_name} />
          <Row label="Action" value={prompt.action} />
          <Row label="Resource" value={prompt.resource} />
        </div>

        {prompt.context && (
          <p className="text-xs text-[var(--color-text-secondary)] bg-[var(--color-bg-tertiary)] rounded px-2 py-1.5 break-words">
            {prompt.context}
          </p>
        )}
      </div>

      {/* Action buttons */}
      <div className={`px-4 pb-4 ${isHighRisk ? "space-y-2" : ""}`}>
        {isHighRisk ? (
          <>
            <button
              onClick={() => respond("deny")}
              disabled={responding}
              autoFocus={isHighRisk}
              className="w-full py-2.5 rounded-md text-sm font-bold bg-[var(--color-danger)] text-white hover:brightness-110 transition-all disabled:opacity-50"
            >
              Deny (D)
            </button>
            <div className="grid grid-cols-3 gap-2">
              <ActionBtn label="Allow Once" hint="A" onClick={() => respond("allow_once")} disabled={responding} />
              <ActionBtn label="Session" hint="S" onClick={() => respond("allow_session")} disabled={responding} />
              <ActionBtn label="Always" hint="P" onClick={() => respond("allow_always")} disabled={responding} />
            </div>
          </>
        ) : (
          <div className="grid grid-cols-4 gap-2">
            <ActionBtn label="Deny" hint="D" onClick={() => respond("deny")} disabled={responding} variant="danger" />
            <ActionBtn label="Allow Once" hint="A" onClick={() => respond("allow_once")} disabled={responding} />
            <ActionBtn label="Session" hint="S" onClick={() => respond("allow_session")} disabled={responding} />
            <ActionBtn label="Always" hint="P" onClick={() => respond("allow_always")} disabled={responding} />
          </div>
        )}
      </div>

      {/* Queue indicator */}
      {queueCount > 0 && (
        <div className="px-4 py-2 border-t border-[var(--color-border)] text-center text-xs text-[var(--color-text-secondary)]">
          {queueCount} more pending
        </div>
      )}
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex gap-2">
      <span className="text-[var(--color-text-secondary)] min-w-16 shrink-0">{label}</span>
      <span className="text-[var(--color-text-primary)] font-medium break-all">{value}</span>
    </div>
  );
}

function ActionBtn({
  label,
  hint,
  onClick,
  disabled,
  variant,
}: {
  label: string;
  hint: string;
  onClick: () => void;
  disabled: boolean;
  variant?: "danger";
}) {
  const base =
    "py-2 rounded-md text-xs font-medium transition-all disabled:opacity-50";
  const style =
    variant === "danger"
      ? `${base} bg-[var(--color-danger)] text-white hover:brightness-110`
      : `${base} bg-[var(--color-bg-tertiary)] text-[var(--color-text-primary)] hover:bg-[var(--color-border)]`;

  return (
    <button onClick={onClick} disabled={disabled} className={style}>
      {label} ({hint})
    </button>
  );
}
