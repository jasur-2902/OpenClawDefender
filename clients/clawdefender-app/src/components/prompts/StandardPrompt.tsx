import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { PendingPrompt } from "../../types";
import { useEventStore } from "../../stores/eventStore";
import { PROMPT_CONFIRMATION } from "../../constants/messages";
import { useToastStore } from "../notifications/ToastContainer";

interface SlmAnalysis {
  analysis: string;
  recommendation: string;
}

type Decision = "allow_once" | "allow_always" | "deny" | "deny_always";

interface StandardPromptProps {
  prompt: PendingPrompt;
  queueCount: number;
}

export function StandardPrompt({ prompt, queueCount }: StandardPromptProps) {
  const removePrompt = useEventStore((s) => s.removePrompt);
  const addToast = useToastStore((s) => s.addToast);
  const [remaining, setRemaining] = useState(prompt.timeout_seconds);
  const [responding, setResponding] = useState(false);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [slmAnalysis, setSlmAnalysis] = useState<SlmAnalysis | null>(
    prompt.slm_analysis
      ? { analysis: prompt.slm_analysis, recommendation: prompt.slm_recommendation ?? "" }
      : null
  );
  const [slmLoading, setSlmLoading] = useState(!prompt.slm_analysis);

  const respond = useCallback(
    async (decision: Decision) => {
      if (responding) return;
      setResponding(true);
      try {
        // Backend handles allow_always and deny_always natively
        // (creates persistent policy rules and reloads daemon).
        await invoke("respond_to_prompt", {
          promptId: prompt.id,
          decision,
        });

        const message =
          decision === "allow_once"
            ? PROMPT_CONFIRMATION.allowed
            : decision === "allow_always"
              ? PROMPT_CONFIRMATION.allowedAlways
              : decision === "deny"
                ? PROMPT_CONFIRMATION.blocked
                : PROMPT_CONFIRMATION.blockedAlways;

        addToast({
          title: message,
          severity: decision.startsWith("allow") ? "info" : "warning",
          duration: 3000,
        });
      } catch {
        // Daemon may not be connected; still remove from UI
      }
      removePrompt(prompt.id);
    },
    [prompt.id, prompt.server_name, prompt.action, removePrompt, responding, addToast]
  );

  // Progressive SLM analysis loading (skipped if pre-enriched)
  useEffect(() => {
    if (slmAnalysis) return; // Already have pre-enriched analysis
    let cancelled = false;
    invoke<SlmAnalysis>("get_slm_analysis_for_prompt", { promptId: prompt.id })
      .then((result) => {
        if (!cancelled && result) {
          setSlmAnalysis(result);
          setSlmLoading(false);
        }
      })
      .catch(() => {
        if (!cancelled) setSlmLoading(false);
      });
    return () => { cancelled = true; };
  }, [prompt.id, slmAnalysis]);

  // Countdown timer
  useEffect(() => {
    const start = Date.now();
    const interval = setInterval(() => {
      const elapsed = Math.floor((Date.now() - start) / 1000);
      const left = prompt.timeout_seconds - elapsed;
      if (left <= 0) {
        clearInterval(interval);
        addToast({
          title: PROMPT_CONFIRMATION.timeout,
          severity: "warning",
          duration: 5000,
        });
        respond("deny");
      } else {
        setRemaining(left);
      }
    }, 250);
    return () => clearInterval(interval);
  }, [prompt.timeout_seconds, respond, addToast]);

  // Keyboard shortcuts
  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;
      const key = e.key.toLowerCase();
      if (key === "a" && e.shiftKey) {
        e.preventDefault();
        respond("allow_always");
      } else if (key === "a") {
        e.preventDefault();
        respond("allow_once");
      } else if (key === "b" && e.shiftKey) {
        e.preventDefault();
        respond("deny_always");
      } else if (key === "b") {
        e.preventDefault();
        respond("deny");
      } else if (key === "escape") {
        e.preventDefault();
        setDetailsOpen((prev) => !prev);
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

  const humanAction = prompt.action.replace(/_/g, " ").replace(/\//g, " ");
  const serverDisplay = prompt.server_name
    .replace(/^mcp-server-/, "")
    .replace(/^mcp-/, "")
    .replace(/-/g, " ");

  return (
    <div
      role="alertdialog"
      aria-labelledby="prompt-title"
      aria-describedby="prompt-context"
      className="flex flex-col w-full max-w-md mx-auto bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-lg shadow-2xl overflow-hidden"
    >
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

      {/* Header */}
      <div className="px-4 pt-4 pb-1">
        <div className="flex items-center justify-between">
          <h2 id="prompt-title" className="text-sm font-semibold text-[var(--color-text-primary)]">
            {serverDisplay} wants to {humanAction}
          </h2>
          <span
            className="text-xs font-mono text-[var(--color-text-secondary)]"
            aria-live="polite"
            aria-label={`${remaining} seconds remaining`}
          >
            {remaining}s
          </span>
        </div>
        <p id="prompt-context" className="text-xs text-[var(--color-text-secondary)] mt-1">
          via {prompt.server_name} using {prompt.tool_name}
        </p>
      </div>

      {/* Behavioral context */}
      {prompt.context && (
        <div className="px-4 pt-1 pb-2">
          <p className="text-xs text-[var(--color-text-secondary)] italic">
            {prompt.context}
          </p>
        </div>
      )}

      {/* SLM Analysis (progressive disclosure) */}
      {(slmLoading || slmAnalysis) && (
        <div className="px-4 pb-2">
          {slmLoading && !slmAnalysis ? (
            <div
              className="flex items-center gap-2 text-xs text-[var(--color-text-secondary)] bg-[var(--color-bg-tertiary)] rounded px-2 py-1.5"
              role="status"
              aria-label="Loading AI analysis"
            >
              <span className="inline-block w-3 h-3 border-2 border-[var(--color-accent)] border-t-transparent rounded-full animate-spin" aria-hidden="true" />
              Analyzing with local AI...
            </div>
          ) : slmAnalysis ? (
            <div className="bg-[var(--color-info-light)] border border-[var(--color-info-border)] rounded px-2 py-1.5 space-y-1">
              <p className="text-xs text-[var(--color-accent)] font-medium flex items-center gap-1">
                <span className="inline-block w-1.5 h-1.5 rounded-full bg-[var(--color-accent)]" aria-hidden="true" />
                AI Analysis
              </p>
              <p className="text-xs text-[var(--color-text-primary)] break-words">{slmAnalysis.analysis}</p>
              {slmAnalysis.recommendation && (
                <p className="text-xs text-[var(--color-text-secondary)]">
                  Recommendation: {slmAnalysis.recommendation}
                </p>
              )}
            </div>
          ) : null}
        </div>
      )}

      {/* Timeout warning */}
      {remaining <= 5 && (
        <div className="px-4 pb-2">
          <p className="text-xs text-[var(--color-danger)] font-medium">
            I will block this in {remaining} seconds if you do not decide.
          </p>
        </div>
      )}

      {/* Collapsible details */}
      <div className="px-4 pb-2">
        <button
          onClick={() => setDetailsOpen(!detailsOpen)}
          className="text-xs text-[var(--color-accent)] hover:underline flex items-center gap-1"
          aria-expanded={detailsOpen}
        >
          <span className="inline-block transition-transform" style={{ transform: detailsOpen ? "rotate(90deg)" : "rotate(0deg)" }}>
            &#9654;
          </span>
          Details
        </button>
        {detailsOpen && (
          <div className="mt-2 space-y-1.5 text-xs bg-[var(--color-bg-tertiary)] rounded px-3 py-2">
            <div className="flex gap-2">
              <span className="text-[var(--color-text-secondary)] min-w-16 shrink-0">Resource</span>
              <span className="text-[var(--color-text-primary)] font-medium break-all">{prompt.resource}</span>
            </div>
            <div className="flex gap-2">
              <span className="text-[var(--color-text-secondary)] min-w-16 shrink-0">Tool</span>
              <span className="text-[var(--color-text-primary)] font-medium break-all">{prompt.tool_name}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[var(--color-text-secondary)] min-w-16 shrink-0">Risk</span>
              <span
                className="inline-block w-2 h-2 rounded-full"
                style={{ backgroundColor: riskColors[prompt.risk_level] }}
                aria-hidden="true"
              />
              <span className="font-semibold uppercase" style={{ color: riskColors[prompt.risk_level] }} role="status" aria-label={`Risk level: ${prompt.risk_level}`}>
                {prompt.risk_level}
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Action buttons */}
      <div className="px-4 pb-3 grid grid-cols-2 gap-2">
        <button
          onClick={() => respond("allow_once")}
          disabled={responding}
          aria-label="Allow this once (keyboard: A)"
          className="py-2 rounded-md text-xs font-medium bg-[var(--color-accent)] text-white hover:brightness-110 transition-all disabled:opacity-50"
        >
          Allow this once (A)
        </button>
        <button
          onClick={() => respond("allow_always")}
          disabled={responding}
          aria-label="Allow always (keyboard: Shift+A)"
          className="py-2 rounded-md text-xs font-medium bg-[var(--color-bg-tertiary)] text-[var(--color-text-primary)] hover:bg-[var(--color-border)] transition-all disabled:opacity-50"
        >
          Allow always (Shift+A)
        </button>
        <button
          onClick={() => respond("deny")}
          disabled={responding}
          aria-label="Block this once (keyboard: B)"
          className="py-2 rounded-md text-xs font-medium bg-[var(--color-bg-tertiary)] text-[var(--color-text-primary)] hover:bg-[var(--color-border)] transition-all disabled:opacity-50"
        >
          Block this once (B)
        </button>
        <button
          onClick={() => respond("deny_always")}
          disabled={responding}
          aria-label="Block always (keyboard: Shift+B)"
          className="py-2 rounded-md text-xs font-medium bg-[var(--color-bg-tertiary)] text-[var(--color-text-primary)] hover:bg-[var(--color-border)] transition-all disabled:opacity-50"
        >
          Block always (Shift+B)
        </button>
      </div>

      {/* Footer */}
      <div className="px-4 pb-3 flex items-center justify-between">
        <span className="text-xs text-[var(--color-text-secondary)]">
          Creates a permanent rule
        </span>
        {queueCount > 0 && (
          <span className="text-xs text-[var(--color-text-secondary)]">
            {queueCount} more pending
          </span>
        )}
      </div>
    </div>
  );
}
