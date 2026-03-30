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

interface CriticalPromptProps {
  prompt: PendingPrompt;
  queueCount: number;
}

const CRITICAL_TIMEOUT = 15;

export function CriticalPrompt({ prompt, queueCount }: CriticalPromptProps) {
  const removePrompt = useEventStore((s) => s.removePrompt);
  const addToast = useToastStore((s) => s.addToast);
  const timeout = Math.min(prompt.timeout_seconds, CRITICAL_TIMEOUT);
  const [remaining, setRemaining] = useState(timeout);
  const [responding, setResponding] = useState(false);
  const [detailsOpen, setDetailsOpen] = useState(true);
  const [confirmingAllow, setConfirmingAllow] = useState<"allow_once" | "allow_always" | null>(null);
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
    if (slmAnalysis) return;
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
      const left = timeout - elapsed;
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
  }, [timeout, respond, addToast]);

  // Keyboard shortcuts
  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;
      const key = e.key.toLowerCase();

      if (confirmingAllow) {
        if (key === "y") {
          e.preventDefault();
          respond(confirmingAllow);
          setConfirmingAllow(null);
        } else if (key === "n" || key === "escape") {
          e.preventDefault();
          setConfirmingAllow(null);
        }
        return;
      }

      if (key === "a" && e.shiftKey) {
        e.preventDefault();
        setConfirmingAllow("allow_always");
      } else if (key === "a") {
        e.preventDefault();
        setConfirmingAllow("allow_once");
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
  }, [respond, confirmingAllow]);

  const timerPercent = (remaining / timeout) * 100;
  const timerColor =
    remaining <= 5
      ? "var(--color-danger)"
      : remaining <= 10
        ? "var(--color-warning)"
        : "var(--color-danger)";

  const humanAction = prompt.action.replace(/_/g, " ").replace(/\//g, " ");
  const serverDisplay = prompt.server_name
    .replace(/^mcp-server-/, "")
    .replace(/^mcp-/, "")
    .replace(/-/g, " ");

  return (
    <div
      role="alertdialog"
      aria-labelledby="prompt-title"
      aria-describedby="prompt-recommendation"
      className="flex flex-col w-full max-w-md mx-auto bg-[var(--color-bg-secondary)] border-l-4 border border-[var(--color-danger)] rounded-lg shadow-2xl overflow-hidden"
    >
      {/* Timer bar */}
      <div className="h-1.5 bg-[var(--color-bg-tertiary)]">
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
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-[var(--color-danger)] text-white text-xs font-bold shrink-0" aria-hidden="true">
              !
            </span>
            <h2 id="prompt-title" className="text-sm font-bold text-[var(--color-text-primary)]">
              {serverDisplay} is trying to {humanAction}
            </h2>
          </div>
          <span
            className="text-xs font-mono text-[var(--color-danger)] font-bold"
            aria-live="polite"
            aria-label={`${remaining} seconds remaining`}
          >
            {remaining}s
          </span>
        </div>
        <p className="text-xs text-[var(--color-text-secondary)] mt-1 ml-8">
          via {prompt.server_name} using {prompt.tool_name}
        </p>
      </div>

      {/* Recommendation callout */}
      <div className="mx-4 mt-3 mb-2 px-3 py-2.5 rounded-md bg-[var(--color-danger-subtle)] border border-[var(--color-danger-border)]">
        <p id="prompt-recommendation" className="text-xs font-semibold text-[var(--color-danger)] flex items-center gap-2">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="shrink-0" aria-hidden="true">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          I recommend blocking this.
        </p>
        {prompt.context && (
          <p className="text-xs text-[var(--color-text-secondary)] mt-1 ml-5">
            {prompt.context}
          </p>
        )}
      </div>

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

      {/* Risk details (expanded by default for critical) */}
      <div className="px-4 pb-2">
        <button
          onClick={() => setDetailsOpen(!detailsOpen)}
          className="text-xs text-[var(--color-accent)] hover:underline flex items-center gap-1"
          aria-expanded={detailsOpen}
        >
          <span className="inline-block transition-transform" style={{ transform: detailsOpen ? "rotate(90deg)" : "rotate(0deg)" }}>
            &#9654;
          </span>
          Risk details
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
              <span className="inline-block w-2 h-2 rounded-full bg-[var(--color-danger)]" aria-hidden="true" />
              <span className="font-semibold uppercase text-[var(--color-danger)]" role="status" aria-label={`Risk level: ${prompt.risk_level}`}>
                {prompt.risk_level}
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Confirmation dialog for allow actions */}
      {confirmingAllow && (
        <div className="mx-4 mb-2 px-3 py-2.5 rounded-md bg-[var(--color-danger-subtle)] border border-[var(--color-danger-border)]">
          <p className="text-xs font-medium text-[var(--color-danger)] mb-2">
            {PROMPT_CONFIRMATION.highRiskConfirm}
          </p>
          <div className="flex gap-2">
            <button
              onClick={() => {
                respond(confirmingAllow);
                setConfirmingAllow(null);
              }}
              disabled={responding}
              className="flex-1 py-1.5 rounded text-xs font-medium bg-[var(--color-warning)] text-white hover:brightness-110 transition-all disabled:opacity-50"
            >
              Yes, allow (Y)
            </button>
            <button
              onClick={() => setConfirmingAllow(null)}
              disabled={responding}
              className="flex-1 py-1.5 rounded text-xs font-medium bg-[var(--color-bg-tertiary)] text-[var(--color-text-primary)] hover:bg-[var(--color-border)] transition-all disabled:opacity-50"
            >
              No, block it (N)
            </button>
          </div>
        </div>
      )}

      {/* Action buttons - Block is primary for critical */}
      {!confirmingAllow && (
        <div className="px-4 pb-3 grid grid-cols-2 gap-2">
          <button
            onClick={() => respond("deny")}
            disabled={responding}
            autoFocus
            aria-label="Block this once (keyboard: B)"
            className="py-2.5 rounded-md text-xs font-bold bg-[var(--color-danger)] text-white hover:brightness-110 transition-all disabled:opacity-50"
          >
            Block this once (B)
          </button>
          <button
            onClick={() => respond("deny_always")}
            disabled={responding}
            aria-label="Block always (keyboard: Shift+B)"
            className="py-2.5 rounded-md text-xs font-medium bg-[var(--color-bg-tertiary)] text-[var(--color-text-primary)] hover:bg-[var(--color-border)] transition-all disabled:opacity-50"
          >
            Block always (Shift+B)
          </button>
          <button
            onClick={() => setConfirmingAllow("allow_once")}
            disabled={responding}
            aria-label="Allow this once (keyboard: A)"
            className="py-2 rounded-md text-xs font-medium bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] hover:bg-[var(--color-border)] transition-all disabled:opacity-50"
          >
            Allow this once (A)
          </button>
          <button
            onClick={() => setConfirmingAllow("allow_always")}
            disabled={responding}
            aria-label="Allow always (keyboard: Shift+A)"
            className="py-2 rounded-md text-xs font-medium bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] hover:bg-[var(--color-border)] transition-all disabled:opacity-50"
          >
            Allow always (Shift+A)
          </button>
        </div>
      )}

      {/* Footer */}
      {queueCount > 0 && (
        <div className="px-4 py-2 border-t border-[var(--color-border)] text-center text-xs text-[var(--color-text-secondary)]">
          {queueCount} more pending
        </div>
      )}
    </div>
  );
}
