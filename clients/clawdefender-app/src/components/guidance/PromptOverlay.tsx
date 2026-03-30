import { useState, useEffect, useCallback, useRef } from "react";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";

interface GuidanceMilestone {
  id: string;
  title: string;
  message: string;
}

interface GuidanceEvent {
  milestone: GuidanceMilestone;
}

export function PromptOverlay() {
  const [milestone, setMilestone] = useState<GuidanceMilestone | null>(null);
  const [visible, setVisible] = useState(false);
  const gotItRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const unlisten = listen<GuidanceEvent>(
      "clawdefender://guidance-overlay",
      (event) => {
        setMilestone(event.payload.milestone);
        requestAnimationFrame(() => {
          setVisible(true);
          // Focus the "Got it" button after overlay appears
          setTimeout(() => gotItRef.current?.focus(), 100);
        });
      }
    );

    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

  const dismiss = useCallback(() => {
    setVisible(false);
    setTimeout(() => {
      if (milestone) {
        invoke("dismiss_guidance", { milestoneId: milestone.id }).catch(() => {});
      }
      setMilestone(null);
    }, 200);
  }, [milestone]);

  // Dismiss on Escape
  useEffect(() => {
    if (!milestone) return;

    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") dismiss();
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [milestone, dismiss]);

  if (!milestone) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={milestone.title}
      className="fixed inset-0"
      style={{
        zIndex: "var(--z-overlay)",
        backgroundColor: visible ? "rgba(0, 0, 0, 0.4)" : "transparent",
        transition: "background-color var(--duration-moderate) var(--ease-out)",
        pointerEvents: visible ? "auto" : "none",
      }}
      onClick={dismiss}
    >
      {/* Callout bubble */}
      <div
        className="absolute bottom-24 left-1/2 w-80 rounded-lg border p-4"
        style={{
          transform: visible
            ? "translateX(-50%) translateY(0)"
            : "translateX(-50%) translateY(16px)",
          opacity: visible ? 1 : 0,
          transition: `transform var(--duration-moderate) var(--ease-out), opacity var(--duration-moderate) var(--ease-out)`,
          backgroundColor: "var(--color-bg-secondary)",
          borderColor: "var(--color-accent)",
          boxShadow: "var(--shadow-dropdown)",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Accent bar */}
        <div
          className="absolute top-0 left-0 right-0 h-0.5 rounded-t-lg"
          style={{
            background: "linear-gradient(90deg, var(--color-accent), var(--color-info))",
          }}
        />
        <div className="flex items-start gap-2.5">
          <span
            className="shrink-0 text-sm font-semibold"
            style={{ color: "var(--color-accent)" }}
            aria-hidden="true"
          >
            C
          </span>
          <div className="flex-1">
            <p
              className="text-sm font-medium mb-1.5"
              style={{ color: "var(--color-text-primary)" }}
            >
              {milestone.title}
            </p>
            <p
              className="text-xs leading-relaxed"
              style={{ color: "var(--color-text-secondary)" }}
            >
              {milestone.message}
            </p>
            <button
              ref={gotItRef}
              onClick={dismiss}
              className="mt-3 text-xs font-medium px-3 py-1.5 rounded-md focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--color-accent)]"
              style={{
                backgroundColor: "var(--color-accent-subtle)",
                color: "var(--color-accent)",
              }}
            >
              Got it
            </button>
          </div>
        </div>
        {/* Arrow pointing down toward prompt buttons */}
        <div
          className="absolute -bottom-1.5 left-1/2 w-3 h-3 rotate-45"
          style={{
            transform: "translateX(-50%) rotate(45deg)",
            backgroundColor: "var(--color-bg-secondary)",
            borderRight: "1px solid var(--color-accent)",
            borderBottom: "1px solid var(--color-accent)",
          }}
        />
      </div>
    </div>
  );
}
