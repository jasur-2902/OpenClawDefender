import { useState, useEffect, useCallback } from "react";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";

interface GuidanceMilestone {
  id: string;
  title: string;
  message: string;
  delivery: string;
  delivery_meta: Record<string, string> | null;
}

interface GuidanceEvent {
  milestone: GuidanceMilestone;
}

interface GuidanceToastData {
  id: string;
  milestone: GuidanceMilestone;
}

export function GuidanceToastContainer() {
  const [toasts, setToasts] = useState<GuidanceToastData[]>([]);

  useEffect(() => {
    const unlisten = listen<GuidanceEvent>(
      "rookbot://guidance-toast",
      (event) => {
        const { milestone } = event.payload;
        setToasts((prev) => [...prev.slice(-2), { id: milestone.id, milestone }]);
      }
    );

    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

  const dismiss = useCallback((milestoneId: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== milestoneId));
    invoke("dismiss_guidance", { milestoneId }).catch(() => {});
  }, []);

  if (toasts.length === 0) return null;

  return (
    <div
      className="fixed top-16 right-4 space-y-2"
      style={{ zIndex: "var(--z-toast)" }}
      role="region"
      aria-label="Guidance notifications"
      aria-live="polite"
    >
      {toasts.map((t) => (
        <GuidanceToast key={t.id} data={t} onDismiss={dismiss} />
      ))}
    </div>
  );
}

function GuidanceToast({
  data,
  onDismiss,
}: {
  data: GuidanceToastData;
  onDismiss: (id: string) => void;
}) {
  const [visible, setVisible] = useState(false);
  const [exiting, setExiting] = useState(false);

  const dismiss = useCallback(() => {
    setExiting(true);
    setTimeout(() => onDismiss(data.id), 300);
  }, [onDismiss, data.id]);

  useEffect(() => {
    requestAnimationFrame(() => setVisible(true));

    // Auto-dismiss after 10 seconds (longer than regular toasts)
    const timer = setTimeout(() => dismiss(), 10000);
    return () => clearTimeout(timer);
  }, [dismiss]);

  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") dismiss();
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [dismiss]);

  return (
    <div
      role="status"
      aria-live="polite"
      aria-label={data.milestone.title}
      className="w-80 border rounded-lg overflow-hidden"
      style={{
        backgroundColor: "var(--color-bg-secondary)",
        borderColor: "var(--color-info-border)",
        boxShadow: "var(--shadow-toast)",
        transform: visible && !exiting ? "translateX(0)" : "translateX(120%)",
        opacity: visible && !exiting ? 1 : 0,
        transition: exiting
          ? "transform 300ms var(--ease-out), opacity 300ms var(--ease-out)"
          : "transform 200ms var(--ease-out), opacity 200ms var(--ease-out)",
      }}
    >
      {/* Accent bar at top */}
      <div
        className="h-0.5"
        style={{ background: "linear-gradient(90deg, var(--color-accent), var(--color-info))" }}
      />
      <div className="flex items-start gap-2.5 px-3 py-3">
        {/* Claw icon */}
        <span
          className="shrink-0 text-sm mt-0.5 font-semibold"
          style={{ color: "var(--color-accent)" }}
          aria-hidden="true"
        >
          C
        </span>
        <div className="flex-1 min-w-0">
          <p
            className="text-xs font-medium leading-snug mb-1"
            style={{ color: "var(--color-text-primary)" }}
          >
            {data.milestone.title}
          </p>
          <p
            className="text-xs leading-relaxed"
            style={{ color: "var(--color-text-secondary)" }}
          >
            {data.milestone.message}
          </p>
          <button
            onClick={(e) => {
              e.stopPropagation();
              dismiss();
            }}
            className="mt-2 text-xs font-medium hover:underline"
            style={{ color: "var(--color-accent)" }}
          >
            Got it
          </button>
        </div>
      </div>
    </div>
  );
}
