import { useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { truncateEnd } from "../../utils/textUtils";

interface InlineHintProps {
  milestoneId: string;
  message: string;
  actionLabel?: string;
  actionRoute?: string;
}

export function InlineHint({
  milestoneId,
  message,
  actionLabel,
  actionRoute,
}: InlineHintProps) {
  const [expanded, setExpanded] = useState(false);
  const [dismissed, setDismissed] = useState(false);

  const handleDismiss = useCallback(() => {
    setDismissed(true);
    invoke("dismiss_guidance", { milestoneId }).catch(() => {});
  }, [milestoneId]);

  if (dismissed) return null;

  // Truncate message for collapsed view (Unicode-safe)
  const teaser = truncateEnd(message, 60);

  return (
    <div
      role="note"
      aria-label="Guidance tip"
      className="rounded-lg border overflow-hidden"
      style={{
        backgroundColor: "var(--color-info-subtle)",
        borderColor: "var(--color-info-border)",
        transition: "all var(--duration-normal) var(--ease-out)",
      }}
    >
      <div className="flex items-start gap-2 px-3 py-2.5">
        {/* Claw icon */}
        <span
          className="shrink-0 text-xs mt-0.5 font-semibold"
          style={{ color: "var(--color-accent)" }}
          aria-hidden="true"
        >
          C
        </span>
        <div className="flex-1 min-w-0">
          {expanded ? (
            <>
              <p
                className="text-xs leading-relaxed"
                style={{ color: "var(--color-text-primary)" }}
              >
                {message}
              </p>
              {actionLabel && actionRoute && (
                <a
                  href={`#${actionRoute}`}
                  className="inline-block mt-1.5 text-xs font-medium hover:underline"
                  style={{ color: "var(--color-accent)" }}
                >
                  {actionLabel}
                </a>
              )}
            </>
          ) : (
            <button
              onClick={() => setExpanded(true)}
              className="text-xs leading-relaxed text-left w-full"
              style={{ color: "var(--color-text-secondary)" }}
            >
              {teaser}
            </button>
          )}
        </div>
        <button
          onClick={handleDismiss}
          className="shrink-0 text-xs p-0.5 rounded hover:bg-[var(--color-bg-tertiary)]"
          style={{ color: "var(--color-text-muted)" }}
          aria-label="Dismiss tip"
        >
          &times;
        </button>
      </div>
    </div>
  );
}
