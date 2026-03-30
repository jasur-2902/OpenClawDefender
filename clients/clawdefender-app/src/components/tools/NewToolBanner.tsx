import { useState, useCallback } from "react";
import { useToolStore } from "../../stores/toolStore";
import { CapabilityIcons } from "./CapabilityIcons";
import type { NewToolInfo } from "../../types";

interface NewToolBannerProps {
  newTools: NewToolInfo[];
}

export function NewToolBanner({ newTools }: NewToolBannerProps) {
  const protectTool = useToolStore((s) => s.protectTool);
  const dismissNewTool = useToolStore((s) => s.dismissNewTool);
  const [protecting, setProtecting] = useState<Set<string>>(new Set());
  const [dismissed, setDismissed] = useState(false);

  const handleProtect = useCallback(
    async (tool: NewToolInfo) => {
      setProtecting((prev) => new Set(prev).add(tool.server_name));
      await protectTool(tool.server_name, tool.client_name);
      setProtecting((prev) => {
        const next = new Set(prev);
        next.delete(tool.server_name);
        return next;
      });
    },
    [protectTool]
  );

  const handleProtectAll = useCallback(async () => {
    for (const tool of newTools) {
      setProtecting((prev) => new Set(prev).add(tool.server_name));
      await protectTool(tool.server_name, tool.client_name);
      setProtecting((prev) => {
        const next = new Set(prev);
        next.delete(tool.server_name);
        return next;
      });
    }
  }, [newTools, protectTool]);

  const handleDismiss = useCallback(async () => {
    for (const tool of newTools) {
      await dismissNewTool(tool.server_name);
    }
    setDismissed(true);
  }, [newTools, dismissNewTool]);

  if (dismissed || newTools.length === 0) return null;

  return (
    <div role="alert" aria-live="polite" className="rounded-lg border border-[var(--color-accent)] bg-[var(--color-accent-subtle)] p-4">
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2">
          <span aria-hidden="true"><NewToolIcon /></span>
          <p className="text-sm font-medium text-[var(--color-text-primary)]">
            I found {newTools.length} new AI tool{newTools.length !== 1 ? "s" : ""}. Want me to protect {newTools.length !== 1 ? "them" : "it"}?
          </p>
        </div>
        <button
          onClick={handleDismiss}
          aria-label="Dismiss new tool notifications"
          className="text-xs text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] rounded"
        >
          Dismiss
        </button>
      </div>

      <div className="space-y-2 mb-3">
        {newTools.map((tool) => (
          <div
            key={tool.server_name}
            className="flex items-center justify-between p-2 rounded-lg bg-[var(--color-bg-secondary)]"
          >
            <div className="flex items-center gap-3 min-w-0 flex-1">
              <div className="min-w-0">
                <p className="text-sm font-medium text-[var(--color-text-primary)] truncate" title={tool.server_name}>
                  {tool.server_name}
                </p>
                <p className="text-xs text-[var(--color-text-muted)] truncate">
                  {tool.client_display_name}
                </p>
              </div>
              {tool.capabilities && (
                <CapabilityIcons capabilities={tool.capabilities} size={12} />
              )}
            </div>
            <button
              onClick={() => handleProtect(tool)}
              disabled={protecting.has(tool.server_name)}
              aria-label={`Protect ${tool.server_name}`}
              className="px-3 py-1.5 rounded-md text-xs font-medium bg-[var(--color-accent)] text-white hover:bg-[var(--color-accent-hover)] disabled:opacity-40 transition-colors duration-100 shrink-0 ml-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-1"
            >
              {protecting.has(tool.server_name) ? "Protecting..." : "Protect"}
            </button>
          </div>
        ))}
      </div>

      {newTools.length > 1 && (
        <button
          onClick={handleProtectAll}
          disabled={protecting.size > 0}
          className="px-4 py-2 rounded-md text-xs font-medium bg-[var(--color-accent)] text-white hover:bg-[var(--color-accent-hover)] disabled:opacity-40 transition-colors duration-100"
        >
          Protect All
        </button>
      )}
    </div>
  );
}

function NewToolIcon() {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="var(--color-accent)"
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <line x1="12" y1="8" x2="12" y2="16" />
      <line x1="8" y1="12" x2="16" y2="12" />
    </svg>
  );
}
