import { useEffect, useCallback, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { PageHeader } from "../components/PageHeader";
import { ToolCard } from "../components/tools/ToolCard";
import { NewToolBanner } from "../components/tools/NewToolBanner";
import { useToolStore } from "../stores/toolStore";
import { useTauriEvent } from "../hooks/useTauriEvent";
import { EMPTY_STATES } from "../constants/messages";
import { useToastStore } from "../components/notifications/ToastContainer";
import type { NewToolInfo } from "../types";

const INITIAL_VISIBLE = 30;

const POLL_INTERVAL = 30_000;

export function MyTools() {
  const tools = useToolStore((s) => s.tools);
  const newTools = useToolStore((s) => s.newTools);
  const loading = useToolStore((s) => s.loading);
  const fetchTools = useToolStore((s) => s.fetchTools);
  const fetchNewTools = useToolStore((s) => s.fetchNewTools);

  // Initial fetch
  useEffect(() => {
    fetchTools();
    fetchNewTools();
  }, [fetchTools, fetchNewTools]);

  // Polling
  useEffect(() => {
    const interval = setInterval(() => {
      fetchTools();
    }, POLL_INTERVAL);
    return () => clearInterval(interval);
  }, [fetchTools]);

  // Listen for new tool events
  const handleNewTool = useCallback(() => {
    fetchNewTools();
    fetchTools();
  }, [fetchNewTools, fetchTools]);

  useTauriEvent<NewToolInfo>("clawdefender://new-tool-detected", handleNewTool);

  // Separate wrapped and unwrapped
  const wrappedTools = useMemo(
    () => tools.filter((t) => t.is_wrapped),
    [tools]
  );
  const unwrappedTools = useMemo(
    () => tools.filter((t) => !t.is_wrapped),
    [tools]
  );

  const addToast = useToastStore((s) => s.addToast);

  const handleScan = useCallback(async () => {
    try {
      await invoke("start_scan", {
        serverCommand: "system-scan",
        modules: [],
        timeout: 300,
      });
    } catch {
      addToast({
        title: "Could not start the scan. Check that the daemon is running.",
        severity: "warning",
      });
    }
  }, [addToast]);

  const isEmpty = !loading && tools.length === 0;

  // Progressive rendering for large tool lists (100+)
  const [wrappedVisible, setWrappedVisible] = useState(INITIAL_VISIBLE);
  const [unwrappedVisible, setUnwrappedVisible] = useState(INITIAL_VISIBLE);

  // Reset visibility when tools change
  useEffect(() => {
    setWrappedVisible(INITIAL_VISIBLE);
    setUnwrappedVisible(INITIAL_VISIBLE);
  }, [tools.length]);

  return (
    <div className="p-6 space-y-6 max-w-5xl">
      <PageHeader
        title="My Tools"
        subtitle="Manage your AI tools and their permissions"
        actions={
          tools.length > 0 ? (
            <button
              onClick={handleScan}
              className="px-3 py-1.5 rounded-md text-xs font-medium bg-[var(--color-bg-tertiary)] text-[var(--color-text-primary)] border border-[var(--color-border)] hover:bg-[var(--color-bg-sunken)] transition-colors duration-100"
            >
              Scan all tools
            </button>
          ) : undefined
        }
      />

      {/* New tool banner */}
      {newTools.length > 0 && <NewToolBanner newTools={newTools} />}

      {/* Loading skeleton */}
      {loading && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {[1, 2, 3, 4, 5, 6].map((i) => (
            <ToolCardSkeleton key={i} />
          ))}
        </div>
      )}

      {/* Empty state */}
      {isEmpty && (
        <div className="flex flex-col items-center justify-center py-16 text-center">
          <EmptyToolsIcon />
          <h2 className="text-base font-medium text-[var(--color-text-primary)] mt-4 mb-1">
            {EMPTY_STATES.myTools.headline}
          </h2>
          <p className="text-sm text-[var(--color-text-secondary)] max-w-sm">
            I don't see any AI tools installed. I support Claude Desktop, Cursor, VS Code, and Windsurf.
          </p>
          <button
            onClick={handleScan}
            className="mt-4 px-4 py-2 rounded-md text-sm font-medium bg-[var(--color-accent)] text-white hover:bg-[var(--color-accent-hover)] transition-colors duration-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-1"
          >
            {EMPTY_STATES.myTools.cta}
          </button>
        </div>
      )}

      {/* Wrapped tools grid */}
      {!loading && wrappedTools.length > 0 && (
        <section aria-label="Protected tools">
          <div role="list" className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {wrappedTools.slice(0, wrappedVisible).map((tool) => (
              <div role="listitem" key={`${tool.client_name}:${tool.server_name}`}>
                <ToolCard tool={tool} />
              </div>
            ))}
          </div>
          {wrappedTools.length > wrappedVisible && (
            <button
              onClick={() => setWrappedVisible((v) => v + INITIAL_VISIBLE)}
              className="mt-4 w-full py-2 text-sm text-[var(--color-accent)] hover:text-[var(--color-accent-hover)] border border-[var(--color-border)] rounded-lg hover:bg-[var(--color-bg-secondary)] transition-colors"
            >
              Show more ({wrappedTools.length - wrappedVisible} remaining)
            </button>
          )}
        </section>
      )}

      {/* Unwrapped tools */}
      {!loading && unwrappedTools.length > 0 && (
        <section aria-label="Unprotected tools">
          <h2 className="text-xs font-semibold text-[var(--color-text-muted)] uppercase tracking-wide mb-3">
            Not Protected ({unwrappedTools.length})
          </h2>
          <div role="list" className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {unwrappedTools.slice(0, unwrappedVisible).map((tool) => (
              <div role="listitem" key={`${tool.client_name}:${tool.server_name}`}>
                <ToolCard tool={tool} />
              </div>
            ))}
          </div>
          {unwrappedTools.length > unwrappedVisible && (
            <button
              onClick={() => setUnwrappedVisible((v) => v + INITIAL_VISIBLE)}
              className="mt-4 w-full py-2 text-sm text-[var(--color-accent)] hover:text-[var(--color-accent-hover)] border border-[var(--color-border)] rounded-lg hover:bg-[var(--color-bg-secondary)] transition-colors"
            >
              Show more ({unwrappedTools.length - unwrappedVisible} remaining)
            </button>
          )}
        </section>
      )}
    </div>
  );
}

function ToolCardSkeleton() {
  return (
    <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4 space-y-3">
      <div className="flex items-center justify-between">
        <div className="h-4 w-32 rounded bg-[var(--color-bg-tertiary)] animate-pulse" />
        <div className="h-5 w-16 rounded-full bg-[var(--color-bg-tertiary)] animate-pulse" />
      </div>
      <div className="h-3 w-20 rounded bg-[var(--color-bg-tertiary)] animate-pulse" />
      <div className="flex gap-1.5">
        {[1, 2, 3, 4, 5].map((i) => (
          <div key={i} className="h-3.5 w-3.5 rounded bg-[var(--color-bg-tertiary)] animate-pulse" />
        ))}
      </div>
      <div className="h-3 w-40 rounded bg-[var(--color-bg-tertiary)] animate-pulse" />
    </div>
  );
}

function EmptyToolsIcon() {
  return (
    <svg
      width="48"
      height="48"
      viewBox="0 0 24 24"
      fill="none"
      stroke="var(--color-text-muted)"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />
    </svg>
  );
}
