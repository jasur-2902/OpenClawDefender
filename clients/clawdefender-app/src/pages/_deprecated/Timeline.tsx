import {
  useEffect,
  useState,
  useCallback,
  useRef,
  useMemo,
} from "react";
import { useLocation } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { useEventStore } from "../stores/eventStore";
import { useTauriEvent } from "../hooks/useTauriEvent";
import type { AuditEvent } from "../types";

const ROW_HEIGHT = 48;
const BUFFER_ROWS = 10;

function formatTimestamp(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return ts;
  }
}

const serverColors = [
  "#3b82f6",
  "#8b5cf6",
  "#06b6d4",
  "#f59e0b",
  "#ec4899",
  "#10b981",
  "#f97316",
  "#6366f1",
];

function getServerColor(name: string): string {
  let hash = 0;
  for (let i = 0; i < name.length; i++) {
    hash = name.charCodeAt(i) + ((hash << 5) - hash);
  }
  return serverColors[Math.abs(hash) % serverColors.length];
}

/** Normalize backend decision values to canonical form: "allowed", "blocked", "prompted". */
function normalizeDecision(d: string): string {
  const lower = d.toLowerCase();
  if (lower === "allowed" || lower === "allow") return "allowed";
  if (lower === "blocked" || lower === "block" || lower === "denied" || lower === "deny")
    return "blocked";
  if (lower === "prompted" || lower === "prompt") return "prompted";
  return lower;
}

/** Normalize backend risk_level to one of: "low", "medium", "high", "critical". */
function normalizeRiskLevel(r: string): string {
  const lower = r.toLowerCase();
  if (lower === "info") return "low";
  if (lower === "block" || lower === "review") return "medium";
  if (lower === "low" || lower === "medium" || lower === "high" || lower === "critical")
    return lower;
  return "low";
}

function truncateResource(resource: string | null, maxLen = 40): string {
  if (!resource) return "";
  if (resource.length <= maxLen) return resource;
  // For file paths, show .../<last-two-segments>
  if (resource.includes("/")) {
    const parts = resource.split("/");
    if (parts.length > 2) {
      const tail = parts.slice(-2).join("/");
      if (tail.length <= maxLen - 4) return ".../" + tail;
    }
  }
  return resource.slice(0, maxLen - 3) + "...";
}

function eventTypeIcon(eventType: string): string {
  switch (eventType.toLowerCase()) {
    case "tool_call":
      return "\u2699";
    case "resource_access":
      return "\u2192";
    case "connection":
      return "\u2194";
    case "error":
      return "\u26A0";
    default:
      return "\u25CF";
  }
}

function DecisionBadge({ decision }: { decision: string }) {
  const d = normalizeDecision(decision);
  const config: Record<string, { label: string; bg: string; color: string }> = {
    allowed: {
      label: "Allowed",
      bg: "rgba(34,197,94,0.15)",
      color: "var(--color-success)",
    },
    blocked: {
      label: "Blocked",
      bg: "rgba(239,68,68,0.15)",
      color: "var(--color-danger)",
    },
    prompted: {
      label: "Prompted",
      bg: "rgba(245,158,11,0.15)",
      color: "var(--color-warning)",
    },
  };
  const c = config[d];
  if (c) {
    return (
      <span
        className="text-xs px-2 py-0.5 rounded-full"
        style={{ backgroundColor: c.bg, color: c.color }}
      >
        {c.label}
      </span>
    );
  }
  return (
    <span className="text-xs px-2 py-0.5 rounded-full bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)]">
      {decision}
    </span>
  );
}

function RiskBadge({ level }: { level: string }) {
  const normalized = normalizeRiskLevel(level);
  const colors: Record<string, string> = {
    critical: "var(--color-danger)",
    high: "var(--color-danger)",
    medium: "var(--color-warning)",
    low: "var(--color-text-secondary)",
  };
  const color = colors[normalized] ?? "var(--color-text-secondary)";
  return (
    <span
      className="text-xs px-1.5 py-0.5 rounded"
      style={{ color, borderColor: color, border: "1px solid" }}
    >
      {normalized}
    </span>
  );
}

function extractSlmAnalysis(details: string): string | null {
  try {
    const parsed = JSON.parse(details);
    // slm_analysis is a structured record with risk_level, explanation, etc.
    const slm = parsed.slm_analysis ?? parsed.analysis;
    if (!slm) return null;
    // If it's a string, return directly; if it's an object, format the key fields.
    if (typeof slm === "string") return slm;
    if (typeof slm === "object") {
      const parts: string[] = [];
      if (slm.risk_level) parts.push(`Risk: ${slm.risk_level}`);
      if (slm.explanation) parts.push(slm.explanation);
      if (slm.confidence != null) parts.push(`Confidence: ${(slm.confidence * 100).toFixed(0)}%`);
      return parts.join("\n") || null;
    }
  } catch {
    // Not JSON or no analysis field
  }
  return null;
}

function SlmAnalysisSection({ details }: { details: string }) {
  const analysis = extractSlmAnalysis(details);
  if (!analysis) return null;
  return (
    <div className="mt-4">
      <p className="text-xs text-[var(--color-text-secondary)] mb-1 flex items-center gap-1.5">
        <span className="inline-block w-2 h-2 rounded-full bg-[var(--color-accent)]" />
        SLM Analysis
      </p>
      <div className="text-xs text-[var(--color-text-primary)] bg-[rgba(59,130,246,0.08)] border border-[rgba(59,130,246,0.2)] rounded-lg p-3 whitespace-pre-wrap break-words">
        {analysis}
      </div>
    </div>
  );
}

function EventDetailPanel({
  event,
  onClose,
}: {
  event: AuditEvent;
  onClose: () => void;
}) {
  return (
    <div className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-xl p-5 mb-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-[var(--color-text-primary)]">
          Event Details
        </h3>
        <button
          onClick={onClose}
          className="text-xs text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors px-2 py-1 rounded hover:bg-[var(--color-bg-tertiary)]"
        >
          Close
        </button>
      </div>

      <div className="grid grid-cols-2 gap-4 mb-4">
        <div>
          <p className="text-xs text-[var(--color-text-secondary)] mb-1">
            Event ID
          </p>
          <p className="text-sm font-mono text-[var(--color-text-primary)]">
            {event.id}
          </p>
        </div>
        <div>
          <p className="text-xs text-[var(--color-text-secondary)] mb-1">
            Timestamp
          </p>
          <p className="text-sm text-[var(--color-text-primary)]">
            {new Date(event.timestamp).toLocaleString()}
          </p>
        </div>
        <div>
          <p className="text-xs text-[var(--color-text-secondary)] mb-1">
            Server
          </p>
          <p className="text-sm text-[var(--color-text-primary)]">
            {event.server_name}
          </p>
        </div>
        <div>
          <p className="text-xs text-[var(--color-text-secondary)] mb-1">
            Event Type
          </p>
          <p className="text-sm text-[var(--color-text-primary)]">
            {event.event_type}
          </p>
        </div>
        <div>
          <p className="text-xs text-[var(--color-text-secondary)] mb-1">
            Tool
          </p>
          <p className="text-sm text-[var(--color-text-primary)]">
            {event.tool_name ?? "N/A"}
          </p>
        </div>
        <div>
          <p className="text-xs text-[var(--color-text-secondary)] mb-1">
            Action
          </p>
          <p className="text-sm text-[var(--color-text-primary)]">
            {event.action}
          </p>
        </div>
        <div>
          <p className="text-xs text-[var(--color-text-secondary)] mb-1">
            Decision
          </p>
          <DecisionBadge decision={event.decision} />
        </div>
        <div>
          <p className="text-xs text-[var(--color-text-secondary)] mb-1">
            Risk Level
          </p>
          <RiskBadge level={event.risk_level} />
        </div>
      </div>

      {event.resource && (
        <div className="mb-4">
          <p className="text-xs text-[var(--color-text-secondary)] mb-1">
            Resource
          </p>
          <p className="text-sm font-mono text-[var(--color-text-primary)] break-all">
            {event.resource}
          </p>
        </div>
      )}

      <div>
        <p className="text-xs text-[var(--color-text-secondary)] mb-1">
          Details
        </p>
        <pre className="text-xs font-mono text-[var(--color-text-primary)] bg-[var(--color-bg-primary)] rounded-lg p-3 overflow-x-auto whitespace-pre-wrap break-all">
          {tryFormatJson(event.details)}
        </pre>
      </div>

      <SlmAnalysisSection details={event.details} />
    </div>
  );
}

function tryFormatJson(str: string): string {
  try {
    return JSON.stringify(JSON.parse(str), null, 2);
  } catch {
    return str;
  }
}

export function Timeline() {
  const location = useLocation();
  const navState = location.state as { filterMessage?: string } | null;

  const events = useEventStore((s) => s.events);
  const setEvents = useEventStore((s) => s.setEvents);
  const addEvent = useEventStore((s) => s.addEvent);

  const [searchText, setSearchText] = useState(navState?.filterMessage ?? "");
  const [serverFilter, setServerFilter] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<string[]>([]);
  const [onlyBlocks, setOnlyBlocks] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const [isLive, setIsLive] = useState(true);

  const scrollContainerRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [containerHeight, setContainerHeight] = useState(0);

  useEffect(() => {
    invoke<AuditEvent[]>("get_recent_events")
      .then((evts) => setEvents(evts))
      .catch(() => {});
  }, [setEvents]);

  const handleNewEvent = useCallback(
    (payload: AuditEvent) => {
      addEvent(payload);
      setIsLive(true);
    },
    [addEvent]
  );

  useTauriEvent<AuditEvent>("clawdefender://event", handleNewEvent);

  const serverNames = useMemo(() => {
    const names = new Set<string>();
    for (const e of events) names.add(e.server_name);
    return Array.from(names).sort();
  }, [events]);

  const filteredEvents = useMemo(() => {
    let result = events;

    if (searchText) {
      const lower = searchText.toLowerCase();
      result = result.filter(
        (e) =>
          e.server_name.toLowerCase().includes(lower) ||
          (e.tool_name?.toLowerCase().includes(lower) ?? false) ||
          e.event_type.toLowerCase().includes(lower) ||
          e.details.toLowerCase().includes(lower) ||
          e.action.toLowerCase().includes(lower)
      );
    }

    if (serverFilter) {
      result = result.filter((e) => e.server_name === serverFilter);
    }

    if (statusFilter.length > 0) {
      result = result.filter((e) =>
        statusFilter.includes(normalizeDecision(e.decision))
      );
    }

    if (onlyBlocks) {
      result = result.filter(
        (e) => normalizeDecision(e.decision) === "blocked"
      );
    }

    return result;
  }, [events, searchText, serverFilter, statusFilter, onlyBlocks]);

  const totalHeight = filteredEvents.length * ROW_HEIGHT;
  const startIndex = Math.max(
    0,
    Math.floor(scrollTop / ROW_HEIGHT) - BUFFER_ROWS
  );
  const endIndex = Math.min(
    filteredEvents.length,
    Math.ceil((scrollTop + containerHeight) / ROW_HEIGHT) + BUFFER_ROWS
  );
  const visibleEvents = filteredEvents.slice(startIndex, endIndex);

  useEffect(() => {
    const container = scrollContainerRef.current;
    if (!container) return;

    const resizeObs = new ResizeObserver((entries) => {
      for (const entry of entries) {
        setContainerHeight(entry.contentRect.height);
      }
    });
    resizeObs.observe(container);
    return () => resizeObs.disconnect();
  }, []);

  const handleScroll = useCallback(() => {
    const container = scrollContainerRef.current;
    if (!container) return;
    setScrollTop(container.scrollTop);

    const isAtTop = container.scrollTop < ROW_HEIGHT;
    setAutoScroll(isAtTop);
  }, []);

  useEffect(() => {
    if (autoScroll && scrollContainerRef.current) {
      scrollContainerRef.current.scrollTop = 0;
    }
  }, [events.length, autoScroll]);

  const toggleStatusFilter = (status: string) => {
    setStatusFilter((prev) =>
      prev.includes(status)
        ? prev.filter((s) => s !== status)
        : [...prev, status]
    );
  };

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-[var(--color-border)]">
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-bold text-[var(--color-text-primary)]">
            Event Timeline
          </h1>
          {isLive && (
            <span className="flex items-center gap-1.5 text-xs text-[var(--color-success)]">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[var(--color-success)] opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-[var(--color-success)]" />
              </span>
              Live
            </span>
          )}
        </div>
        <span className="text-xs text-[var(--color-text-secondary)]">
          {filteredEvents.length} events
          {filteredEvents.length !== events.length &&
            ` (${events.length} total)`}
        </span>
      </div>

      {/* Filter Bar */}
      <div className="flex items-center gap-3 px-6 py-3 border-b border-[var(--color-border)] bg-[var(--color-bg-secondary)]">
        <input
          type="text"
          placeholder="Search events..."
          aria-label="Search events"
          value={searchText}
          onChange={(e) => setSearchText(e.target.value)}
          className="flex-1 max-w-xs bg-[var(--color-bg-primary)] border border-[var(--color-border)] rounded-lg px-3 py-1.5 text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-secondary)] focus:outline-none focus:border-[var(--color-accent)]"
        />

        <select
          value={serverFilter}
          onChange={(e) => setServerFilter(e.target.value)}
          aria-label="Filter by server"
          className="bg-[var(--color-bg-primary)] border border-[var(--color-border)] rounded-lg px-3 py-1.5 text-sm text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
        >
          <option value="">All Servers</option>
          {serverNames.map((name) => (
            <option key={name} value={name}>
              {name}
            </option>
          ))}
        </select>

        <div className="flex items-center gap-1" role="group" aria-label="Filter by decision">
          {["allowed", "blocked", "prompted"].map((status) => (
            <button
              key={status}
              onClick={() => toggleStatusFilter(status)}
              aria-pressed={statusFilter.includes(status)}
              className={`text-xs px-2.5 py-1 rounded-full border transition-colors ${
                statusFilter.includes(status)
                  ? "border-[var(--color-accent)] bg-[rgba(59,130,246,0.15)] text-[var(--color-accent)]"
                  : "border-[var(--color-border)] text-[var(--color-text-secondary)] hover:border-[var(--color-text-secondary)]"
              }`}
            >
              {status}
            </button>
          ))}
        </div>

        <label className="flex items-center gap-1.5 text-xs text-[var(--color-text-secondary)] cursor-pointer">
          <input
            type="checkbox"
            checked={onlyBlocks}
            onChange={(e) => setOnlyBlocks(e.target.checked)}
            className="rounded"
          />
          Only blocks
        </label>
      </div>

      {/* Selected Event Detail */}
      {selectedEvent && (
        <div className="px-6 pt-4">
          <EventDetailPanel
            event={selectedEvent}
            onClose={() => setSelectedEvent(null)}
          />
        </div>
      )}

      {/* Virtualized Event List */}
      <div
        ref={scrollContainerRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto"
        role="log"
        aria-label="Event timeline"
      >
        <div style={{ height: totalHeight, position: "relative" }}>
          <div
            style={{
              position: "absolute",
              top: startIndex * ROW_HEIGHT,
              left: 0,
              right: 0,
            }}
          >
            {visibleEvents.map((evt) => (
              <div
                key={evt.id}
                onClick={() =>
                  setSelectedEvent(
                    selectedEvent?.id === evt.id ? null : evt
                  )
                }
                className={`flex items-center gap-3 px-6 cursor-pointer transition-colors ${
                  selectedEvent?.id === evt.id
                    ? "bg-[var(--color-bg-tertiary)]"
                    : "hover:bg-[var(--color-bg-secondary)]"
                }`}
                style={{ height: ROW_HEIGHT }}
              >
                <span className="text-xs text-[var(--color-text-secondary)] w-16 shrink-0 font-mono">
                  {formatTimestamp(evt.timestamp)}
                </span>
                <span
                  className="text-xs w-24 truncate shrink-0 font-medium"
                  style={{ color: getServerColor(evt.server_name) }}
                >
                  {evt.server_name}
                </span>
                <span className="text-sm w-5 text-center text-[var(--color-text-secondary)] shrink-0">
                  {eventTypeIcon(evt.event_type)}
                </span>
                <DecisionBadge decision={evt.decision} />
                <span className="text-sm text-[var(--color-text-primary)] flex-1 truncate">
                  {evt.tool_name
                    ? `${evt.tool_name}: ${evt.action}`
                    : evt.action}
                  {evt.resource && (
                    <span className="ml-1.5 text-xs text-[var(--color-text-secondary)] font-mono">
                      {truncateResource(evt.resource, 36)}
                    </span>
                  )}
                </span>
                <RiskBadge level={evt.risk_level} />
              </div>
            ))}
          </div>
        </div>

        {filteredEvents.length === 0 && (
          <div className="flex items-center justify-center h-full text-sm text-[var(--color-text-secondary)]">
            {events.length === 0
              ? "No events recorded yet."
              : "No events match your filters."}
          </div>
        )}
      </div>

      {/* Auto-scroll indicator */}
      {!autoScroll && filteredEvents.length > 0 && (
        <button
          onClick={() => {
            setAutoScroll(true);
            if (scrollContainerRef.current) {
              scrollContainerRef.current.scrollTop = 0;
            }
          }}
          className="absolute bottom-4 right-4 bg-[var(--color-accent)] text-white text-xs px-3 py-1.5 rounded-full shadow-lg hover:bg-[var(--color-accent-hover)] transition-colors"
        >
          Scroll to latest
        </button>
      )}
    </div>
  );
}
