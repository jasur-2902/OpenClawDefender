import {
  useEffect,
  useState,
  useCallback,
  useRef,
  useMemo,
} from "react";
import { invoke } from "@tauri-apps/api/core";
import { useEventStore } from "../stores/eventStore";
import { useTauriEvent } from "../hooks/useTauriEvent";
import { PageHeader } from "../components/PageHeader";
import { ActivityFilters } from "../components/activity/ActivityFilters";
import { EventRow } from "../components/activity/EventRow";
import { GroupedEventRow } from "../components/activity/GroupedEventRow";
import { groupEvents, PERIOD_LABELS } from "../utils/eventGrouper";
import { EMPTY_STATES } from "../constants/messages";
import { useToastStore } from "../components/notifications/ToastContainer";
import type { AuditEvent, HumanizedEvent } from "../types";
import type { EventGroup, TimePeriod } from "../utils/eventGrouper";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ROW_HEIGHT_ESTIMATE = 52;
const BUFFER_PX = 400;

// ---------------------------------------------------------------------------
// Time range helpers
// ---------------------------------------------------------------------------

function getTimeRangeCutoff(range: string): number {
  const now = Date.now();
  switch (range) {
    case "1h":
      return now - 3600_000;
    case "today": {
      const d = new Date();
      d.setHours(0, 0, 0, 0);
      return d.getTime();
    }
    case "yesterday": {
      const d = new Date();
      d.setDate(d.getDate() - 1);
      d.setHours(0, 0, 0, 0);
      return d.getTime();
    }
    case "week": {
      const d = new Date();
      d.setDate(d.getDate() - 7);
      d.setHours(0, 0, 0, 0);
      return d.getTime();
    }
    default:
      return 0;
  }
}

// ---------------------------------------------------------------------------
// Activity Page
// ---------------------------------------------------------------------------

export function Activity() {
  const events = useEventStore((s) => s.events);
  const setEvents = useEventStore((s) => s.setEvents);
  const addRawEvent = useEventStore((s) => s.addRawEvent);
  const onlyNotable = useEventStore((s) => s.onlyNotable);
  const setOnlyNotable = useEventStore((s) => s.setOnlyNotable);

  // Filters
  const [searchText, setSearchText] = useState("");
  const [serverFilter, setServerFilter] = useState<string[]>([]);
  const [statusFilter, setStatusFilter] = useState("");
  const [riskFilter, setRiskFilter] = useState("");
  const [timeRange, setTimeRange] = useState("");
  const [correlationFilter, setCorrelationFilter] = useState("");

  // Scroll state
  const [autoScroll, setAutoScroll] = useState(true);
  const [newEventsPending, setNewEventsPending] = useState(0);
  const scrollContainerRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [containerHeight, setContainerHeight] = useState(0);

  // Live indicator
  const [isLive, setIsLive] = useState(false);
  const liveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Loading
  const [loading, setLoading] = useState(true);
  const addToast = useToastStore((s) => s.addToast);

  // ---------------------------------------------------------------------------
  // Data loading -- use humanized events
  // ---------------------------------------------------------------------------

  useEffect(() => {
    invoke<HumanizedEvent[]>("get_humanized_events", { count: 500, offset: 0 })
      .then((evts) => {
        setEvents(evts);
        setLoading(false);
      })
      .catch(() => {
        setLoading(false);
        addToast({
          title: "Could not load activity. Showing cached data.",
          severity: "warning",
          action: {
            label: "Retry",
            onClick: () => window.location.reload(),
          },
        });
      });
  }, [setEvents]);

  const handleNewEvent = useCallback(
    (payload: AuditEvent) => {
      addRawEvent(payload);

      // Flash live indicator
      setIsLive(true);
      if (liveTimerRef.current) clearTimeout(liveTimerRef.current);
      liveTimerRef.current = setTimeout(() => setIsLive(false), 5000);

      // If not auto-scrolling, show "new events" chip
      if (!autoScroll) {
        setNewEventsPending((prev) => prev + 1);
      }
    },
    [addRawEvent, autoScroll]
  );

  useTauriEvent<AuditEvent>("clawdefender://event", handleNewEvent);

  // ---------------------------------------------------------------------------
  // Derived data
  // ---------------------------------------------------------------------------

  const serverNames = useMemo(() => {
    const names = new Set<string>();
    for (const e of events) names.add(e.server_display_name);
    return Array.from(names).sort();
  }, [events]);

  const filteredEvents = useMemo(() => {
    let result = events;

    // "Only show things that matter" toggle
    if (onlyNotable) {
      result = result.filter((e) => e.is_notable);
    }

    // Text search -- searches humanized fields
    if (searchText) {
      const lower = searchText.toLowerCase();
      result = result.filter(
        (e) =>
          e.one_liner.toLowerCase().includes(lower) ||
          e.expanded_explanation.toLowerCase().includes(lower) ||
          e.server_display_name.toLowerCase().includes(lower) ||
          (e.raw_event.tool_name?.toLowerCase().includes(lower) ?? false) ||
          (e.raw_event.resource?.toLowerCase().includes(lower) ?? false)
      );
    }

    // Server filter (multi-select) -- uses display names
    if (serverFilter.length > 0) {
      result = result.filter((e) =>
        serverFilter.includes(e.server_display_name)
      );
    }

    // Action filter (uses humanized action_taken)
    if (statusFilter) {
      result = result.filter((e) => e.action_taken === statusFilter);
    }

    // Risk filter (uses humanized risk_level)
    if (riskFilter) {
      result = result.filter((e) => e.risk_level === riskFilter);
    }

    // Time range
    if (timeRange) {
      const cutoff = getTimeRangeCutoff(timeRange);
      result = result.filter(
        (e) => new Date(e.timestamp).getTime() >= cutoff
      );
    }

    // Correlation filter
    if (correlationFilter === "correlated") {
      result = result.filter((e) => e.correlation_id != null);
    } else if (correlationFilter === "uncorrelated") {
      result = result.filter((e) => e.correlation_id == null);
    }

    return result;
  }, [
    events,
    onlyNotable,
    searchText,
    serverFilter,
    statusFilter,
    riskFilter,
    timeRange,
    correlationFilter,
  ]);

  // Count hidden routine events for the filter indicator
  const hiddenCount = onlyNotable
    ? events.length - events.filter((e) => e.is_notable).length
    : 0;

  const groups = useMemo(() => groupEvents(filteredEvents), [filteredEvents]);

  // Flatten groups with period headers for virtualization
  type FeedItem =
    | { type: "period-header"; period: TimePeriod; id: string }
    | { type: "group"; group: EventGroup; id: string };

  const feedItems = useMemo(() => {
    const items: FeedItem[] = [];
    let currentPeriod: TimePeriod | null = null;

    for (const group of groups) {
      if (group.period !== currentPeriod) {
        currentPeriod = group.period;
        items.push({
          type: "period-header",
          period: group.period,
          id: `ph-${group.period}`,
        });
      }
      items.push({ type: "group", group, id: group.id });
    }

    return items;
  }, [groups]);

  // ---------------------------------------------------------------------------
  // Virtual scrolling
  // ---------------------------------------------------------------------------

  const totalHeight = feedItems.length * ROW_HEIGHT_ESTIMATE;
  const startIdx = Math.max(
    0,
    Math.floor((scrollTop - BUFFER_PX) / ROW_HEIGHT_ESTIMATE)
  );
  const endIdx = Math.min(
    feedItems.length,
    Math.ceil((scrollTop + containerHeight + BUFFER_PX) / ROW_HEIGHT_ESTIMATE)
  );
  const visibleItems = feedItems.slice(startIdx, endIdx);

  useEffect(() => {
    const container = scrollContainerRef.current;
    if (!container) return;
    const obs = new ResizeObserver((entries) => {
      for (const entry of entries) {
        setContainerHeight(entry.contentRect.height);
      }
    });
    obs.observe(container);
    return () => obs.disconnect();
  }, []);

  const rafRef = useRef<number | null>(null);
  const handleScroll = useCallback(() => {
    if (rafRef.current) return;
    rafRef.current = requestAnimationFrame(() => {
      rafRef.current = null;
      const container = scrollContainerRef.current;
      if (!container) return;
      setScrollTop(container.scrollTop);
      const isAtTop = container.scrollTop < ROW_HEIGHT_ESTIMATE;
      if (isAtTop && !autoScroll) {
        setAutoScroll(true);
        setNewEventsPending(0);
      } else if (!isAtTop && autoScroll) {
        setAutoScroll(false);
      }
    });
  }, [autoScroll]);

  useEffect(() => {
    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
  }, []);

  // Auto-scroll to top when new events arrive and user is at top
  useEffect(() => {
    if (autoScroll && scrollContainerRef.current) {
      scrollContainerRef.current.scrollTop = 0;
    }
  }, [events.length, autoScroll]);

  const scrollToTop = () => {
    if (scrollContainerRef.current) {
      scrollContainerRef.current.scrollTo({ top: 0, behavior: "smooth" });
    }
    setAutoScroll(true);
    setNewEventsPending(0);
  };

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  const hasFilters =
    searchText ||
    serverFilter.length > 0 ||
    statusFilter ||
    riskFilter ||
    timeRange ||
    onlyNotable ||
    correlationFilter;

  return (
    <div className="flex flex-col h-full">
      <div className="px-4 pt-4">
        <PageHeader
          title="Activity"
          subtitle="Live event feed from your AI tools"
          actions={
            <div className="flex items-center gap-3">
              {isLive && (
                <span
                  className="flex items-center gap-1.5 text-xs text-[var(--color-safe)]"
                  role="status"
                  aria-label="Receiving live events"
                >
                  <span className="relative flex h-2 w-2" aria-hidden="true">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[var(--color-safe)] opacity-75" />
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-[var(--color-safe)]" />
                  </span>
                  Live
                </span>
              )}
              <span
                className="text-xs text-[var(--color-text-secondary)] tabular-nums"
                aria-live="polite"
              >
                {filteredEvents.length} events
                {filteredEvents.length !== events.length &&
                  ` of ${events.length}`}
              </span>
            </div>
          }
        />
      </div>

      {/* Filter bar */}
      <ActivityFilters
        searchText={searchText}
        onSearchChange={setSearchText}
        serverFilter={serverFilter}
        onServerFilterChange={setServerFilter}
        serverNames={serverNames}
        statusFilter={statusFilter}
        onStatusFilterChange={setStatusFilter}
        riskFilter={riskFilter}
        onRiskFilterChange={setRiskFilter}
        timeRange={timeRange}
        onTimeRangeChange={setTimeRange}
        onlyNotable={onlyNotable}
        onOnlyNotableChange={setOnlyNotable}
        hiddenCount={hiddenCount}
        correlationFilter={correlationFilter}
        onCorrelationFilterChange={setCorrelationFilter}
      />

      {/* Feed */}
      <div
        ref={scrollContainerRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto relative"
        role="log"
        aria-label="Activity feed"
      >
        {/* Skeleton loading */}
        {loading && (
          <div className="space-y-1 p-4">
            {Array.from({ length: 8 }).map((_, i) => (
              <div
                key={i}
                className="h-[48px] rounded-lg bg-[var(--color-bg-secondary)] animate-pulse"
              />
            ))}
          </div>
        )}

        {/* Empty state */}
        {!loading && filteredEvents.length === 0 && (
          <div className="flex flex-col items-center justify-center h-full text-center px-4">
            <p className="text-lg font-medium text-[var(--color-text-primary)] mb-2">
              {hasFilters
                ? EMPTY_STATES.searchResults.headline
                : EMPTY_STATES.activity.headline}
            </p>
            <p className="text-sm text-[var(--color-text-secondary)] max-w-md">
              {hasFilters
                ? EMPTY_STATES.searchResults.body
                : EMPTY_STATES.activity.body}
            </p>
            {hasFilters && (
              <button
                onClick={() => {
                  setSearchText("");
                  setServerFilter([]);
                  setStatusFilter("");
                  setRiskFilter("");
                  setTimeRange("");
                  setOnlyNotable(false);
                  setCorrelationFilter("");
                }}
                className="mt-4 text-sm text-[var(--color-accent)] hover:text-[var(--color-accent-hover)] transition-colors"
              >
                Clear all filters
              </button>
            )}
          </div>
        )}

        {/* Virtualized event list */}
        {!loading && feedItems.length > 0 && (
          <div style={{ height: totalHeight, position: "relative" }}>
            <div
              style={{
                position: "absolute",
                top: startIdx * ROW_HEIGHT_ESTIMATE,
                left: 0,
                right: 0,
              }}
            >
              {visibleItems.map((item) => {
                if (item.type === "period-header") {
                  return (
                    <div
                      key={item.id}
                      className="sticky top-0 z-[var(--z-sticky)] px-4 py-2 bg-[var(--color-bg-primary)] border-b border-[var(--color-border)]"
                      style={{ height: ROW_HEIGHT_ESTIMATE }}
                    >
                      <span className="text-xs font-semibold uppercase tracking-wider text-[var(--color-text-secondary)]">
                        {PERIOD_LABELS[item.period]}
                      </span>
                    </div>
                  );
                }

                const group = item.group;
                if (group.type === "single") {
                  return (
                    <EventRow key={group.id} event={group.representative} />
                  );
                }
                return <GroupedEventRow key={group.id} group={group} />;
              })}
            </div>
          </div>
        )}
      </div>

      {/* "New events" floating chip */}
      {newEventsPending > 0 && !autoScroll && (
        <button
          onClick={scrollToTop}
          aria-live="polite"
          aria-label={`${newEventsPending} new event${newEventsPending > 1 ? "s" : ""}, scroll to top`}
          className="absolute top-[140px] left-1/2 -translate-x-1/2 bg-[var(--color-accent)] text-white text-xs px-4 py-1.5 rounded-full shadow-[var(--shadow-toast)] hover:bg-[var(--color-accent-hover)] transition-colors z-[var(--z-toast)]"
        >
          {newEventsPending} new event{newEventsPending > 1 ? "s" : ""}{" "}
          {"\u2191"}
        </button>
      )}
    </div>
  );
}
