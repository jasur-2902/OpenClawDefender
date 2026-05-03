import { useEffect, useState, useRef, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { useEventStore } from "../stores/eventStore";
import { Icon, Dot, VerdictPill, Badge } from "../components/design";
import { useToastStore } from "../components/notifications/ToastContainer";
import type { HumanizedEvent } from "../types";
import { PermissionBanner } from "../components/PermissionBanner";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Map source/event type to an icon name. */
function kindIcon(e: HumanizedEvent): string {
  const et = e.raw_event.event_type;
  if (et === "eslogger" || e.source_type === "os") return "process";
  if (et === "network" || et === "dns") return et;
  return "tools";
}

function fmtTime(ts: string): string {
  try {
    return new Date(ts).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return ts;
  }
}

function describeAction(e: HumanizedEvent): string {
  return e.one_liner;
}

function pathTail(e: HumanizedEvent): string {
  const r = e.raw_event.resource;
  if (!r) return "\u2014";
  const parts = r.split("/");
  return parts.slice(-2).join("/") || r;
}

/** Return classification color. */
function classColor(level: string): string {
  switch (level.toLowerCase()) {
    case "critical":
      return "var(--red)";
    case "high":
      return "var(--red)";
    case "suspicious":
      return "var(--amber)";
    case "medium":
      return "var(--amber)";
    case "notable":
      return "var(--amber)";
    case "low":
      return "var(--green)";
    default:
      return "var(--ink-2)";
  }
}

// ---------------------------------------------------------------------------
// Pill filter select
// ---------------------------------------------------------------------------

function Pill({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: string[];
  onChange: (v: string) => void;
}) {
  return (
    <label
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 5,
        padding: "4px 8px",
        borderRadius: 6,
        fontSize: 12,
        color: "var(--ink-2)",
        background: "var(--bg-2)",
      }}
    >
      <span style={{ color: "var(--ink-3)" }}>{label}:</span>
      <select
        value={value}
        onChange={(ev) => onChange(ev.target.value)}
        style={{
          background: "transparent",
          border: "none",
          color: "var(--ink-0)",
          fontSize: 12,
          outline: "none",
        }}
      >
        {options.map((o) => (
          <option key={o} value={o}>
            {o}
          </option>
        ))}
      </select>
    </label>
  );
}

// ---------------------------------------------------------------------------
// Activity Screen
// ---------------------------------------------------------------------------

export function Activity() {
  const navigate = useNavigate();
  const events = useEventStore((s) => s.events);
  const setEvents = useEventStore((s) => s.setEvents);
  const onlyNotable = useEventStore((s) => s.onlyNotable);
  const setOnlyNotable = useEventStore((s) => s.setOnlyNotable);
  const searchText = useEventStore((s) => s.searchText);
  const setSearchText = useEventStore((s) => s.setSearchText);
  const serverFilter = useEventStore((s) => s.serverFilter);
  const setServerFilter = useEventStore((s) => s.setServerFilter);
  const riskFilter = useEventStore((s) => s.riskFilter);
  const setRiskFilter = useEventStore((s) => s.setRiskFilter);

  const [liveMode, setLiveMode] = useState(true);
  const [loading, setLoading] = useState(true);
  const addToast = useToastStore((s) => s.addToast);

  // Track live indicator
  const eventCount = events.length;
  const prevCountRef = useRef(eventCount);
  const liveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [isLive, setIsLive] = useState(false);

  useEffect(() => {
    if (eventCount > prevCountRef.current) {
      setIsLive(true);
      if (liveTimerRef.current) clearTimeout(liveTimerRef.current);
      liveTimerRef.current = setTimeout(() => setIsLive(false), 5000);
    }
    prevCountRef.current = eventCount;
  }, [eventCount]);

  // Load data
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
          action: { label: "Retry", onClick: () => window.location.reload() },
        });
      });
  }, [setEvents, addToast]);

  // Derived server list
  const serverNames = useMemo(() => {
    const s = new Set<string>();
    for (const e of events) s.add(e.server_display_name);
    return ["all", ...Array.from(s).sort()];
  }, [events]);

  // Derived kind list
  const kindOptions = useMemo(() => {
    const s = new Set<string>();
    for (const e of events) s.add(e.raw_event.event_type);
    return ["all", ...Array.from(s).sort()];
  }, [events]);

  // Active filter values (using store's serverFilter[0] or "all")
  const activeServer =
    serverFilter.length > 0 ? serverFilter[0] : "all";
  const activeKind = riskFilter || "all";

  // Filtered events
  const visible = useMemo(() => {
    let result = events;
    if (onlyNotable) result = result.filter((e) => e.is_notable);
    if (activeKind !== "all")
      result = result.filter((e) => e.raw_event.event_type === activeKind);
    if (activeServer !== "all")
      result = result.filter((e) => e.server_display_name === activeServer);
    if (searchText) {
      const lower = searchText.toLowerCase();
      result = result.filter(
        (e) =>
          e.one_liner.toLowerCase().includes(lower) ||
          e.server_display_name.toLowerCase().includes(lower) ||
          (e.raw_event.resource?.toLowerCase().includes(lower) ?? false)
      );
    }
    return result;
  }, [events, onlyNotable, activeKind, activeServer, searchText]);

  return (
    <div style={{ display: "grid", gridTemplateRows: "auto auto 1fr", height: "100%" }}>
      <PermissionBanner />
      {/* Toolbar */}
      <div
        style={{
          padding: "12px 20px",
          borderBottom: "1px solid var(--line)",
          display: "flex",
          alignItems: "center",
          gap: 10,
          flexWrap: "wrap",
          background: "var(--bg-1)",
        }}
      >
        <Dot
          color={liveMode && isLive ? "var(--green)" : "var(--ink-3)"}
          size={7}
          pulse={liveMode && isLive}
        />
        <span style={{ fontSize: 13, fontWeight: 600 }}>
          {visible.length} events
        </span>
        <span style={{ fontSize: 12, color: "var(--ink-3)" }}>
          {isLive ? "· live" : ""}
        </span>
        <button
          onClick={() => setLiveMode(!liveMode)}
          style={{
            padding: "4px 10px",
            borderRadius: 6,
            fontSize: 12,
            color: "var(--ink-1)",
            background: "var(--bg-2)",
            border: "none",
            cursor: "pointer",
          }}
        >
          {liveMode ? "Pause" : "Resume"}
        </button>

        <div
          style={{
            marginLeft: "auto",
            display: "flex",
            gap: 8,
            alignItems: "center",
          }}
        >
          <div style={{ position: "relative" }}>
            <Icon
              name="search"
              size={12}
              color="var(--ink-3)"
            />
            <input
              placeholder="Search\u2026"
              value={searchText}
              onChange={(ev) => setSearchText(ev.target.value)}
              style={{
                background: "var(--bg-2)",
                border: "none",
                borderRadius: 6,
                padding: "5px 10px 5px 26px",
                fontSize: 12.5,
                color: "var(--ink-0)",
                width: 200,
                outline: "none",
              }}
            />
          </div>
          <Pill
            label="kind"
            value={activeKind}
            options={kindOptions}
            onChange={(v) => setRiskFilter(v === "all" ? "" : v)}
          />
          <Pill
            label="app"
            value={activeServer}
            options={serverNames}
            onChange={(v) =>
              setServerFilter(v === "all" ? [] : [v])
            }
          />
          <button
            onClick={() => setOnlyNotable(!onlyNotable)}
            style={{
              padding: "5px 10px",
              fontSize: 12,
              borderRadius: 6,
              background: onlyNotable ? "var(--accent-soft)" : "transparent",
              color: onlyNotable ? "var(--accent)" : "var(--ink-2)",
              border: "none",
              cursor: "pointer",
            }}
          >
            Only what matters
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="cd-scroll" style={{ overflowY: "auto" }}>
        {loading && (
          <div style={{ padding: 40, textAlign: "center", color: "var(--ink-3)", fontSize: 13 }}>
            Loading events...
          </div>
        )}

        {!loading && visible.length === 0 && (
          <div
            style={{
              padding: 60,
              textAlign: "center",
              color: "var(--ink-3)",
              fontSize: 14,
            }}
          >
            No events match your filters.
            {(searchText || onlyNotable || activeKind !== "all" || activeServer !== "all") && (
              <button
                onClick={() => useEventStore.getState().resetFilters()}
                style={{
                  display: "block",
                  margin: "12px auto 0",
                  fontSize: 13,
                  color: "var(--accent)",
                  background: "none",
                  border: "none",
                  cursor: "pointer",
                }}
              >
                Clear all filters
              </button>
            )}
          </div>
        )}

        {!loading && visible.length > 0 && (
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}>
            <thead>
              <tr style={{ position: "sticky", top: 0, background: "var(--bg-1)", zIndex: 1 }}>
                {["", "Time", "App", "What it did", "Where", "Result"].map(
                  (h, i) => (
                    <th
                      key={i}
                      style={{
                        padding: "8px 12px",
                        textAlign: i === 5 ? "right" : "left",
                        fontSize: 11,
                        fontWeight: 600,
                        color: "var(--ink-2)",
                        borderBottom: "1px solid var(--line)",
                      }}
                    >
                      {h}
                    </th>
                  )
                )}
              </tr>
            </thead>
            <tbody>
              {visible.map((e) => (
                <tr
                  key={e.event_id}
                  onClick={() => navigate(`/activity/${e.event_id}`)}
                  style={{
                    cursor: "pointer",
                    borderBottom: "1px solid var(--line-soft)",
                  }}
                  onMouseEnter={(ev) =>
                    (ev.currentTarget.style.background = "var(--accent-soft)")
                  }
                  onMouseLeave={(ev) =>
                    (ev.currentTarget.style.background = "transparent")
                  }
                >
                  <td style={{ padding: "11px 16px", width: 28 }}>
                    <Icon name={kindIcon(e)} size={14} color="var(--ink-2)" />
                  </td>
                  <td
                    style={{
                      padding: "11px 12px",
                      color: "var(--ink-3)",
                      whiteSpace: "nowrap",
                      width: 70,
                      fontVariantNumeric: "tabular-nums",
                    }}
                  >
                    {fmtTime(e.timestamp)}
                  </td>
                  <td style={{ padding: "11px 12px", color: "var(--ink-0)" }}>
                    {e.server_display_name}
                  </td>
                  <td
                    style={{
                      padding: "11px 12px",
                      fontFamily: "var(--font-mono)",
                      fontSize: 12,
                      color: "var(--ink-1)",
                      maxWidth: 380,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {describeAction(e)}
                  </td>
                  <td
                    style={{
                      padding: "11px 12px",
                      color: "var(--ink-2)",
                      fontSize: 12,
                    }}
                  >
                    {pathTail(e)}
                  </td>
                  <td style={{ padding: "11px 16px", textAlign: "right" }}>
                    {e.is_notable ? (
                      <Badge color={classColor(e.risk_level)}>
                        {e.risk_level}
                      </Badge>
                    ) : (
                      <VerdictPill verdict={e.action_taken === "Blocked" ? "BLOCK" : "ALLOW"} />
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
