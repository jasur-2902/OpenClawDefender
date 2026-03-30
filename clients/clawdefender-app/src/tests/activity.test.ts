import { describe, it, expect } from "vitest";
import { groupEvents, PERIOD_LABELS } from "../utils/eventGrouper";
import type { EventGroup, TimePeriod } from "../utils/eventGrouper";
import { normalizeDecision, normalizeRiskLevel } from "../utils/normalize";
import { getServerColor } from "../utils/serverColor";
import { formatTimestamp, formatRelativeTime } from "../utils/formatTime";
import type { AuditEvent } from "../types";

// ---------------------------------------------------------------------------
// Test Helpers
// ---------------------------------------------------------------------------

function makeEvent(overrides: Partial<AuditEvent> & { id: string }): AuditEvent {
  return {
    timestamp: new Date().toISOString(),
    event_type: "tool_call",
    server_name: "fs-server",
    tool_name: "read_file",
    action: "read",
    decision: "allowed",
    risk_level: "low",
    details: "{}",
    resource: "/tmp/test.txt",
    ...overrides,
  };
}

function makeEventsAt(
  baseTime: Date,
  count: number,
  overrides: Partial<AuditEvent> = {}
): AuditEvent[] {
  return Array.from({ length: count }, (_, i) =>
    makeEvent({
      id: `evt-${i}`,
      timestamp: new Date(baseTime.getTime() + i * 1000).toISOString(),
      resource: `/project/src/file${i}.ts`,
      ...overrides,
    })
  );
}

// ---------------------------------------------------------------------------
// normalizeDecision
// ---------------------------------------------------------------------------

describe("normalizeDecision", () => {
  it("normalizes 'allow' to 'allowed'", () => {
    expect(normalizeDecision("allow")).toBe("allowed");
    expect(normalizeDecision("Allow")).toBe("allowed");
    expect(normalizeDecision("allowed")).toBe("allowed");
    expect(normalizeDecision("ALLOWED")).toBe("allowed");
  });

  it("normalizes 'block'/'deny' to 'blocked'", () => {
    expect(normalizeDecision("block")).toBe("blocked");
    expect(normalizeDecision("blocked")).toBe("blocked");
    expect(normalizeDecision("deny")).toBe("blocked");
    expect(normalizeDecision("denied")).toBe("blocked");
  });

  it("normalizes 'prompt' to 'prompted'", () => {
    expect(normalizeDecision("prompt")).toBe("prompted");
    expect(normalizeDecision("prompted")).toBe("prompted");
  });

  it("returns lowercase for unknown values", () => {
    expect(normalizeDecision("Unknown")).toBe("unknown");
  });
});

// ---------------------------------------------------------------------------
// normalizeRiskLevel
// ---------------------------------------------------------------------------

describe("normalizeRiskLevel", () => {
  it("normalizes 'info' to 'low'", () => {
    expect(normalizeRiskLevel("info")).toBe("low");
  });

  it("normalizes 'block'/'review' to 'medium'", () => {
    expect(normalizeRiskLevel("block")).toBe("medium");
    expect(normalizeRiskLevel("review")).toBe("medium");
  });

  it("passes through known levels", () => {
    expect(normalizeRiskLevel("low")).toBe("low");
    expect(normalizeRiskLevel("medium")).toBe("medium");
    expect(normalizeRiskLevel("high")).toBe("high");
    expect(normalizeRiskLevel("critical")).toBe("critical");
  });

  it("defaults unknown to 'low'", () => {
    expect(normalizeRiskLevel("unknown")).toBe("low");
  });
});

// ---------------------------------------------------------------------------
// getServerColor
// ---------------------------------------------------------------------------

describe("getServerColor", () => {
  it("returns a consistent color for the same name", () => {
    const color1 = getServerColor("fs-server");
    const color2 = getServerColor("fs-server");
    expect(color1).toBe(color2);
  });

  it("returns a hex color string", () => {
    const color = getServerColor("test-server");
    expect(color).toMatch(/^#[0-9a-fA-F]{6}$/);
  });

  it("returns different colors for different names", () => {
    const colors = new Set([
      getServerColor("server-a"),
      getServerColor("server-b"),
      getServerColor("server-c"),
      getServerColor("server-d"),
    ]);
    // With 8 colors and 4 names, we should get at least 2 distinct colors
    expect(colors.size).toBeGreaterThanOrEqual(2);
  });
});

// ---------------------------------------------------------------------------
// formatTimestamp
// ---------------------------------------------------------------------------

describe("formatTimestamp", () => {
  it("formats a valid ISO timestamp", () => {
    const result = formatTimestamp("2024-06-15T14:30:45Z");
    // Should contain time components
    expect(result).toBeTruthy();
    expect(result.length).toBeGreaterThan(0);
  });

  it("returns the input for invalid timestamps", () => {
    expect(formatTimestamp("not-a-date")).toBe("not-a-date");
  });
});

describe("formatRelativeTime", () => {
  it("returns 'just now' for recent timestamps", () => {
    const now = new Date().toISOString();
    expect(formatRelativeTime(now)).toBe("just now");
  });

  it("returns minutes for timestamps within an hour", () => {
    const tenMinAgo = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    expect(formatRelativeTime(tenMinAgo)).toBe("10m ago");
  });

  it("returns hours for timestamps within a day", () => {
    const threeHoursAgo = new Date(Date.now() - 3 * 3600 * 1000).toISOString();
    expect(formatRelativeTime(threeHoursAgo)).toBe("3h ago");
  });
});

// ---------------------------------------------------------------------------
// PERIOD_LABELS
// ---------------------------------------------------------------------------

describe("PERIOD_LABELS", () => {
  it("has labels for all period types", () => {
    const periods: TimePeriod[] = [
      "right_now",
      "earlier_today",
      "yesterday",
      "this_week",
      "older",
    ];
    for (const p of periods) {
      expect(PERIOD_LABELS[p]).toBeTruthy();
    }
  });
});

// ---------------------------------------------------------------------------
// groupEvents — time period assignment
// ---------------------------------------------------------------------------

describe("groupEvents — time periods", () => {
  const now = new Date("2024-06-15T15:00:00Z");

  it("assigns 'right_now' for events within 5 minutes", () => {
    const events = [
      makeEvent({
        id: "1",
        timestamp: new Date(now.getTime() - 2 * 60 * 1000).toISOString(),
      }),
    ];
    const groups = groupEvents(events, now);
    expect(groups.length).toBe(1);
    expect(groups[0].period).toBe("right_now");
  });

  it("assigns 'earlier_today' for events earlier today but beyond 5 min", () => {
    const events = [
      makeEvent({
        id: "1",
        timestamp: new Date("2024-06-15T10:00:00Z").toISOString(),
      }),
    ];
    const groups = groupEvents(events, now);
    expect(groups.length).toBe(1);
    expect(groups[0].period).toBe("earlier_today");
  });

  it("assigns 'yesterday' for events from yesterday", () => {
    const events = [
      makeEvent({
        id: "1",
        timestamp: new Date("2024-06-14T10:00:00Z").toISOString(),
      }),
    ];
    const groups = groupEvents(events, now);
    expect(groups.length).toBe(1);
    expect(groups[0].period).toBe("yesterday");
  });

  it("assigns 'this_week' for events from this week", () => {
    const events = [
      makeEvent({
        id: "1",
        timestamp: new Date("2024-06-10T10:00:00Z").toISOString(),
      }),
    ];
    const groups = groupEvents(events, now);
    expect(groups.length).toBe(1);
    expect(groups[0].period).toBe("this_week");
  });

  it("assigns 'older' for events beyond this week", () => {
    const events = [
      makeEvent({
        id: "1",
        timestamp: new Date("2024-01-01T10:00:00Z").toISOString(),
      }),
    ];
    const groups = groupEvents(events, now);
    expect(groups.length).toBe(1);
    expect(groups[0].period).toBe("older");
  });
});

// ---------------------------------------------------------------------------
// groupEvents — clustering
// ---------------------------------------------------------------------------

describe("groupEvents — clustering", () => {
  const now = new Date("2024-06-15T15:00:00Z");

  it("groups events with same server, tool, action, and path prefix within 30s", () => {
    const baseTime = new Date(now.getTime() - 60 * 1000); // 1 min ago
    const events = makeEventsAt(baseTime, 5, {
      server_name: "fs-server",
      tool_name: "read_file",
      action: "read",
    });
    const groups = groupEvents(events, now);

    // All 5 should be in one group
    expect(groups.length).toBe(1);
    expect(groups[0].type).toBe("grouped");
    expect(groups[0].count).toBe(5);
    expect(groups[0].children.length).toBe(5);
  });

  it("does not group events with different servers", () => {
    const baseTime = new Date(now.getTime() - 60 * 1000);
    const events = [
      makeEvent({
        id: "1",
        timestamp: baseTime.toISOString(),
        server_name: "server-a",
      }),
      makeEvent({
        id: "2",
        timestamp: new Date(baseTime.getTime() + 5000).toISOString(),
        server_name: "server-b",
      }),
    ];
    const groups = groupEvents(events, now);
    expect(groups.length).toBe(2);
    expect(groups.every((g) => g.type === "single")).toBe(true);
  });

  it("does not group events with different tools", () => {
    const baseTime = new Date(now.getTime() - 60 * 1000);
    const events = [
      makeEvent({
        id: "1",
        timestamp: baseTime.toISOString(),
        tool_name: "read_file",
      }),
      makeEvent({
        id: "2",
        timestamp: new Date(baseTime.getTime() + 5000).toISOString(),
        tool_name: "write_file",
      }),
    ];
    const groups = groupEvents(events, now);
    expect(groups.length).toBe(2);
  });

  it("does not group events more than 30 seconds apart", () => {
    const baseTime = new Date(now.getTime() - 2 * 60 * 1000);
    const events = [
      makeEvent({
        id: "1",
        timestamp: baseTime.toISOString(),
      }),
      makeEvent({
        id: "2",
        timestamp: new Date(baseTime.getTime() + 35_000).toISOString(), // 35s later
      }),
    ];
    const groups = groupEvents(events, now);
    expect(groups.length).toBe(2);
  });

  it("creates single-type groups for lone events", () => {
    const events = [
      makeEvent({
        id: "1",
        timestamp: new Date(now.getTime() - 60_000).toISOString(),
        server_name: "unique-server",
      }),
    ];
    const groups = groupEvents(events, now);
    expect(groups.length).toBe(1);
    expect(groups[0].type).toBe("single");
    expect(groups[0].count).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// groupEvents — summary text
// ---------------------------------------------------------------------------

describe("groupEvents — summary text", () => {
  const now = new Date("2024-06-15T15:00:00Z");

  it("generates summary with server, verb, count, and path for grouped events", () => {
    const baseTime = new Date(now.getTime() - 60 * 1000);
    const events = makeEventsAt(baseTime, 3, {
      server_name: "fs-server",
      tool_name: "read_file",
      action: "read",
    });
    const groups = groupEvents(events, now);
    expect(groups.length).toBe(1);
    const summary = groups[0].summary;
    expect(summary).toContain("fs-server");
    expect(summary).toContain("read");
    expect(summary).toContain("3");
  });

  it("generates description for single events", () => {
    const events = [
      makeEvent({
        id: "1",
        timestamp: new Date(now.getTime() - 60_000).toISOString(),
        tool_name: "read_file",
        action: "read",
        resource: "/tmp/test.txt",
      }),
    ];
    const groups = groupEvents(events, now);
    expect(groups[0].summary).toContain("read_file");
    expect(groups[0].summary).toContain("read");
  });
});

// ---------------------------------------------------------------------------
// groupEvents — multiple periods
// ---------------------------------------------------------------------------

describe("groupEvents — ordering across periods", () => {
  const now = new Date("2024-06-15T15:00:00Z");

  it("returns groups ordered by period (right_now first, older last)", () => {
    const events = [
      makeEvent({
        id: "old",
        timestamp: new Date("2024-01-01T10:00:00Z").toISOString(),
        server_name: "old-server",
      }),
      makeEvent({
        id: "recent",
        timestamp: new Date(now.getTime() - 60_000).toISOString(),
        server_name: "recent-server",
      }),
    ];
    const groups = groupEvents(events, now);
    expect(groups.length).toBe(2);
    expect(groups[0].period).toBe("right_now");
    expect(groups[1].period).toBe("older");
  });

  it("returns empty array for empty input", () => {
    const groups = groupEvents([], now);
    expect(groups).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// groupEvents — large dataset performance
// ---------------------------------------------------------------------------

describe("groupEvents — performance", () => {
  it("handles 10,000 events without throwing", () => {
    const now = new Date();
    const events: AuditEvent[] = [];
    for (let i = 0; i < 10_000; i++) {
      events.push(
        makeEvent({
          id: `e-${i}`,
          timestamp: new Date(
            now.getTime() - Math.random() * 7 * 24 * 3600 * 1000
          ).toISOString(),
          server_name: `server-${i % 5}`,
          tool_name: `tool-${i % 3}`,
          action: i % 2 === 0 ? "read" : "write",
          resource: `/project/src/file${i % 100}.ts`,
        })
      );
    }

    const start = performance.now();
    const groups = groupEvents(events, now);
    const elapsed = performance.now() - start;

    expect(groups.length).toBeGreaterThan(0);
    // Should complete well within 1 second for 10K events
    expect(elapsed).toBeLessThan(1000);
  });
});

// ---------------------------------------------------------------------------
// Filter logic (extracted for testing)
// ---------------------------------------------------------------------------

describe("Activity filter logic", () => {
  const events: AuditEvent[] = [
    makeEvent({ id: "1", server_name: "fs-server", decision: "allowed", risk_level: "low", tool_name: "read_file", action: "read", resource: "/tmp/a.txt" }),
    makeEvent({ id: "2", server_name: "net-server", decision: "blocked", risk_level: "high", tool_name: "fetch", action: "connect", resource: "tcp://evil.com" }),
    makeEvent({ id: "3", server_name: "fs-server", decision: "prompted", risk_level: "medium", tool_name: "write_file", action: "write", resource: "/etc/hosts" }),
    makeEvent({ id: "4", server_name: "db-server", decision: "allowed", risk_level: "low", tool_name: "query", action: "read", resource: null }),
    makeEvent({ id: "5", server_name: "net-server", decision: "deny", risk_level: "critical", tool_name: null, action: "connection_failed", resource: null }),
  ];

  function applyFilters(
    evts: AuditEvent[],
    opts: {
      search?: string;
      servers?: string[];
      status?: string;
      risk?: string;
      onlyConcerning?: boolean;
    }
  ): AuditEvent[] {
    let result = evts;

    if (opts.search) {
      const lower = opts.search.toLowerCase();
      result = result.filter(
        (e) =>
          e.server_name.toLowerCase().includes(lower) ||
          (e.tool_name?.toLowerCase().includes(lower) ?? false) ||
          e.action.toLowerCase().includes(lower) ||
          (e.resource?.toLowerCase().includes(lower) ?? false) ||
          e.details.toLowerCase().includes(lower)
      );
    }

    if (opts.servers && opts.servers.length > 0) {
      result = result.filter((e) => opts.servers!.includes(e.server_name));
    }

    if (opts.status) {
      result = result.filter(
        (e) => normalizeDecision(e.decision) === opts.status
      );
    }

    if (opts.risk) {
      const norm = (r: string) => normalizeRiskLevel(r);
      if (opts.risk === "dangerous") {
        result = result.filter((e) => norm(e.risk_level) === "critical" || norm(e.risk_level) === "high");
      } else if (opts.risk === "suspicious") {
        result = result.filter((e) => norm(e.risk_level) === "high" || norm(e.risk_level) === "medium");
      }
    }

    if (opts.onlyConcerning) {
      result = result.filter((e) => {
        const n = normalizeRiskLevel(e.risk_level);
        return n === "medium" || n === "high" || n === "critical";
      });
    }

    return result;
  }

  it("search filters by server name", () => {
    const result = applyFilters(events, { search: "fs-server" });
    expect(result.length).toBe(2);
    expect(result.every((e) => e.server_name === "fs-server")).toBe(true);
  });

  it("search filters by tool name", () => {
    const result = applyFilters(events, { search: "fetch" });
    expect(result.length).toBe(1);
    expect(result[0].id).toBe("2");
  });

  it("search filters by resource", () => {
    const result = applyFilters(events, { search: "evil.com" });
    expect(result.length).toBe(1);
    expect(result[0].id).toBe("2");
  });

  it("multi-server filter works", () => {
    const result = applyFilters(events, { servers: ["fs-server", "db-server"] });
    expect(result.length).toBe(3);
  });

  it("status filter: blocked", () => {
    const result = applyFilters(events, { status: "blocked" });
    expect(result.length).toBe(2); // "blocked" + "deny" both normalize to "blocked"
  });

  it("status filter: prompted", () => {
    const result = applyFilters(events, { status: "prompted" });
    expect(result.length).toBe(1);
    expect(result[0].id).toBe("3");
  });

  it("risk filter: dangerous (critical + high)", () => {
    const result = applyFilters(events, { risk: "dangerous" });
    expect(result.length).toBe(2);
  });

  it("onlyConcerning filters to medium+ risk", () => {
    const result = applyFilters(events, { onlyConcerning: true });
    expect(result.length).toBe(3); // high, medium, critical
  });

  it("combined filters work together", () => {
    const result = applyFilters(events, {
      servers: ["net-server"],
      status: "blocked",
    });
    expect(result.length).toBe(2);
  });

  it("returns all events with no filters", () => {
    const result = applyFilters(events, {});
    expect(result.length).toBe(5);
  });
});
