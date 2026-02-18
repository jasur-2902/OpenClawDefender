import { describe, it, expect } from "vitest";
import type {
  NetworkConnectionEvent,
  NetworkSummaryData,
  ServerTrafficData,
} from "../types";

// Helper to create mock connection events
function mockConnection(overrides: Partial<NetworkConnectionEvent> = {}): NetworkConnectionEvent {
  return {
    id: "net-001",
    timestamp: "2026-02-18T12:00:00Z",
    pid: 1234,
    process_name: "test-server",
    server_name: "filesystem",
    destination_ip: "93.184.216.34",
    destination_port: 443,
    destination_domain: "example.com",
    protocol: "tcp",
    tls: true,
    action: "allowed",
    reason: "Rule 'allow_https'",
    rule: "allow_https",
    ioc_match: false,
    anomaly_score: null,
    behavioral: null,
    kill_chain: null,
    bytes_sent: 1024,
    bytes_received: 4096,
    duration_ms: 150,
    ...overrides,
  };
}

describe("NetworkConnectionEvent format", () => {
  it("should have all required fields", () => {
    const conn = mockConnection();
    expect(conn.id).toBeTruthy();
    expect(conn.timestamp).toBeTruthy();
    expect(conn.pid).toBeGreaterThan(0);
    expect(conn.destination_ip).toBeTruthy();
    expect(conn.destination_port).toBeGreaterThan(0);
    expect(conn.protocol).toBeTruthy();
    expect(typeof conn.tls).toBe("boolean");
    expect(["allowed", "blocked", "prompted"]).toContain(conn.action);
  });

  it("should allow optional fields to be null", () => {
    const conn = mockConnection({
      server_name: null,
      destination_domain: null,
      rule: null,
      anomaly_score: null,
      behavioral: null,
      kill_chain: null,
    });
    expect(conn.server_name).toBeNull();
    expect(conn.destination_domain).toBeNull();
    expect(conn.rule).toBeNull();
  });

  it("should serialize to JSON and back", () => {
    const conn = mockConnection();
    const json = JSON.stringify(conn);
    const parsed = JSON.parse(json) as NetworkConnectionEvent;
    expect(parsed.id).toBe(conn.id);
    expect(parsed.destination_domain).toBe("example.com");
    expect(parsed.bytes_sent).toBe(1024);
  });
});

describe("NetworkSummaryData aggregation", () => {
  function aggregateSummary(
    connections: NetworkConnectionEvent[],
    period: string
  ): NetworkSummaryData {
    let total_allowed = 0;
    let total_blocked = 0;
    let total_prompted = 0;
    const destCounts: Record<string, number> = {};

    for (const c of connections) {
      if (c.action === "allowed") total_allowed++;
      else if (c.action === "blocked") total_blocked++;
      else if (c.action === "prompted") total_prompted++;

      const dest = c.destination_domain ?? c.destination_ip;
      destCounts[dest] = (destCounts[dest] ?? 0) + 1;
    }

    const top_destinations = Object.entries(destCounts)
      .map(([destination, count]) => ({ destination, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    return { total_allowed, total_blocked, total_prompted, top_destinations, period };
  }

  it("should count allowed, blocked, prompted correctly", () => {
    const connections = [
      mockConnection({ id: "1", action: "allowed" }),
      mockConnection({ id: "2", action: "allowed" }),
      mockConnection({ id: "3", action: "blocked" }),
      mockConnection({ id: "4", action: "prompted" }),
    ];
    const summary = aggregateSummary(connections, "last_24h");
    expect(summary.total_allowed).toBe(2);
    expect(summary.total_blocked).toBe(1);
    expect(summary.total_prompted).toBe(1);
  });

  it("should produce empty summary for empty input", () => {
    const summary = aggregateSummary([], "last_24h");
    expect(summary.total_allowed).toBe(0);
    expect(summary.total_blocked).toBe(0);
    expect(summary.total_prompted).toBe(0);
    expect(summary.top_destinations).toHaveLength(0);
  });

  it("should rank top destinations by frequency", () => {
    const connections = [
      mockConnection({ id: "1", destination_domain: "api.github.com" }),
      mockConnection({ id: "2", destination_domain: "api.github.com" }),
      mockConnection({ id: "3", destination_domain: "api.github.com" }),
      mockConnection({ id: "4", destination_domain: "example.com" }),
      mockConnection({ id: "5", destination_domain: "example.com" }),
      mockConnection({ id: "6", destination_domain: "cdn.jsdelivr.net" }),
    ];
    const summary = aggregateSummary(connections, "last_24h");
    expect(summary.top_destinations[0].destination).toBe("api.github.com");
    expect(summary.top_destinations[0].count).toBe(3);
    expect(summary.top_destinations[1].destination).toBe("example.com");
    expect(summary.top_destinations[1].count).toBe(2);
  });

  it("should use destination_ip when domain is null", () => {
    const connections = [
      mockConnection({ id: "1", destination_domain: null, destination_ip: "8.8.8.8" }),
      mockConnection({ id: "2", destination_domain: null, destination_ip: "8.8.8.8" }),
    ];
    const summary = aggregateSummary(connections, "last_24h");
    expect(summary.top_destinations[0].destination).toBe("8.8.8.8");
    expect(summary.top_destinations[0].count).toBe(2);
  });
});

describe("Filter logic", () => {
  const connections = [
    mockConnection({ id: "1", action: "allowed", protocol: "tcp", server_name: "filesystem", destination_domain: "example.com" }),
    mockConnection({ id: "2", action: "blocked", protocol: "tcp", server_name: "github", destination_domain: "malicious.com" }),
    mockConnection({ id: "3", action: "prompted", protocol: "udp", server_name: "everything", destination_domain: "internal.corp" }),
    mockConnection({ id: "4", action: "allowed", protocol: "tcp", server_name: "filesystem", destination_domain: "api.github.com" }),
  ];

  function filterConnections(
    conns: NetworkConnectionEvent[],
    opts: { action?: string; protocol?: string; search?: string }
  ): NetworkConnectionEvent[] {
    let result = conns;

    if (opts.action) {
      result = result.filter((c) => c.action === opts.action);
    }
    if (opts.protocol) {
      result = result.filter((c) => c.protocol === opts.protocol);
    }
    if (opts.search) {
      const lower = opts.search.toLowerCase();
      result = result.filter(
        (c) =>
          (c.server_name?.toLowerCase().includes(lower) ?? false) ||
          c.destination_ip.toLowerCase().includes(lower) ||
          (c.destination_domain?.toLowerCase().includes(lower) ?? false) ||
          c.reason.toLowerCase().includes(lower)
      );
    }
    return result;
  }

  it("should filter by action", () => {
    expect(filterConnections(connections, { action: "allowed" })).toHaveLength(2);
    expect(filterConnections(connections, { action: "blocked" })).toHaveLength(1);
    expect(filterConnections(connections, { action: "prompted" })).toHaveLength(1);
  });

  it("should filter by protocol", () => {
    expect(filterConnections(connections, { protocol: "tcp" })).toHaveLength(3);
    expect(filterConnections(connections, { protocol: "udp" })).toHaveLength(1);
  });

  it("should filter by search text", () => {
    expect(filterConnections(connections, { search: "github" })).toHaveLength(2);
    expect(filterConnections(connections, { search: "malicious" })).toHaveLength(1);
    expect(filterConnections(connections, { search: "nonexistent" })).toHaveLength(0);
  });

  it("should combine filters", () => {
    expect(
      filterConnections(connections, { action: "allowed", protocol: "tcp" })
    ).toHaveLength(2);
    expect(
      filterConnections(connections, { action: "allowed", search: "github" })
    ).toHaveLength(1);
  });
});

describe("Traffic stats computation", () => {
  function computeTrafficStats(
    connections: NetworkConnectionEvent[],
    serverName: string,
    period: string
  ): ServerTrafficData {
    const serverConns = connections.filter((c) => c.server_name === serverName);

    const uniqueDests = new Set<string>();
    let bytesSent = 0;
    let bytesReceived = 0;
    let allowed = 0;
    let blocked = 0;
    let prompted = 0;

    for (const c of serverConns) {
      const dest = c.destination_domain ?? c.destination_ip;
      uniqueDests.add(dest);
      bytesSent += c.bytes_sent;
      bytesReceived += c.bytes_received;
      if (c.action === "allowed") allowed++;
      else if (c.action === "blocked") blocked++;
      else if (c.action === "prompted") prompted++;
    }

    return {
      server_name: serverName,
      total_connections: serverConns.length,
      connections_allowed: allowed,
      connections_blocked: blocked,
      connections_prompted: prompted,
      bytes_sent: bytesSent,
      bytes_received: bytesReceived,
      unique_destinations: uniqueDests.size,
      period,
    };
  }

  it("should aggregate stats for a specific server", () => {
    const connections = [
      mockConnection({ id: "1", server_name: "github", action: "allowed", bytes_sent: 100, bytes_received: 500, destination_domain: "api.github.com" }),
      mockConnection({ id: "2", server_name: "github", action: "blocked", bytes_sent: 0, bytes_received: 0, destination_domain: "malicious.com" }),
      mockConnection({ id: "3", server_name: "filesystem", action: "allowed", bytes_sent: 50, bytes_received: 200, destination_domain: "example.com" }),
    ];

    const stats = computeTrafficStats(connections, "github", "last_24h");
    expect(stats.total_connections).toBe(2);
    expect(stats.connections_allowed).toBe(1);
    expect(stats.connections_blocked).toBe(1);
    expect(stats.bytes_sent).toBe(100);
    expect(stats.bytes_received).toBe(500);
    expect(stats.unique_destinations).toBe(2);
  });

  it("should return zeros for unknown server", () => {
    const stats = computeTrafficStats([], "unknown", "last_24h");
    expect(stats.total_connections).toBe(0);
    expect(stats.bytes_sent).toBe(0);
    expect(stats.unique_destinations).toBe(0);
  });
});

describe("Sort by timestamp", () => {
  it("should sort connections by timestamp descending", () => {
    const connections = [
      mockConnection({ id: "1", timestamp: "2026-02-18T12:00:00Z" }),
      mockConnection({ id: "2", timestamp: "2026-02-18T13:00:00Z" }),
      mockConnection({ id: "3", timestamp: "2026-02-18T11:00:00Z" }),
    ];

    const sorted = [...connections].sort(
      (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );

    expect(sorted[0].id).toBe("2");
    expect(sorted[1].id).toBe("1");
    expect(sorted[2].id).toBe("3");
  });
});
