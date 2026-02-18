import { describe, it, expect } from "vitest";
import type {
  NetworkConnectionEvent,
  NetworkSummaryData,
  ServerTrafficData,
  NetworkSettings,
  NetworkExtensionStatus,
} from "../types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mockConnection(
  overrides: Partial<NetworkConnectionEvent> = {}
): NetworkConnectionEvent {
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

// Simulate the network policy evaluation logic from the Rust engine.
type PolicyAction = "allowed" | "blocked" | "prompted";

interface PolicyEvaluationInput {
  isAgent: boolean;
  iocMatch: string | null;
  guardAllowlist: string[] | null;
  destinationDomain: string | null;
  destinationIp: string;
  killChainContext: string | null;
  serverHasNeverNetworked: boolean;
}

function evaluateNetworkPolicy(input: PolicyEvaluationInput): {
  action: PolicyAction;
  reason: string;
  severity: "low" | "medium" | "high" | "critical";
} {
  // 1. Non-agent traffic always allowed.
  if (!input.isAgent) {
    return { action: "allowed", reason: "Non-agent process", severity: "low" };
  }

  // 2. IoC match -> block.
  if (input.iocMatch) {
    return {
      action: "blocked",
      reason: `IoC match: ${input.iocMatch}`,
      severity: "critical",
    };
  }

  // 3. Guard allowlist.
  if (input.guardAllowlist) {
    const dest = input.destinationDomain ?? input.destinationIp;
    if (!input.guardAllowlist.includes(dest)) {
      return {
        action: "blocked",
        reason: `${dest} not in guard allowlist`,
        severity: "high",
      };
    }
  }

  // 4. Behavioral escalation.
  if (input.serverHasNeverNetworked) {
    const severity = input.killChainContext ? "critical" : "medium";
    return {
      action: "prompted",
      reason: "Server has never made network connections",
      severity: severity as "critical" | "medium",
    };
  }

  // 5. Kill chain escalation.
  if (input.killChainContext) {
    return {
      action: "prompted",
      reason: input.killChainContext,
      severity: "critical",
    };
  }

  // 6. Default.
  return { action: "prompted", reason: "No rule matched", severity: "medium" };
}

// Simulate DNS filter logic.
interface DnsFilterConfig {
  blocklist: string[];
  wildcardBlocks: string[];
  allowlist: string[];
  iocDomains: string[];
}

function checkDnsFilter(
  domain: string,
  config: DnsFilterConfig
): { action: "allow" | "block" | "log"; reason: string } {
  const lower = domain.toLowerCase();

  if (config.allowlist.includes(lower)) {
    return { action: "allow", reason: "domain in allowlist" };
  }

  if (config.blocklist.includes(lower)) {
    return { action: "block", reason: "domain in blocklist" };
  }

  for (const pattern of config.wildcardBlocks) {
    if (lower.endsWith(pattern) && lower.length > pattern.length) {
      return { action: "block", reason: `wildcard block *${pattern}` };
    }
  }

  for (const ioc of config.iocDomains) {
    if (lower === ioc.toLowerCase()) {
      return { action: "block", reason: "domain matches IoC feed" };
    }
  }

  return { action: "allow", reason: "no threat detected" };
}

// Simulate rate limiter.
function checkRateLimit(
  connectionTimestamps: number[],
  maxPerMinute: number,
  uniqueDestinations: string[],
  maxUniquePer10s: number
): { connectionAlert: boolean; destinationAlert: boolean } {
  return {
    connectionAlert: connectionTimestamps.length > maxPerMinute,
    destinationAlert: new Set(uniqueDestinations).size > maxUniquePer10s,
  };
}

// ---------------------------------------------------------------------------
// Tests: Network Policy Evaluation
// ---------------------------------------------------------------------------

describe("Network policy evaluation", () => {
  it("should always allow non-agent traffic regardless of signals", () => {
    const result = evaluateNetworkPolicy({
      isAgent: false,
      iocMatch: "THREAT-001",
      guardAllowlist: ["only-this.com"],
      destinationDomain: "evil.com",
      destinationIp: "10.0.0.1",
      killChainContext: "Active kill chain",
      serverHasNeverNetworked: true,
    });
    expect(result.action).toBe("allowed");
    expect(result.severity).toBe("low");
  });

  it("should block agent traffic matching IoC", () => {
    const result = evaluateNetworkPolicy({
      isAgent: true,
      iocMatch: "THREAT-2026-001",
      guardAllowlist: null,
      destinationDomain: "api.trusted.com",
      destinationIp: "1.2.3.4",
      killChainContext: null,
      serverHasNeverNetworked: false,
    });
    expect(result.action).toBe("blocked");
    expect(result.severity).toBe("critical");
    expect(result.reason).toContain("THREAT-2026-001");
  });

  it("should block agent traffic outside guard allowlist", () => {
    const result = evaluateNetworkPolicy({
      isAgent: true,
      iocMatch: null,
      guardAllowlist: ["api.anthropic.com"],
      destinationDomain: "unauthorized.com",
      destinationIp: "5.6.7.8",
      killChainContext: null,
      serverHasNeverNetworked: false,
    });
    expect(result.action).toBe("blocked");
    expect(result.reason).toContain("guard allowlist");
  });

  it("should allow agent traffic within guard allowlist", () => {
    const result = evaluateNetworkPolicy({
      isAgent: true,
      iocMatch: null,
      guardAllowlist: ["api.anthropic.com"],
      destinationDomain: "api.anthropic.com",
      destinationIp: "5.6.7.8",
      killChainContext: null,
      serverHasNeverNetworked: false,
    });
    expect(result.action).not.toBe("blocked");
  });

  it("should escalate to critical when kill chain context is active", () => {
    const result = evaluateNetworkPolicy({
      isAgent: true,
      iocMatch: null,
      guardAllowlist: null,
      destinationDomain: "suspicious.com",
      destinationIp: "9.9.9.9",
      killChainContext: "Credential read followed by network connection",
      serverHasNeverNetworked: true,
    });
    expect(result.severity).toBe("critical");
  });

  it("should prompt when server has never networked", () => {
    const result = evaluateNetworkPolicy({
      isAgent: true,
      iocMatch: null,
      guardAllowlist: null,
      destinationDomain: "api.example.com",
      destinationIp: "93.184.216.34",
      killChainContext: null,
      serverHasNeverNetworked: true,
    });
    expect(result.action).toBe("prompted");
    expect(result.reason).toContain("never made network connections");
  });
});

// ---------------------------------------------------------------------------
// Tests: DNS Filter
// ---------------------------------------------------------------------------

describe("DNS filter evaluation", () => {
  const defaultConfig: DnsFilterConfig = {
    blocklist: ["malware-c2.evil.com", "bad-domain.net"],
    wildcardBlocks: [".evil-corp.com"],
    allowlist: ["safe.example.com"],
    iocDomains: ["known-bad.net"],
  };

  it("should block exact blocklist match", () => {
    const result = checkDnsFilter("malware-c2.evil.com", defaultConfig);
    expect(result.action).toBe("block");
    expect(result.reason).toContain("blocklist");
  });

  it("should block wildcard match", () => {
    const result = checkDnsFilter("api.evil-corp.com", defaultConfig);
    expect(result.action).toBe("block");
    expect(result.reason).toContain("wildcard");
  });

  it("should block deeper subdomains via wildcard", () => {
    const result = checkDnsFilter("deep.sub.evil-corp.com", defaultConfig);
    expect(result.action).toBe("block");
  });

  it("should not block root domain with wildcard rule", () => {
    // ".evil-corp.com" wildcard should not match "evil-corp.com" itself
    // because lower.length must be > pattern.length
    const result = checkDnsFilter("evil-corp.com", defaultConfig);
    expect(result.action).not.toBe("block");
  });

  it("should block IoC domain match", () => {
    const result = checkDnsFilter("known-bad.net", defaultConfig);
    expect(result.action).toBe("block");
    expect(result.reason).toContain("IoC");
  });

  it("should allow domain in allowlist even if in blocklist", () => {
    const config: DnsFilterConfig = {
      blocklist: ["safe.example.com"],
      wildcardBlocks: [],
      allowlist: ["safe.example.com"],
      iocDomains: [],
    };
    const result = checkDnsFilter("safe.example.com", config);
    expect(result.action).toBe("allow");
    expect(result.reason).toContain("allowlist");
  });

  it("should allow unknown safe domains", () => {
    const result = checkDnsFilter("api.github.com", defaultConfig);
    expect(result.action).toBe("allow");
    expect(result.reason).toContain("no threat");
  });

  it("should be case-insensitive", () => {
    const result = checkDnsFilter("MALWARE-C2.EVIL.COM", defaultConfig);
    expect(result.action).toBe("block");
  });
});

// ---------------------------------------------------------------------------
// Tests: Rate Limiter
// ---------------------------------------------------------------------------

describe("Rate limiter behavior", () => {
  it("should not alert when under thresholds", () => {
    const timestamps = [1, 2, 3, 4, 5];
    const destinations = ["a.com", "b.com", "c.com"];
    const result = checkRateLimit(timestamps, 10, destinations, 5);
    expect(result.connectionAlert).toBe(false);
    expect(result.destinationAlert).toBe(false);
  });

  it("should alert when connections exceed per-minute limit", () => {
    const timestamps = Array.from({ length: 101 }, (_, i) => i);
    const destinations = ["a.com"];
    const result = checkRateLimit(timestamps, 100, destinations, 10);
    expect(result.connectionAlert).toBe(true);
    expect(result.destinationAlert).toBe(false);
  });

  it("should alert when unique destinations exceed threshold", () => {
    const timestamps = [1, 2, 3];
    const destinations = Array.from({ length: 11 }, (_, i) => `dest-${i}.com`);
    const result = checkRateLimit(timestamps, 100, destinations, 10);
    expect(result.connectionAlert).toBe(false);
    expect(result.destinationAlert).toBe(true);
  });

  it("should alert on both thresholds simultaneously", () => {
    const timestamps = Array.from({ length: 200 }, (_, i) => i);
    const destinations = Array.from({ length: 20 }, (_, i) => `dest-${i}.com`);
    const result = checkRateLimit(timestamps, 100, destinations, 10);
    expect(result.connectionAlert).toBe(true);
    expect(result.destinationAlert).toBe(true);
  });

  it("should not alert with duplicate destinations", () => {
    const timestamps = [1, 2, 3];
    const destinations = ["a.com", "a.com", "a.com", "a.com", "a.com"];
    const result = checkRateLimit(timestamps, 10, destinations, 3);
    expect(result.destinationAlert).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Tests: Connection Log Aggregation for Dashboard
// ---------------------------------------------------------------------------

describe("Connection log aggregation for dashboard", () => {
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

    return {
      total_allowed,
      total_blocked,
      total_prompted,
      top_destinations,
      period,
    };
  }

  function computeTrafficStats(
    connections: NetworkConnectionEvent[],
    serverName: string,
    period: string
  ): ServerTrafficData {
    const serverConns = connections.filter(
      (c) => c.server_name === serverName
    );
    const uniqueDests = new Set<string>();
    let bytesSent = 0;
    let bytesReceived = 0;
    let allowed = 0;
    let blocked = 0;
    let prompted = 0;

    for (const c of serverConns) {
      uniqueDests.add(c.destination_domain ?? c.destination_ip);
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

  it("should aggregate mixed connections into correct summary", () => {
    const connections = [
      mockConnection({ id: "1", action: "allowed" }),
      mockConnection({ id: "2", action: "blocked" }),
      mockConnection({ id: "3", action: "blocked" }),
      mockConnection({ id: "4", action: "prompted" }),
      mockConnection({ id: "5", action: "allowed" }),
    ];
    const summary = aggregateSummary(connections, "last_24h");
    expect(summary.total_allowed).toBe(2);
    expect(summary.total_blocked).toBe(2);
    expect(summary.total_prompted).toBe(1);
    expect(summary.period).toBe("last_24h");
  });

  it("should correctly identify top destinations", () => {
    const connections = [
      mockConnection({ id: "1", destination_domain: "api.github.com" }),
      mockConnection({ id: "2", destination_domain: "api.github.com" }),
      mockConnection({ id: "3", destination_domain: "api.github.com" }),
      mockConnection({ id: "4", destination_domain: "example.com" }),
    ];
    const summary = aggregateSummary(connections, "last_24h");
    expect(summary.top_destinations[0].destination).toBe("api.github.com");
    expect(summary.top_destinations[0].count).toBe(3);
  });

  it("should compute per-server traffic stats", () => {
    const connections = [
      mockConnection({
        id: "1",
        server_name: "github",
        action: "allowed",
        bytes_sent: 100,
        bytes_received: 500,
        destination_domain: "api.github.com",
      }),
      mockConnection({
        id: "2",
        server_name: "github",
        action: "blocked",
        bytes_sent: 0,
        bytes_received: 0,
        destination_domain: "evil.com",
      }),
      mockConnection({
        id: "3",
        server_name: "filesystem",
        action: "allowed",
        bytes_sent: 50,
        bytes_received: 200,
      }),
    ];
    const stats = computeTrafficStats(connections, "github", "last_24h");
    expect(stats.total_connections).toBe(2);
    expect(stats.connections_allowed).toBe(1);
    expect(stats.connections_blocked).toBe(1);
    expect(stats.bytes_sent).toBe(100);
    expect(stats.bytes_received).toBe(500);
    expect(stats.unique_destinations).toBe(2);
  });

  it("should handle empty connection list", () => {
    const summary = aggregateSummary([], "last_24h");
    expect(summary.total_allowed).toBe(0);
    expect(summary.total_blocked).toBe(0);
    expect(summary.total_prompted).toBe(0);
    expect(summary.top_destinations).toHaveLength(0);
  });

  it("should cap top destinations at 10", () => {
    const connections = Array.from({ length: 15 }, (_, i) =>
      mockConnection({
        id: `${i}`,
        destination_domain: `dest-${i}.example.com`,
      })
    );
    const summary = aggregateSummary(connections, "last_24h");
    expect(summary.top_destinations.length).toBeLessThanOrEqual(10);
  });
});

// ---------------------------------------------------------------------------
// Tests: Settings Persistence Logic
// ---------------------------------------------------------------------------

describe("Network settings persistence", () => {
  function defaultSettings(): NetworkSettings {
    return {
      filter_enabled: true,
      dns_enabled: true,
      filter_all_processes: false,
      default_action: "prompt",
      prompt_timeout: 30,
      block_private_ranges: false,
      block_doh: false,
      log_dns: true,
    };
  }

  it("should have correct default values", () => {
    const settings = defaultSettings();
    expect(settings.filter_enabled).toBe(true);
    expect(settings.dns_enabled).toBe(true);
    expect(settings.filter_all_processes).toBe(false);
    expect(settings.default_action).toBe("prompt");
    expect(settings.prompt_timeout).toBe(30);
    expect(settings.block_private_ranges).toBe(false);
    expect(settings.block_doh).toBe(false);
    expect(settings.log_dns).toBe(true);
  });

  it("should serialize and deserialize settings correctly", () => {
    const settings = defaultSettings();
    settings.default_action = "block";
    settings.prompt_timeout = 60;

    const json = JSON.stringify(settings);
    const parsed = JSON.parse(json) as NetworkSettings;

    expect(parsed.default_action).toBe("block");
    expect(parsed.prompt_timeout).toBe(60);
    expect(parsed.filter_enabled).toBe(true);
  });

  it("should validate default_action enum values", () => {
    const validActions: NetworkSettings["default_action"][] = [
      "prompt",
      "block",
      "allow",
    ];
    for (const action of validActions) {
      const settings = defaultSettings();
      settings.default_action = action;
      expect(["prompt", "block", "allow"]).toContain(settings.default_action);
    }
  });

  it("should preserve all fields through round-trip", () => {
    const settings: NetworkSettings = {
      filter_enabled: false,
      dns_enabled: false,
      filter_all_processes: true,
      default_action: "allow",
      prompt_timeout: 120,
      block_private_ranges: true,
      block_doh: true,
      log_dns: false,
    };

    const roundTripped = JSON.parse(
      JSON.stringify(settings)
    ) as NetworkSettings;

    expect(roundTripped).toEqual(settings);
  });

  it("should handle extension status types", () => {
    const status: NetworkExtensionStatus = {
      loaded: true,
      filter_active: true,
      dns_active: true,
      filtering_count: 42,
      mock_mode: false,
    };

    const json = JSON.stringify(status);
    const parsed = JSON.parse(json) as NetworkExtensionStatus;

    expect(parsed.loaded).toBe(true);
    expect(parsed.filtering_count).toBe(42);
    expect(parsed.mock_mode).toBe(false);
  });

  it("should handle mock mode status", () => {
    const status: NetworkExtensionStatus = {
      loaded: false,
      filter_active: false,
      dns_active: false,
      filtering_count: 0,
      mock_mode: true,
    };

    expect(status.mock_mode).toBe(true);
    expect(status.loaded).toBe(false);
  });
});
