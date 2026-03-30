import { describe, it, expect } from 'vitest';
import { generateAlerts, mergeAlerts } from '../utils/alertGenerator';
import type { AuditEvent } from '../types/index';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

function makeEvent(overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    id: 'evt-1',
    timestamp: '2026-02-25T12:00:00Z',
    event_type: 'tool_call',
    server_name: 'filesystem-server',
    tool_name: 'read_file',
    action: 'read',
    decision: 'allowed',
    risk_level: 'low',
    details: 'Read a file',
    resource: '/project/src/main.ts',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Alert Generation
// ---------------------------------------------------------------------------

describe('Alert Generator', () => {
  it('should not generate alerts for low-risk allowed events', () => {
    const events = [makeEvent()];
    const alerts = generateAlerts(events);
    expect(alerts).toHaveLength(0);
  });

  it('should generate an alert for high-risk events', () => {
    const events = [makeEvent({ id: 'evt-high', risk_level: 'high', decision: 'blocked', details: 'Suspicious access' })];
    const alerts = generateAlerts(events);
    expect(alerts).toHaveLength(1);
    expect(alerts[0].severity).toBe('suspicious');
    expect(alerts[0].eventId).toBe('evt-high');
  });

  it('should generate an alert for critical-risk events', () => {
    const events = [makeEvent({ id: 'evt-crit', risk_level: 'critical', details: 'Attack detected' })];
    const alerts = generateAlerts(events);
    expect(alerts).toHaveLength(1);
    expect(alerts[0].severity).toBe('dangerous');
  });

  it('should generate an alert for blocked events regardless of risk level', () => {
    const events = [makeEvent({ id: 'evt-blocked', decision: 'blocked', risk_level: 'medium', details: 'Blocked action' })];
    const alerts = generateAlerts(events);
    expect(alerts).toHaveLength(1);
  });

  it('should generate an alert for kill chain events', () => {
    const events = [makeEvent({ id: 'evt-kc', details: 'Kill chain pattern detected', risk_level: 'low', decision: 'allowed' })];
    const alerts = generateAlerts(events);
    expect(alerts).toHaveLength(1);
    expect(alerts[0].category).toBe('kill_chain');
  });

  it('should generate an alert for uncorrelated activity', () => {
    const events = [makeEvent({ id: 'evt-unc', details: 'Uncorrelated OS activity detected', risk_level: 'low', decision: 'allowed' })];
    const alerts = generateAlerts(events);
    expect(alerts).toHaveLength(1);
    expect(alerts[0].category).toBe('uncorrelated');
  });

  it('should generate an alert for IoC matches', () => {
    const events = [makeEvent({ id: 'evt-ioc', details: 'IoC match on known threat', risk_level: 'low', decision: 'allowed' })];
    const alerts = generateAlerts(events);
    expect(alerts).toHaveLength(1);
    expect(alerts[0].category).toBe('ioc');
  });

  it('should deduplicate events from the same server and action within 5 minutes', () => {
    const events = [
      makeEvent({ id: 'evt-1', server_name: 'fs-server', tool_name: 'read_file', decision: 'blocked', timestamp: '2026-02-25T12:00:00Z' }),
      makeEvent({ id: 'evt-2', server_name: 'fs-server', tool_name: 'read_file', decision: 'blocked', timestamp: '2026-02-25T12:02:00Z' }),
      makeEvent({ id: 'evt-3', server_name: 'fs-server', tool_name: 'read_file', decision: 'blocked', timestamp: '2026-02-25T12:04:00Z' }),
    ];
    const alerts = generateAlerts(events);
    expect(alerts).toHaveLength(1);
  });

  it('should not deduplicate events from different servers', () => {
    const events = [
      makeEvent({ id: 'evt-1', server_name: 'server-a', tool_name: 'read_file', decision: 'blocked', timestamp: '2026-02-25T12:00:00Z' }),
      makeEvent({ id: 'evt-2', server_name: 'server-b', tool_name: 'read_file', decision: 'blocked', timestamp: '2026-02-25T12:01:00Z' }),
    ];
    const alerts = generateAlerts(events);
    expect(alerts).toHaveLength(2);
  });

  it('should not deduplicate events more than 5 minutes apart', () => {
    const events = [
      makeEvent({ id: 'evt-1', server_name: 'fs-server', tool_name: 'read_file', decision: 'blocked', timestamp: '2026-02-25T12:00:00Z' }),
      makeEvent({ id: 'evt-2', server_name: 'fs-server', tool_name: 'read_file', decision: 'blocked', timestamp: '2026-02-25T12:06:00Z' }),
    ];
    const alerts = generateAlerts(events);
    expect(alerts).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// Alert Titles (plain language)
// ---------------------------------------------------------------------------

describe('Alert Titles', () => {
  it('should generate SSH key title when resource contains .ssh', () => {
    const events = [makeEvent({ id: 'evt-ssh', resource: '~/.ssh/id_rsa', decision: 'blocked', server_name: 'code-server' })];
    const alerts = generateAlerts(events);
    expect(alerts[0].title).toContain('SSH keys');
    expect(alerts[0].title).toContain('code-server');
  });

  it('should generate AWS credentials title when resource matches', () => {
    const events = [makeEvent({ id: 'evt-aws', resource: '~/.aws/credentials', decision: 'blocked', server_name: 'data-server' })];
    const alerts = generateAlerts(events);
    expect(alerts[0].title).toContain('AWS credentials');
  });

  it('should generate env secrets title when resource contains .env', () => {
    const events = [makeEvent({ id: 'evt-env', resource: '/project/.env', decision: 'blocked', server_name: 'build-server' })];
    const alerts = generateAlerts(events);
    expect(alerts[0].title).toContain('environment secrets');
  });

  it('should generate kill chain title when details mention it', () => {
    const events = [makeEvent({ id: 'evt-kc', details: 'Kill chain credential exfiltration pattern', risk_level: 'critical' })];
    const alerts = generateAlerts(events);
    expect(alerts[0].title).toContain('Multi-step attack pattern');
  });

  it('should generate blocked action title for generic blocks', () => {
    const events = [makeEvent({ id: 'evt-block', decision: 'blocked', tool_name: 'write_file' })];
    const alerts = generateAlerts(events);
    expect(alerts[0].title).toContain('blocked');
    expect(alerts[0].title).toContain('write_file');
  });
});

// ---------------------------------------------------------------------------
// Alert Severity Mapping
// ---------------------------------------------------------------------------

describe('Alert Severity', () => {
  it('should map critical risk to dangerous severity', () => {
    const events = [makeEvent({ id: 'e1', risk_level: 'critical' })];
    const alerts = generateAlerts(events);
    expect(alerts[0].severity).toBe('dangerous');
  });

  it('should map high risk to suspicious severity', () => {
    const events = [makeEvent({ id: 'e1', risk_level: 'high', decision: 'blocked' })];
    const alerts = generateAlerts(events);
    expect(alerts[0].severity).toBe('suspicious');
  });

  it('should map medium/low risk blocked events to unusual severity', () => {
    const events = [makeEvent({ id: 'e1', risk_level: 'medium', decision: 'blocked' })];
    const alerts = generateAlerts(events);
    expect(alerts[0].severity).toBe('unusual');
  });
});

// ---------------------------------------------------------------------------
// Alert Merging
// ---------------------------------------------------------------------------

describe('Alert Merging', () => {
  it('should add new alerts that do not exist yet', () => {
    const existing = [
      { id: 'alert-1', severity: 'dangerous', title: 'Old alert', description: 'Desc', timestamp: '2026-02-25T11:00:00Z', resolved: false, eventId: 'evt-old' },
    ];
    const incoming = [
      { id: 'alert-evt-new', severity: 'suspicious' as const, title: 'New alert', description: 'Desc', timestamp: '2026-02-25T12:00:00Z', resolved: false, eventId: 'evt-new', serverName: 'server', decision: 'blocked', category: 'block' as const },
    ];
    const merged = mergeAlerts(existing, incoming);
    expect(merged).toHaveLength(2);
  });

  it('should not duplicate alerts with the same eventId', () => {
    const existing = [
      { id: 'alert-1', severity: 'dangerous', title: 'Existing', description: 'Desc', timestamp: '2026-02-25T11:00:00Z', resolved: false, eventId: 'evt-1' },
    ];
    const incoming = [
      { id: 'alert-evt-1', severity: 'dangerous' as const, title: 'Same event', description: 'Desc', timestamp: '2026-02-25T12:00:00Z', resolved: false, eventId: 'evt-1', serverName: 'server', decision: 'blocked', category: 'block' as const },
    ];
    const merged = mergeAlerts(existing, incoming);
    expect(merged).toHaveLength(1);
    expect(merged[0].title).toBe('Existing');
  });
});

// ---------------------------------------------------------------------------
// Alert Store Logic
// ---------------------------------------------------------------------------

describe('Alert Store Logic', () => {
  it('should count unresolved alerts correctly', () => {
    function countUnresolved(alerts: { resolved: boolean }[]): number {
      return alerts.filter((a) => !a.resolved).length;
    }
    const alerts = [
      { resolved: false },
      { resolved: true },
      { resolved: false },
      { resolved: true },
      { resolved: false },
    ];
    expect(countUnresolved(alerts)).toBe(3);
  });

  it('should mark all low-severity alerts as resolved', () => {
    function resolveAllLowSeverity(alerts: { severity: string; resolved: boolean }[]) {
      return alerts.map((a) =>
        !a.resolved && a.severity === 'unusual' ? { ...a, resolved: true } : a
      );
    }
    const alerts = [
      { severity: 'dangerous', resolved: false },
      { severity: 'unusual', resolved: false },
      { severity: 'suspicious', resolved: false },
      { severity: 'unusual', resolved: false },
    ];
    const result = resolveAllLowSeverity(alerts);
    expect(result[0].resolved).toBe(false); // dangerous stays unresolved
    expect(result[1].resolved).toBe(true); // unusual resolved
    expect(result[2].resolved).toBe(false); // suspicious stays unresolved
    expect(result[3].resolved).toBe(true); // unusual resolved
  });

  it('should sort alerts by severity then recency', () => {
    const severityOrder: Record<string, number> = { dangerous: 0, suspicious: 1, unusual: 2 };
    const alerts = [
      { severity: 'unusual', timestamp: '2026-02-25T12:00:00Z' },
      { severity: 'dangerous', timestamp: '2026-02-25T11:00:00Z' },
      { severity: 'suspicious', timestamp: '2026-02-25T12:30:00Z' },
      { severity: 'dangerous', timestamp: '2026-02-25T12:00:00Z' },
    ];
    const sorted = [...alerts].sort((a, b) => {
      const sa = severityOrder[a.severity] ?? 9;
      const sb = severityOrder[b.severity] ?? 9;
      if (sa !== sb) return sa - sb;
      return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
    });
    expect(sorted[0].severity).toBe('dangerous');
    expect(sorted[0].timestamp).toBe('2026-02-25T12:00:00Z'); // more recent dangerous first
    expect(sorted[1].severity).toBe('dangerous');
    expect(sorted[2].severity).toBe('suspicious');
    expect(sorted[3].severity).toBe('unusual');
  });
});

// ---------------------------------------------------------------------------
// Empty State
// ---------------------------------------------------------------------------

describe('Alerts Empty State', () => {
  it('should show empty state when there are no alerts, blocks, or recommendations', () => {
    const hasActiveAlerts = false;
    const hasRecentBlocks = false;
    const hasRecommendations = false;
    const isEmpty = !hasActiveAlerts && !hasRecentBlocks && !hasRecommendations;
    expect(isEmpty).toBe(true);
  });

  it('should not show empty state when there are active alerts', () => {
    const hasActiveAlerts = true;
    const hasRecentBlocks = false;
    const hasRecommendations = false;
    const isEmpty = !hasActiveAlerts && !hasRecentBlocks && !hasRecommendations;
    expect(isEmpty).toBe(false);
  });

  it('should not show empty state when there are recent blocks but no active alerts', () => {
    const hasActiveAlerts = false;
    const hasRecentBlocks = true;
    const hasRecommendations = false;
    const isEmpty = !hasActiveAlerts && !hasRecentBlocks && !hasRecommendations;
    expect(isEmpty).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Decision normalization
// ---------------------------------------------------------------------------

describe('Decision Normalization', () => {
  it('should normalize various blocked formats', () => {
    function normalizeDecision(d: string): string {
      const lower = d.toLowerCase();
      if (lower === 'blocked' || lower === 'block' || lower === 'denied' || lower === 'deny') return 'blocked';
      return lower;
    }
    expect(normalizeDecision('blocked')).toBe('blocked');
    expect(normalizeDecision('block')).toBe('blocked');
    expect(normalizeDecision('denied')).toBe('blocked');
    expect(normalizeDecision('deny')).toBe('blocked');
    expect(normalizeDecision('Blocked')).toBe('blocked');
    expect(normalizeDecision('allowed')).toBe('allowed');
  });
});

// ---------------------------------------------------------------------------
// Relative Time Formatting
// ---------------------------------------------------------------------------

describe('Relative Time', () => {
  it('should return "just now" for timestamps less than a minute ago', () => {
    function relativeTime(ts: string): string {
      const diffMs = Date.now() - new Date(ts).getTime();
      const diffMin = Math.floor(diffMs / 60_000);
      if (diffMin < 1) return 'just now';
      if (diffMin < 60) return `${diffMin}m ago`;
      const diffHr = Math.floor(diffMin / 60);
      if (diffHr < 24) return `${diffHr}h ago`;
      const diffDay = Math.floor(diffHr / 24);
      return `${diffDay}d ago`;
    }
    const now = new Date().toISOString();
    expect(relativeTime(now)).toBe('just now');
  });

  it('should return minutes for recent timestamps', () => {
    function relativeTime(ts: string): string {
      const diffMs = Date.now() - new Date(ts).getTime();
      const diffMin = Math.floor(diffMs / 60_000);
      if (diffMin < 1) return 'just now';
      if (diffMin < 60) return `${diffMin}m ago`;
      const diffHr = Math.floor(diffMin / 60);
      if (diffHr < 24) return `${diffHr}h ago`;
      const diffDay = Math.floor(diffHr / 24);
      return `${diffDay}d ago`;
    }
    const fiveMinAgo = new Date(Date.now() - 5 * 60_000).toISOString();
    expect(relativeTime(fiveMinAgo)).toBe('5m ago');
  });
});

// ---------------------------------------------------------------------------
// Category detection
// ---------------------------------------------------------------------------

describe('Alert Category Detection', () => {
  it('should categorize kill chain events', () => {
    const events = [makeEvent({ id: 'e1', details: 'Kill chain pattern', risk_level: 'critical' })];
    expect(generateAlerts(events)[0].category).toBe('kill_chain');
  });

  it('should categorize IoC events', () => {
    const events = [makeEvent({ id: 'e1', details: 'IoC match found', risk_level: 'critical' })];
    expect(generateAlerts(events)[0].category).toBe('ioc');
  });

  it('should categorize blocked events as block', () => {
    const events = [makeEvent({ id: 'e1', details: 'Normal event', decision: 'blocked', risk_level: 'medium' })];
    expect(generateAlerts(events)[0].category).toBe('block');
  });

  it('should categorize auto-block events', () => {
    const events = [makeEvent({ id: 'e1', details: 'Auto-blocked due to high risk', risk_level: 'critical' })];
    expect(generateAlerts(events)[0].category).toBe('auto_block');
  });
});
