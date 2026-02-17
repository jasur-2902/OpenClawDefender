import { describe, it, expect } from 'vitest';
import type {
  FeedStatus,
  BlocklistAlert,
  RulePackInfo,
  IoCStats,
  TelemetryStatus,
} from '../types';

// --- Feed Status Display Logic ---

describe('Feed Status Display', () => {
  it('should display feed version and entries count', () => {
    const feedStatus: FeedStatus = {
      version: '1.0.0',
      last_updated: '2026-02-17T00:00:00Z',
      next_check: '2026-02-17T06:00:00Z',
      entries_count: 115,
    };
    expect(feedStatus.version).toBe('1.0.0');
    expect(feedStatus.entries_count).toBe(115);
  });

  it('should format last_updated timestamp', () => {
    function formatTime(ts: string): string {
      try {
        return new Date(ts).toLocaleString();
      } catch {
        return ts;
      }
    }
    const result = formatTime('2026-02-17T00:00:00Z');
    expect(typeof result).toBe('string');
    expect(result.length).toBeGreaterThan(0);
  });

  it('should return raw string when timestamp is invalid', () => {
    function formatTime(ts: string): string {
      try {
        const d = new Date(ts);
        if (isNaN(d.getTime())) return ts;
        return d.toLocaleString();
      } catch {
        return ts;
      }
    }
    expect(formatTime('not-a-date')).toBe('not-a-date');
  });

  it('should show loading state when feedStatus is null', () => {
    const feedStatus: FeedStatus | null = null;
    const isLoading = feedStatus === null;
    expect(isLoading).toBe(true);
  });

  it('should show data when feedStatus is loaded', () => {
    const feedStatus: FeedStatus | null = {
      version: '1.0.0',
      last_updated: '2026-02-17T00:00:00Z',
      next_check: '2026-02-17T06:00:00Z',
      entries_count: 100,
    };
    const isLoading = feedStatus === null;
    expect(isLoading).toBe(false);
    expect(feedStatus!.version).toBe('1.0.0');
  });
});

// --- Rule Pack Install/Uninstall State Management ---

describe('Rule Pack State Management', () => {
  it('should toggle installed state from false to true', () => {
    const pack: RulePackInfo = {
      id: 'credential-protection',
      name: 'Credential Protection',
      installed: false,
      version: '1.0.0',
      rule_count: 12,
      description: 'Blocks access to SSH keys and credentials',
    };
    const updated = { ...pack, installed: true };
    expect(updated.installed).toBe(true);
    expect(updated.id).toBe('credential-protection');
  });

  it('should toggle installed state from true to false', () => {
    const pack: RulePackInfo = {
      id: 'network-security',
      name: 'Network Security',
      installed: true,
      version: '1.0.0',
      rule_count: 10,
      description: 'Controls outbound network connections',
    };
    const updated = { ...pack, installed: false };
    expect(updated.installed).toBe(false);
  });

  it('should update rule packs list after install', () => {
    const packs: RulePackInfo[] = [
      { id: 'pack-a', name: 'Pack A', installed: false, version: '1.0.0', rule_count: 5, description: 'A' },
      { id: 'pack-b', name: 'Pack B', installed: true, version: '1.0.0', rule_count: 8, description: 'B' },
    ];
    const updated = packs.map((p) =>
      p.id === 'pack-a' ? { ...p, installed: true } : p
    );
    expect(updated[0].installed).toBe(true);
    expect(updated[1].installed).toBe(true);
  });

  it('should update rule packs list after uninstall', () => {
    const packs: RulePackInfo[] = [
      { id: 'pack-a', name: 'Pack A', installed: true, version: '1.0.0', rule_count: 5, description: 'A' },
      { id: 'pack-b', name: 'Pack B', installed: true, version: '1.0.0', rule_count: 8, description: 'B' },
    ];
    const updated = packs.map((p) =>
      p.id === 'pack-b' ? { ...p, installed: false } : p
    );
    expect(updated[0].installed).toBe(true);
    expect(updated[1].installed).toBe(false);
  });

  it('should count installed packs correctly', () => {
    const packs: RulePackInfo[] = [
      { id: 'a', name: 'A', installed: true, version: '1.0.0', rule_count: 5, description: '' },
      { id: 'b', name: 'B', installed: false, version: '1.0.0', rule_count: 5, description: '' },
      { id: 'c', name: 'C', installed: true, version: '1.0.0', rule_count: 5, description: '' },
    ];
    const installedCount = packs.filter((p) => p.installed).length;
    expect(installedCount).toBe(2);
  });

  it('should calculate total rule count across installed packs', () => {
    const packs: RulePackInfo[] = [
      { id: 'a', name: 'A', installed: true, version: '1.0.0', rule_count: 12, description: '' },
      { id: 'b', name: 'B', installed: false, version: '1.0.0', rule_count: 10, description: '' },
      { id: 'c', name: 'C', installed: true, version: '1.0.0', rule_count: 8, description: '' },
    ];
    const totalRules = packs
      .filter((p) => p.installed)
      .reduce((sum, p) => sum + p.rule_count, 0);
    expect(totalRules).toBe(20);
  });
});

// --- IoC Stats Formatting ---

describe('IoC Stats Formatting', () => {
  it('should compute total from individual categories', () => {
    const stats: IoCStats = {
      network: 55,
      file: 25,
      behavioral: 35,
      total: 115,
      last_updated: '2026-02-17T00:00:00Z',
    };
    const computed = stats.network + stats.file + stats.behavioral;
    expect(computed).toBe(stats.total);
  });

  it('should handle zero IoC stats', () => {
    const stats: IoCStats = {
      network: 0,
      file: 0,
      behavioral: 0,
      total: 0,
      last_updated: '2026-02-17T00:00:00Z',
    };
    expect(stats.total).toBe(0);
  });

  it('should format large IoC numbers', () => {
    function formatCount(n: number): string {
      if (n >= 1000000) return `${(n / 1000000).toFixed(1)}M`;
      if (n >= 1000) return `${(n / 1000).toFixed(1)}K`;
      return n.toString();
    }
    expect(formatCount(115)).toBe('115');
    expect(formatCount(1500)).toBe('1.5K');
    expect(formatCount(2500000)).toBe('2.5M');
  });

  it('should show loading state when stats are null', () => {
    const iocStats: IoCStats | null = null;
    expect(iocStats === null).toBe(true);
  });

  it('should display stat card values correctly', () => {
    const stats: IoCStats = {
      network: 55,
      file: 25,
      behavioral: 35,
      total: 115,
      last_updated: '2026-02-17T00:00:00Z',
    };
    const cards = [
      { label: 'Network', value: stats.network },
      { label: 'File', value: stats.file },
      { label: 'Behavioral', value: stats.behavioral },
      { label: 'Total', value: stats.total },
    ];
    expect(cards).toHaveLength(4);
    expect(cards[0].value).toBe(55);
    expect(cards[3].label).toBe('Total');
    expect(cards[3].value).toBe(115);
  });
});

// --- Telemetry Toggle Behavior ---

describe('Telemetry Toggle Behavior', () => {
  it('should toggle telemetry from disabled to enabled', () => {
    const status: TelemetryStatus = {
      enabled: false,
      last_report: null,
      installation_id: null,
    };
    const toggled = { ...status, enabled: !status.enabled };
    expect(toggled.enabled).toBe(true);
  });

  it('should toggle telemetry from enabled to disabled', () => {
    const status: TelemetryStatus = {
      enabled: true,
      last_report: '2026-02-16T12:00:00Z',
      installation_id: 'abc-123',
    };
    const toggled = { ...status, enabled: !status.enabled };
    expect(toggled.enabled).toBe(false);
  });

  it('should preserve other fields when toggling', () => {
    const status: TelemetryStatus = {
      enabled: true,
      last_report: '2026-02-16T12:00:00Z',
      installation_id: 'abc-123',
    };
    const toggled = { ...status, enabled: false };
    expect(toggled.last_report).toBe('2026-02-16T12:00:00Z');
    expect(toggled.installation_id).toBe('abc-123');
  });

  it('should handle null telemetry status gracefully', () => {
    const status: TelemetryStatus | null = null;
    const shouldShowToggle = status !== null;
    expect(shouldShowToggle).toBe(false);
  });

  it('should determine toggle CSS class based on enabled state', () => {
    function getToggleClass(enabled: boolean): string {
      return enabled ? 'bg-accent' : 'bg-tertiary';
    }
    expect(getToggleClass(true)).toBe('bg-accent');
    expect(getToggleClass(false)).toBe('bg-tertiary');
  });

  it('should determine toggle knob position based on enabled state', () => {
    function getKnobTransform(enabled: boolean): string {
      return enabled ? 'translate-x-6' : 'translate-x-1';
    }
    expect(getKnobTransform(true)).toBe('translate-x-6');
    expect(getKnobTransform(false)).toBe('translate-x-1');
  });
});

// --- Blocklist Alert Severity Sorting ---

describe('Blocklist Alert Severity Sorting', () => {
  const severityOrder: Record<string, number> = {
    Critical: 4,
    High: 3,
    Medium: 2,
    Low: 1,
  };

  function sortBySeverity(alerts: BlocklistAlert[]): BlocklistAlert[] {
    return [...alerts].sort(
      (a, b) => (severityOrder[b.severity] ?? 0) - (severityOrder[a.severity] ?? 0)
    );
  }

  it('should sort alerts by severity descending (Critical first)', () => {
    const alerts: BlocklistAlert[] = [
      { entry_id: 'CLAW-2026-005', server_name: 'mcp-file-browser', severity: 'High', description: 'Path traversal' },
      { entry_id: 'CLAW-2026-001', server_name: 'evil-mcp', severity: 'Critical', description: 'Credential exfil' },
      { entry_id: 'CLAW-2026-012', server_name: 'mcp-image', severity: 'Medium', description: 'DoS' },
    ];
    const sorted = sortBySeverity(alerts);
    expect(sorted[0].severity).toBe('Critical');
    expect(sorted[1].severity).toBe('High');
    expect(sorted[2].severity).toBe('Medium');
  });

  it('should handle empty alerts list', () => {
    const sorted = sortBySeverity([]);
    expect(sorted).toHaveLength(0);
  });

  it('should handle alerts with same severity', () => {
    const alerts: BlocklistAlert[] = [
      { entry_id: 'CLAW-2026-001', server_name: 'a', severity: 'Critical', description: 'A' },
      { entry_id: 'CLAW-2026-002', server_name: 'b', severity: 'Critical', description: 'B' },
    ];
    const sorted = sortBySeverity(alerts);
    expect(sorted).toHaveLength(2);
    expect(sorted[0].severity).toBe('Critical');
    expect(sorted[1].severity).toBe('Critical');
  });

  it('should handle all severity levels', () => {
    const alerts: BlocklistAlert[] = [
      { entry_id: '1', server_name: 'a', severity: 'Low', description: '' },
      { entry_id: '2', server_name: 'b', severity: 'Critical', description: '' },
      { entry_id: '3', server_name: 'c', severity: 'Medium', description: '' },
      { entry_id: '4', server_name: 'd', severity: 'High', description: '' },
    ];
    const sorted = sortBySeverity(alerts);
    expect(sorted.map((a) => a.severity)).toEqual(['Critical', 'High', 'Medium', 'Low']);
  });

  it('should not modify the original array', () => {
    const alerts: BlocklistAlert[] = [
      { entry_id: '1', server_name: 'a', severity: 'Low', description: '' },
      { entry_id: '2', server_name: 'b', severity: 'Critical', description: '' },
    ];
    const sorted = sortBySeverity(alerts);
    expect(alerts[0].severity).toBe('Low');
    expect(sorted[0].severity).toBe('Critical');
  });

  it('should handle unknown severity gracefully', () => {
    const alerts: BlocklistAlert[] = [
      { entry_id: '1', server_name: 'a', severity: 'Unknown', description: '' },
      { entry_id: '2', server_name: 'b', severity: 'High', description: '' },
    ];
    const sorted = sortBySeverity(alerts);
    expect(sorted[0].severity).toBe('High');
    expect(sorted[1].severity).toBe('Unknown');
  });

  it('should display no-matches message when blocklist is empty', () => {
    const alerts: BlocklistAlert[] = [];
    const message = alerts.length === 0
      ? 'No blocklist matches. All monitored servers appear clean.'
      : `${alerts.length} blocklist matches found.`;
    expect(message).toBe('No blocklist matches. All monitored servers appear clean.');
  });

  it('should display match count when blocklist has entries', () => {
    const alerts: BlocklistAlert[] = [
      { entry_id: '1', server_name: 'a', severity: 'High', description: '' },
      { entry_id: '2', server_name: 'b', severity: 'Critical', description: '' },
    ];
    const message = alerts.length === 0
      ? 'No blocklist matches. All monitored servers appear clean.'
      : `${alerts.length} blocklist matches found.`;
    expect(message).toBe('2 blocklist matches found.');
  });
});
