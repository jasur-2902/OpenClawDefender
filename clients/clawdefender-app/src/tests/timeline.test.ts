import { describe, it, expect } from 'vitest';

interface AuditEvent {
  id: string;
  timestamp: string;
  event_type: string;
  server_name: string;
  tool_name: string | null;
  action: string;
  decision: string;
  risk_level: string;
  details: string;
  resource: string | null;
}

const sampleEvents: AuditEvent[] = [
  { id: '1', timestamp: '2024-01-15T10:00:00Z', event_type: 'tool_call', server_name: 'fs-server', tool_name: 'read_file', action: 'read', decision: 'allowed', risk_level: 'low', details: '{}', resource: '/tmp/test.txt' },
  { id: '2', timestamp: '2024-01-15T10:01:00Z', event_type: 'tool_call', server_name: 'net-server', tool_name: 'fetch', action: 'network', decision: 'blocked', risk_level: 'high', details: '{}', resource: 'tcp://evil.com' },
  { id: '3', timestamp: '2024-01-15T10:02:00Z', event_type: 'resource_access', server_name: 'fs-server', tool_name: 'write_file', action: 'write', decision: 'prompted', risk_level: 'medium', details: '{}', resource: '/etc/hosts' },
  { id: '4', timestamp: '2024-01-15T10:03:00Z', event_type: 'tool_call', server_name: 'db-server', tool_name: 'query', action: 'read', decision: 'allowed', risk_level: 'low', details: '{"query": "SELECT 1"}', resource: null },
  { id: '5', timestamp: '2024-01-15T10:04:00Z', event_type: 'error', server_name: 'net-server', tool_name: null, action: 'connection_failed', decision: 'deny', risk_level: 'critical', details: 'Connection refused', resource: null },
];

function applyFilters(
  events: AuditEvent[],
  searchText: string,
  serverFilter: string,
  statusFilter: string[],
  onlyBlocks: boolean
): AuditEvent[] {
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
      statusFilter.some((s) => e.decision.toLowerCase() === s.toLowerCase())
    );
  }

  if (onlyBlocks) {
    result = result.filter(
      (e) => e.decision.toLowerCase() === 'blocked' || e.decision.toLowerCase() === 'deny'
    );
  }

  return result;
}

describe('Timeline filters', () => {
  it('should return all events when no filters are applied', () => {
    const result = applyFilters(sampleEvents, '', '', [], false);
    expect(result.length).toBe(5);
  });

  it('should filter by search text matching server name', () => {
    const result = applyFilters(sampleEvents, 'fs-server', '', [], false);
    expect(result.length).toBe(2);
    expect(result.every((e) => e.server_name === 'fs-server')).toBe(true);
  });

  it('should filter by search text matching tool name', () => {
    const result = applyFilters(sampleEvents, 'fetch', '', [], false);
    expect(result.length).toBe(1);
    expect(result[0].tool_name).toBe('fetch');
  });

  it('should filter by search text matching action', () => {
    const result = applyFilters(sampleEvents, 'write', '', [], false);
    expect(result.length).toBe(1);
    expect(result[0].action).toBe('write');
  });

  it('should filter by search text matching details content', () => {
    const result = applyFilters(sampleEvents, 'SELECT', '', [], false);
    expect(result.length).toBe(1);
    expect(result[0].id).toBe('4');
  });

  it('should filter by server dropdown', () => {
    const result = applyFilters(sampleEvents, '', 'net-server', [], false);
    expect(result.length).toBe(2);
    expect(result.every((e) => e.server_name === 'net-server')).toBe(true);
  });

  it('should filter by status filter (allowed)', () => {
    const result = applyFilters(sampleEvents, '', '', ['allowed'], false);
    expect(result.length).toBe(2);
  });

  it('should filter by multiple status filters', () => {
    const result = applyFilters(sampleEvents, '', '', ['blocked', 'deny'], false);
    expect(result.length).toBe(2);
  });

  it('should filter only blocks', () => {
    const result = applyFilters(sampleEvents, '', '', [], true);
    expect(result.length).toBe(2);
    expect(result.every((e) => e.decision === 'blocked' || e.decision === 'deny')).toBe(true);
  });

  it('should combine search and server filter', () => {
    const result = applyFilters(sampleEvents, 'read', 'fs-server', [], false);
    expect(result.length).toBe(1);
    expect(result[0].tool_name).toBe('read_file');
  });

  it('should return empty when no events match', () => {
    const result = applyFilters(sampleEvents, 'nonexistent', '', [], false);
    expect(result.length).toBe(0);
  });

  it('should be case-insensitive for search', () => {
    const result = applyFilters(sampleEvents, 'FS-SERVER', '', [], false);
    expect(result.length).toBe(2);
  });
});

describe('Timeline helpers', () => {
  it('should extract unique server names', () => {
    const names = new Set<string>();
    for (const e of sampleEvents) names.add(e.server_name);
    const sorted = Array.from(names).sort();
    expect(sorted).toEqual(['db-server', 'fs-server', 'net-server']);
  });

  it('should compute virtual scroll indices correctly', () => {
    const ROW_HEIGHT = 44;
    const BUFFER_ROWS = 10;
    const scrollTop = 440; // scrolled 10 rows down
    const containerHeight = 440; // shows 10 rows
    const totalEvents = 100;

    const startIndex = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - BUFFER_ROWS);
    const endIndex = Math.min(totalEvents, Math.ceil((scrollTop + containerHeight) / ROW_HEIGHT) + BUFFER_ROWS);

    expect(startIndex).toBe(0);
    expect(endIndex).toBe(30);
  });
});
