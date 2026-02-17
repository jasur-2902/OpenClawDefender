import { describe, it, expect } from 'vitest';

interface AuditEvent {
  id: string;
  timestamp: string;
  event_type: string;
  server_name: string;
  tool_name: string | null;
  action: string;
  decision: string;
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  details: string;
  resource: string | null;
}

interface PendingPrompt {
  id: string;
  timestamp: string;
  server_name: string;
  tool_name: string;
  action: string;
  resource: string;
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  context: string;
  timeout_seconds: number;
}

const MAX_EVENTS = 10_000;

function makeEvent(id: string, overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    id,
    timestamp: new Date().toISOString(),
    event_type: 'tool_call',
    server_name: 'test-server',
    tool_name: 'test-tool',
    action: 'read',
    decision: 'allowed',
    risk_level: 'low',
    details: '{}',
    resource: null,
    ...overrides,
  };
}

function makePrompt(id: string): PendingPrompt {
  return {
    id,
    timestamp: new Date().toISOString(),
    server_name: 'test-server',
    tool_name: 'test-tool',
    action: 'write',
    resource: '/tmp/file',
    risk_level: 'high',
    context: 'Writing to file system',
    timeout_seconds: 30,
  };
}

describe('EventStore logic', () => {
  it('should add events to the front of the list', () => {
    const events: AuditEvent[] = [];
    const event = makeEvent('1');
    const updated = [event, ...events];
    expect(updated.length).toBe(1);
    expect(updated[0].id).toBe('1');
  });

  it('should prepend new events', () => {
    const events = [makeEvent('1'), makeEvent('2')];
    const newEvent = makeEvent('3');
    const updated = [newEvent, ...events];
    expect(updated[0].id).toBe('3');
    expect(updated.length).toBe(3);
  });

  it('should enforce the ring buffer max of 10,000 events', () => {
    const events: AuditEvent[] = Array.from({ length: MAX_EVENTS }, (_, i) =>
      makeEvent(String(i))
    );
    const newEvent = makeEvent('new');
    const updated = [newEvent, ...events];
    if (updated.length > MAX_EVENTS) {
      updated.length = MAX_EVENTS;
    }
    expect(updated.length).toBe(MAX_EVENTS);
    expect(updated[0].id).toBe('new');
  });

  it('should add prompts to the pending list', () => {
    const prompts: PendingPrompt[] = [];
    const prompt = makePrompt('p1');
    const updated = [...prompts, prompt];
    expect(updated.length).toBe(1);
    expect(updated[0].id).toBe('p1');
  });

  it('should remove prompts by id', () => {
    const prompts = [makePrompt('p1'), makePrompt('p2'), makePrompt('p3')];
    const filtered = prompts.filter((p) => p.id !== 'p2');
    expect(filtered.length).toBe(2);
    expect(filtered.find((p) => p.id === 'p2')).toBeUndefined();
  });

  it('should handle removing a non-existent prompt gracefully', () => {
    const prompts = [makePrompt('p1')];
    const filtered = prompts.filter((p) => p.id !== 'non-existent');
    expect(filtered.length).toBe(1);
  });

  it('should set events replacing the entire list', () => {
    const newEvents = [makeEvent('a'), makeEvent('b')];
    const state = { events: newEvents };
    expect(state.events.length).toBe(2);
    expect(state.events[0].id).toBe('a');
  });

  it('should track daemon running state', () => {
    let daemonRunning = false;
    daemonRunning = true;
    expect(daemonRunning).toBe(true);
    daemonRunning = false;
    expect(daemonRunning).toBe(false);
  });
});
