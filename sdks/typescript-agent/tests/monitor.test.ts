import { Monitor } from '../src/monitor';

describe('Monitor', () => {
  test('records operations', () => {
    const monitor = new Monitor();
    monitor.record('file_read', '/tmp/test.txt', true);
    monitor.record('file_write', '/etc/passwd', false, 'blocked');

    expect(monitor.totalOperations).toBe(2);
    expect(monitor.blockedOperations).toBe(1);
  });

  test('getRecords returns all records', () => {
    const monitor = new Monitor();
    monitor.record('file_read', '/a', true);
    monitor.record('file_read', '/b', true);

    const records = monitor.getRecords();
    expect(records).toHaveLength(2);
    expect(records[0]!.target).toBe('/a');
    expect(records[1]!.target).toBe('/b');
  });

  test('records include timestamps', () => {
    const monitor = new Monitor();
    monitor.record('file_read', '/test', true);
    const records = monitor.getRecords();
    expect(records[0]!.timestamp).toBeInstanceOf(Date);
  });

  test('clear removes all records', () => {
    const monitor = new Monitor();
    monitor.record('file_read', '/a', true);
    monitor.record('file_read', '/b', true);
    monitor.clear();
    expect(monitor.totalOperations).toBe(0);
  });

  test('suggestPermissions aggregates observed actions', () => {
    const monitor = new Monitor();
    monitor.record('file_read', '/tmp/a.txt', true);
    monitor.record('file_write', '/tmp/b.txt', true);
    monitor.record('network_request', 'api.openai.com', true);
    monitor.record('network_request', 'api.openai.com', true); // duplicate
    monitor.record('shell_execute', 'git status', true);
    monitor.record('tool_call', 'readFile', true);

    const suggested = monitor.suggestPermissions();
    expect(suggested.allowedPaths).toContain('/tmp/a.txt');
    expect(suggested.allowedPaths).toContain('/tmp/b.txt');
    expect(suggested.networkAllowlist).toEqual(['api.openai.com']); // deduped
    expect(suggested.shellCommands).toEqual(['git']);
    expect(suggested.allowedTools).toEqual(['readFile']);
  });

  test('suggestPermissions returns empty arrays when no records', () => {
    const monitor = new Monitor();
    const suggested = monitor.suggestPermissions();
    expect(suggested.allowedPaths).toEqual([]);
    expect(suggested.allowedTools).toEqual([]);
    expect(suggested.networkAllowlist).toEqual([]);
    expect(suggested.shellCommands).toEqual([]);
  });

  test('records include reason when provided', () => {
    const monitor = new Monitor();
    monitor.record('file_read', '/secret', false, 'path blocked');
    const records = monitor.getRecords();
    expect(records[0]!.reason).toBe('path blocked');
    expect(records[0]!.allowed).toBe(false);
  });
});
