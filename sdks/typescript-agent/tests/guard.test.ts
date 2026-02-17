import { AgentGuard } from '../src/guard';
import type { GuardOptions } from '../src/types';

// Mock fetch globally to prevent real network calls
const mockFetch = jest.fn().mockRejectedValue(new Error('no daemon'));
(global as any).fetch = mockFetch;

function makeGuard(overrides?: Partial<GuardOptions>): AgentGuard {
  return new AgentGuard({
    name: 'test-agent',
    allowedPaths: ['/tmp/**'],
    blockedPaths: ['/etc/**'],
    allowedTools: ['readFile', 'writeFile'],
    networkAllowlist: ['api.example.com'],
    shellPolicy: 'deny',
    ...overrides,
  });
}

describe('AgentGuard', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockFetch.mockRejectedValue(new Error('no daemon'));
  });

  test('starts inactive', () => {
    const guard = makeGuard();
    expect(guard.isActive).toBe(false);
    expect(guard.isHealthy()).toBe(false);
  });

  test('activates with fallback when daemon is unavailable', async () => {
    const guard = makeGuard();
    await guard.activate({ fallback: true });
    expect(guard.isActive).toBe(true);
    expect(guard.isHealthy()).toBe(true);
    await guard.deactivate();
  });

  test('throws when daemon unavailable and fallback disabled', async () => {
    const guard = makeGuard();
    await expect(guard.activate({ fallback: false })).rejects.toThrow(
      'could not connect to ClawDefender daemon',
    );
    expect(guard.isActive).toBe(false);
  });

  test('deactivates cleanly', async () => {
    const guard = makeGuard();
    await guard.activate({ fallback: true });
    await guard.deactivate();
    expect(guard.isActive).toBe(false);
    expect(guard.isHealthy()).toBe(false);
  });

  test('deactivate is idempotent', async () => {
    const guard = makeGuard();
    await guard.deactivate(); // should not throw
    await guard.activate({ fallback: true });
    await guard.deactivate();
    await guard.deactivate(); // second call should not throw
    expect(guard.isActive).toBe(false);
  });

  test('activate is idempotent', async () => {
    const guard = makeGuard();
    await guard.activate({ fallback: true });
    await guard.activate({ fallback: true }); // second call should not re-activate
    expect(guard.isActive).toBe(true);
    await guard.deactivate();
  });

  test('checkAction allows permitted path', async () => {
    const guard = makeGuard();
    await guard.activate({ fallback: true });
    const result = await guard.checkAction('file_read', '/tmp/test.txt');
    expect(result.allowed).toBe(true);
    await guard.deactivate();
  });

  test('checkAction blocks restricted path', async () => {
    const guard = makeGuard();
    await guard.activate({ fallback: true });
    const result = await guard.checkAction('file_read', '/etc/passwd');
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('blockedPaths');
    await guard.deactivate();
  });

  test('checkAction blocks shell when policy is deny', async () => {
    const guard = makeGuard({ shellPolicy: 'deny' });
    await guard.activate({ fallback: true });
    const result = await guard.checkAction('shell_execute', 'rm -rf /');
    expect(result.allowed).toBe(false);
    await guard.deactivate();
  });

  test('tracks allowed and blocked counts', async () => {
    const guard = makeGuard();
    await guard.activate({ fallback: true });

    await guard.checkAction('file_read', '/tmp/ok.txt');
    await guard.checkAction('file_read', '/etc/shadow');
    await guard.checkAction('file_read', '/tmp/also-ok.txt');

    expect(guard.allowedCount).toBe(2);
    expect(guard.blockedCount).toBe(1);
    await guard.deactivate();
  });

  test('stats returns correct data', async () => {
    const guard = makeGuard();
    await guard.activate({ fallback: true });

    await guard.checkAction('file_read', '/etc/passwd');

    const s = guard.stats();
    expect(s.activatedAt).toBeInstanceOf(Date);
    expect(s.operationsBlocked).toBe(1);
    expect(s.blockedDetails).toHaveLength(1);
    expect(s.blockedDetails[0]!.tool).toBe('file_read');
    expect(s.blockedDetails[0]!.target).toBe('/etc/passwd');
    expect(s.status).toEqual({ degraded: 'running in embedded mode' });
    await guard.deactivate();
  });

  test('stats shows inactive status when not activated', () => {
    const guard = makeGuard();
    const s = guard.stats();
    expect(s.status).toBe('inactive');
    expect(s.activatedAt).toBeNull();
  });

  test('suggestPermissions returns observed operations', async () => {
    const guard = makeGuard({ mode: 'monitor' });
    await guard.activate({ fallback: true });

    await guard.checkAction('file_read', '/var/log/app.log');
    await guard.checkAction('network_request', 'api.openai.com');
    await guard.checkAction('shell_execute', 'git status');

    const suggested = guard.suggestPermissions();
    expect(suggested.allowedPaths).toContain('/var/log/app.log');
    expect(suggested.networkAllowlist).toContain('api.openai.com');
    expect(suggested.shellCommands).toContain('git');
    await guard.deactivate();
  });

  test('checkAction returns allowed when guard is not active', async () => {
    const guard = makeGuard();
    const result = await guard.checkAction('file_read', '/etc/passwd');
    expect(result.allowed).toBe(true);
    expect(result.reason).toBe('guard not active');
  });

  test('Symbol.asyncDispose deactivates the guard', async () => {
    const guard = makeGuard();
    await guard.activate({ fallback: true });
    expect(guard.isActive).toBe(true);
    await guard[Symbol.asyncDispose]();
    expect(guard.isActive).toBe(false);
  });
});
