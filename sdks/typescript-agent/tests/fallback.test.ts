import { FallbackEnforcer } from '../src/fallback';

describe('FallbackEnforcer', () => {
  let consoleSpy: jest.SpyInstance;

  beforeEach(() => {
    consoleSpy = jest.spyOn(console, 'log').mockImplementation();
  });

  afterEach(() => {
    consoleSpy.mockRestore();
  });

  test('logs embedded mode on construction', () => {
    new FallbackEnforcer({ name: 'test' });
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('embedded mode'),
    );
  });

  test('allows all actions in monitor mode', () => {
    const enforcer = new FallbackEnforcer({ name: 'test', mode: 'monitor' });
    expect(enforcer.checkAction('file_read', '/etc/passwd').allowed).toBe(true);
    expect(enforcer.checkAction('shell_execute', 'rm -rf /').allowed).toBe(true);
  });

  // Path checking
  test('blocks paths in blockedPaths', () => {
    const enforcer = new FallbackEnforcer({
      name: 'test',
      blockedPaths: ['/etc/**', '/root/**'],
    });
    const result = enforcer.checkPath('file_read', '/etc/passwd');
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('blockedPaths');
  });

  test('allows paths in allowedPaths', () => {
    const enforcer = new FallbackEnforcer({
      name: 'test',
      allowedPaths: ['/tmp/**', '/home/user/**'],
    });
    expect(enforcer.checkPath('file_read', '/tmp/test.txt').allowed).toBe(true);
    expect(enforcer.checkPath('file_read', '/var/log/app.log').allowed).toBe(false);
  });

  test('allows all paths when no restrictions set', () => {
    const enforcer = new FallbackEnforcer({ name: 'test' });
    expect(enforcer.checkPath('file_read', '/any/path').allowed).toBe(true);
  });

  test('blockedPaths takes priority over allowedPaths', () => {
    const enforcer = new FallbackEnforcer({
      name: 'test',
      allowedPaths: ['/home/**'],
      blockedPaths: ['/home/secret/**'],
    });
    expect(enforcer.checkPath('file_read', '/home/secret/key').allowed).toBe(false);
    expect(enforcer.checkPath('file_read', '/home/public/doc').allowed).toBe(true);
  });

  // Tool checking
  test('allows tools in allowedTools', () => {
    const enforcer = new FallbackEnforcer({
      name: 'test',
      allowedTools: ['readFile', 'writeFile'],
    });
    expect(enforcer.checkTool('readFile').allowed).toBe(true);
    expect(enforcer.checkTool('deleteFile').allowed).toBe(false);
  });

  test('allows all tools when no restrictions set', () => {
    const enforcer = new FallbackEnforcer({ name: 'test' });
    expect(enforcer.checkTool('anyTool').allowed).toBe(true);
  });

  // Network checking
  test('allows hosts in networkAllowlist', () => {
    const enforcer = new FallbackEnforcer({
      name: 'test',
      networkAllowlist: ['api.example.com', '*.github.com'],
    });
    expect(enforcer.checkNetwork('api.example.com').allowed).toBe(true);
    expect(enforcer.checkNetwork('evil.example.com').allowed).toBe(false);
  });

  test('matches wildcard network patterns', () => {
    const enforcer = new FallbackEnforcer({
      name: 'test',
      networkAllowlist: ['*.example.com'],
    });
    expect(enforcer.checkNetwork('api.example.com').allowed).toBe(true);
    expect(enforcer.checkNetwork('other.org').allowed).toBe(false);
  });

  test('allows all hosts when no restrictions set', () => {
    const enforcer = new FallbackEnforcer({ name: 'test' });
    expect(enforcer.checkNetwork('anywhere.com').allowed).toBe(true);
  });

  // Shell checking
  test('denies shell when policy is deny', () => {
    const enforcer = new FallbackEnforcer({ name: 'test', shellPolicy: 'deny' });
    expect(enforcer.checkShell('ls').allowed).toBe(false);
  });

  test('allows listed commands with allowlist policy', () => {
    const enforcer = new FallbackEnforcer({
      name: 'test',
      shellPolicy: 'allowlist',
      allowedCommands: ['git', 'npm'],
    });
    expect(enforcer.checkShell('git status').allowed).toBe(true);
    expect(enforcer.checkShell('npm install').allowed).toBe(true);
    expect(enforcer.checkShell('rm -rf /').allowed).toBe(false);
  });

  test('allows shell with approve policy', () => {
    const enforcer = new FallbackEnforcer({ name: 'test', shellPolicy: 'approve' });
    const result = enforcer.checkShell('anything');
    expect(result.allowed).toBe(true);
    expect(result.rule).toBe('shell-approve');
  });

  // Default action checking
  test('allows unknown action types by default', () => {
    const enforcer = new FallbackEnforcer({ name: 'test' });
    const result = enforcer.checkAction('custom_action', 'target');
    expect(result.allowed).toBe(true);
    expect(result.rule).toBe('default-allow');
  });
});
