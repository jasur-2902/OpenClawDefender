import { FallbackEnforcer } from '../src/fallback';
import { NodeHooks } from '../src/hooks';

describe('NodeHooks', () => {
  let consoleSpy: jest.SpyInstance;

  beforeEach(() => {
    consoleSpy = jest.spyOn(console, 'log').mockImplementation();
  });

  afterEach(() => {
    consoleSpy.mockRestore();
  });

  test('installs and uninstalls without error', () => {
    const enforcer = new FallbackEnforcer({
      name: 'test',
      allowedPaths: ['/tmp/**'],
      shellPolicy: 'deny',
    });
    const hooks = new NodeHooks(enforcer);
    hooks.install();
    hooks.uninstall();
  });

  test('install is idempotent', () => {
    const enforcer = new FallbackEnforcer({ name: 'test' });
    const hooks = new NodeHooks(enforcer);
    hooks.install();
    hooks.install(); // should not throw
    hooks.uninstall();
  });

  test('uninstall is idempotent', () => {
    const enforcer = new FallbackEnforcer({ name: 'test' });
    const hooks = new NodeHooks(enforcer);
    hooks.uninstall(); // should not throw even without install
  });

  test('hooks block fs operations for blocked paths', () => {
    const enforcer = new FallbackEnforcer({
      name: 'test',
      blockedPaths: ['/secret/**'],
    });
    const hooks = new NodeHooks(enforcer);
    hooks.install();

    const fs = require('fs');
    expect(() => {
      fs.readFileSync('/secret/key.pem');
    }).toThrow('AgentGuard blocked file read');

    hooks.uninstall();
  });

  test('hooks allow fs operations for permitted paths', () => {
    const enforcer = new FallbackEnforcer({
      name: 'test',
      allowedPaths: ['/tmp/**'],
    });
    const hooks = new NodeHooks(enforcer);
    hooks.install();

    // readFileSync for /tmp should not throw due to guard,
    // it may throw ENOENT but not AgentGuard error
    const fs = require('fs');
    try {
      fs.readFileSync('/tmp/nonexistent-guard-test-file');
    } catch (err: any) {
      expect(err.message).not.toContain('AgentGuard blocked');
    }

    hooks.uninstall();
  });

  test('restores original functions on uninstall', () => {
    const enforcer = new FallbackEnforcer({
      name: 'test',
      blockedPaths: ['/secret/**'],
    });
    const hooks = new NodeHooks(enforcer);

    const fs = require('fs');
    const originalReadFile = fs.readFileSync;
    hooks.install();
    expect(fs.readFileSync).not.toBe(originalReadFile);
    hooks.uninstall();
    expect(fs.readFileSync).toBe(originalReadFile);
  });

  test('hooks block child_process when shell policy is deny', () => {
    const enforcer = new FallbackEnforcer({
      name: 'test',
      shellPolicy: 'deny',
    });
    const hooks = new NodeHooks(enforcer);
    hooks.install();

    const cp = require('child_process');
    expect(() => {
      cp.execSync('echo hello');
    }).toThrow('AgentGuard blocked shell execution');

    hooks.uninstall();
  });

  test('hooks block network requests for non-allowed hosts', () => {
    const enforcer = new FallbackEnforcer({
      name: 'test',
      networkAllowlist: ['api.example.com'],
    });
    const hooks = new NodeHooks(enforcer);
    hooks.install();

    const http = require('http');
    expect(() => {
      http.request({ hostname: 'evil.com', path: '/' });
    }).toThrow('AgentGuard blocked network request');

    hooks.uninstall();
  });
});
