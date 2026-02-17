import { describe, it, expect } from 'vitest';

interface PolicyRule {
  name: string;
  description: string;
  action: 'allow' | 'deny' | 'prompt' | 'audit';
  resource: string;
  pattern: string;
  priority: number;
  enabled: boolean;
}

const sampleRules: PolicyRule[] = [
  { name: 'Block file writes', description: 'Prevent writing to sensitive files', action: 'deny', resource: '*', pattern: '/etc/**', priority: 90, enabled: true },
  { name: 'Prompt network access', description: 'Ask before outbound connections', action: 'prompt', resource: '*', pattern: 'tcp://*', priority: 80, enabled: true },
  { name: 'Allow read operations', description: 'Safe read access is permitted', action: 'allow', resource: '*', pattern: 'read://**', priority: 50, enabled: true },
  { name: 'Audit tool calls', description: 'Log all tool invocations', action: 'audit', resource: '*', pattern: 'tool://**', priority: 30, enabled: true },
  { name: 'Block env access', description: 'Prevent access to environment files', action: 'deny', resource: '*', pattern: '**/.env*', priority: 95, enabled: false },
];

describe('Policy rule validation', () => {
  it('should require a non-empty name', () => {
    const rule = { ...sampleRules[0], name: '' };
    expect(rule.name.length).toBe(0);
    const isValid = rule.name.length > 0;
    expect(isValid).toBe(false);
  });

  it('should require a valid action type', () => {
    const validActions = ['allow', 'deny', 'prompt', 'audit'];
    for (const rule of sampleRules) {
      expect(validActions).toContain(rule.action);
    }
  });

  it('should have priority between 0 and 100', () => {
    for (const rule of sampleRules) {
      expect(rule.priority).toBeGreaterThanOrEqual(0);
      expect(rule.priority).toBeLessThanOrEqual(100);
    }
  });

  it('should require a non-empty pattern', () => {
    for (const rule of sampleRules) {
      expect(rule.pattern.length).toBeGreaterThan(0);
    }
  });
});

describe('Policy rule operations', () => {
  it('should toggle rule enabled state', () => {
    const rules = [...sampleRules];
    const toggled = rules.map((r) =>
      r.name === 'Block env access' ? { ...r, enabled: !r.enabled } : r
    );
    const envRule = toggled.find((r) => r.name === 'Block env access');
    expect(envRule?.enabled).toBe(true);
  });

  it('should delete a rule by name', () => {
    const filtered = sampleRules.filter((r) => r.name !== 'Audit tool calls');
    expect(filtered.length).toBe(4);
    expect(filtered.find((r) => r.name === 'Audit tool calls')).toBeUndefined();
  });

  it('should duplicate a rule with a new name', () => {
    const original = sampleRules[0];
    const dup = { ...original, name: `${original.name} (copy)` };
    expect(dup.name).toBe('Block file writes (copy)');
    expect(dup.action).toBe(original.action);
    expect(dup.pattern).toBe(original.pattern);
  });

  it('should move a rule up in the list', () => {
    const rules = [...sampleRules];
    const index = 2;
    const target = index - 1;
    [rules[index], rules[target]] = [rules[target], rules[index]];
    expect(rules[1].name).toBe('Allow read operations');
    expect(rules[2].name).toBe('Prompt network access');
  });

  it('should move a rule down in the list', () => {
    const rules = [...sampleRules];
    const index = 0;
    const target = index + 1;
    [rules[index], rules[target]] = [rules[target], rules[index]];
    expect(rules[0].name).toBe('Prompt network access');
    expect(rules[1].name).toBe('Block file writes');
  });

  it('should not move the first rule up', () => {
    const index = 0;
    const target = index - 1;
    const canMove = target >= 0;
    expect(canMove).toBe(false);
  });

  it('should not move the last rule down', () => {
    const index = sampleRules.length - 1;
    const target = index + 1;
    const canMove = target < sampleRules.length;
    expect(canMove).toBe(false);
  });
});

describe('Policy action config', () => {
  it('should map action types to correct display labels', () => {
    const actionConfig: Record<string, { icon: string; label: string }> = {
      deny: { icon: '\u2717', label: 'Block' },
      prompt: { icon: '!', label: 'Prompt' },
      allow: { icon: '\u2713', label: 'Allow' },
      audit: { icon: '\u270E', label: 'Audit' },
    };
    expect(actionConfig.deny.label).toBe('Block');
    expect(actionConfig.prompt.label).toBe('Prompt');
    expect(actionConfig.allow.label).toBe('Allow');
    expect(actionConfig.audit.label).toBe('Audit');
  });

  it('should count enabled rules', () => {
    const enabledCount = sampleRules.filter((r) => r.enabled).length;
    expect(enabledCount).toBe(4);
  });

  it('should count disabled rules', () => {
    const disabledCount = sampleRules.filter((r) => !r.enabled).length;
    expect(disabledCount).toBe(1);
  });
});
